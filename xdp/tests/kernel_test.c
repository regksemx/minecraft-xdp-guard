/*
 * In-kernel tests of the complete XDP program.
 *
 * Loads the real BPF object through the kernel verifier with different
 * runtime configurations and feeds it hand-built frames via
 * BPF_PROG_TEST_RUN, checking the XDP verdict of every packet. Nothing is
 * attached to an interface, so this is safe to run anywhere; it only needs
 * root (CAP_BPF) and a kernel >= 5.11. See dev/test.sh for how it is built.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "minecraft_filter.skel.h"
#include "../stats.h"

/* ------------------------------------------------------------------------
 * Tiny test framework
 * --------------------------------------------------------------------- */

static unsigned checks_run = 0;
static unsigned checks_failed = 0;

#define CHECK(cond)                                                          \
    do                                                                       \
    {                                                                        \
        checks_run++;                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            checks_failed++;                                                 \
            printf("FAIL %s:%d in %s: %s\n", __FILE__, __LINE__, __func__,   \
                   #cond);                                                   \
        }                                                                    \
    } while (0)

#define PASSES(frame) CHECK(run(frame) == XDP_PASS)
#define DROPS(frame) CHECK(run(frame) == XDP_DROP)

#define MS 1000000ULL
#define SEC 1000000000ULL

static void sleep_ms(unsigned ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static __u64 monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * SEC + (__u64)ts.tv_nsec;
}

/* ------------------------------------------------------------------------
 * Program under test
 * --------------------------------------------------------------------- */

#define JAVA_PORT 25565
#define GUARD_PORT 19132  // NetherNet signaling shares its number with RakNet
#define RAKNET_PORT 19132
#define ICE_PORT 27020
#define OTHER_PORT 22

#define SERVER_IP 0x0A000001u // 10.0.0.1
#define CLIENT_IP 0xC6336401u // 198.51.100.1

#define RETRY_SLOTS 1024

static struct minecraft_filter *skel = NULL;

typedef void (*configure_fn)(struct minecraft_filter *);

// everything protected, every limit off: the scenarios switch on what they test
static void base_config(struct minecraft_filter *s)
{
    s->rodata->PROMETHEUS = 1;
    s->rodata->LIMIT_WINDOW_NS = 1 * SEC;

    s->rodata->JAVA_START_PORT = JAVA_PORT;
    s->rodata->JAVA_END_PORT = JAVA_PORT;
    s->rodata->ONLINE_NAMES = 1;
    s->rodata->TCP_IDLE_NS = 60 * SEC;

    s->rodata->GUARD_START_PORT = GUARD_PORT;
    s->rodata->GUARD_END_PORT = GUARD_PORT;
    s->rodata->GUARD_TLS = 1;
    s->rodata->GUARD_HTTP = 1;

    s->rodata->RAKNET_START_PORT = RAKNET_PORT;
    s->rodata->RAKNET_END_PORT = RAKNET_PORT;
    s->rodata->RAKNET_PROTO_MIN = 9;
    s->rodata->RAKNET_PROTO_MAX = 11;
    s->rodata->RAKNET_OCR1_MIN = 400;

    s->rodata->ICE_START_PORT = ICE_PORT;
    s->rodata->ICE_END_PORT = ICE_PORT + 9;
    s->rodata->UDP_IDLE_NS = 30 * SEC;

    s->rodata->RETRY_MASK = RETRY_SLOTS - 1;
    s->rodata->RETRY_MIN_TICKS = 3;   // ~200ms
    s->rodata->RETRY_MAX_TICKS = 150; // ~10s
    s->rodata->RETRY_SEED = 0x1234567890ABCDEFULL;
    s->rodata->CHALLENGE_HOLD_NS = 10 * SEC;
}

static void unload(void)
{
    if (skel)
    {
        minecraft_filter__destroy(skel);
        skel = NULL;
    }
}

// loads a fresh instance (empty maps) with base_config plus `configure`
static int load(configure_fn configure)
{
    unload();
    skel = minecraft_filter__open();
    if (!skel)
    {
        printf("FAIL: cannot open the BPF object: %s\n", strerror(errno));
        return -1;
    }
    base_config(skel);
    if (configure)
    {
        configure(skel);
    }
    bpf_map__set_max_entries(skel->maps.retry_table, RETRY_SLOTS);
    const int err = minecraft_filter__load(skel);
    if (err)
    {
        printf("FAIL: the kernel rejected the program: %s\n", strerror(-err));
        unload();
        return -1;
    }
    return 0;
}

#define LOAD_OR_RETURN(configure)  \
    do                             \
    {                              \
        checks_run++;              \
        if (load(configure))       \
        {                          \
            checks_failed++;       \
            return;                \
        }                          \
    } while (0)

static __u64 stat(enum stat_id id)
{
    const int cpus = libbpf_num_possible_cpus();
    struct statistics *values = calloc((size_t)cpus, sizeof(*values));
    __u32 zero = 0;
    __u64 total = 0;
    if (bpf_map__lookup_elem(skel->maps.stats_map, &zero, sizeof(zero), values, (size_t)cpus * sizeof(*values), 0) == 0)
    {
        for (int cpu = 0; cpu < cpus; cpu++)
        {
            total += values[cpu].counters[id];
        }
    }
    free(values);
    return total;
}

/* ------------------------------------------------------------------------
 * Frame building
 * --------------------------------------------------------------------- */

struct frame
{
    __u8 b[2048];
    __u32 n;
};

static int run(struct frame frame)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.b,
                .data_size_in = frame.n,
                .repeat = 1);
    const int err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.minecraft_filter), &opts);
    if (err)
    {
        printf("FAIL: BPF_PROG_TEST_RUN: %s\n", strerror(-err));
        return -1;
    }
    return (int)opts.retval;
}

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

static struct frame ipv4_frame(__u32 src_ip, __u8 protocol, __u32 l4_len)
{
    struct frame f = {{0}, 0};
    struct ethhdr *eth = (struct ethhdr *)f.b;
    eth->h_proto = htons(ETH_P_IP);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->saddr = htonl(src_ip);
    ip->daddr = htonl(SERVER_IP);
    ip->tot_len = htons((__u16)(sizeof(*ip) + l4_len));
    f.n = sizeof(*eth) + sizeof(*ip) + l4_len;
    return f;
}

static struct frame tcp_to(__u32 src_ip, __u16 src_port, __u16 dst_port, __u32 seq, __u8 flags, const void *payload, __u32 len)
{
    struct frame f = ipv4_frame(src_ip, IPPROTO_TCP, sizeof(struct tcphdr) + len);
    struct tcphdr *tcp = (struct tcphdr *)(f.b + sizeof(struct ethhdr) + sizeof(struct iphdr));
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->doff = 5;
    ((__u8 *)tcp)[13] = flags;
    if (len)
    {
        memcpy(tcp + 1, payload, len);
    }
    return f;
}

static struct frame udp_to(__u32 src_ip, __u16 src_port, __u16 dst_port, const void *payload, __u32 len)
{
    struct frame f = ipv4_frame(src_ip, IPPROTO_UDP, sizeof(struct udphdr) + len);
    struct udphdr *udp = (struct udphdr *)(f.b + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons((__u16)(sizeof(*udp) + len));
    if (len)
    {
        memcpy(udp + 1, payload, len);
    }
    return f;
}

// payload builder
struct bytes
{
    __u8 b[1600];
    __u32 n;
};

static void put(struct bytes *p, const void *data, __u32 len)
{
    memcpy(p->b + p->n, data, len);
    p->n += len;
}

static void put_u8(struct bytes *p, __u8 value)
{
    p->b[p->n++] = value;
}

static void put_varint(struct bytes *p, __s32 value)
{
    __u32 v = (__u32)value;
    do
    {
        __u8 byte = v & 0x7F;
        v >>= 7;
        if (v)
        {
            byte |= 0x80;
        }
        p->b[p->n++] = byte;
    } while (v);
}

// prefixes a packet body with its length varint, like the protocol does
static struct bytes packetize(const struct bytes *body)
{
    struct bytes pkt = {{0}, 0};
    put_varint(&pkt, (__s32)body->n);
    put(&pkt, body->b, body->n);
    return pkt;
}

static struct bytes concat(const struct bytes *a, const struct bytes *b)
{
    struct bytes out = *a;
    put(&out, b->b, b->n);
    return out;
}

#define PROTO_1_21 767
#define INTENT_STATUS 1
#define INTENT_LOGIN 2

static struct bytes mc_handshake_host(__s32 protocol, const void *host, __u32 host_len, __s32 intention)
{
    struct bytes body = {{0}, 0};
    put_varint(&body, 0x00);
    put_varint(&body, protocol);
    put_varint(&body, (__s32)host_len);
    put(&body, host, host_len);
    put_u8(&body, JAVA_PORT >> 8);
    put_u8(&body, JAVA_PORT & 0xFF);
    put_varint(&body, intention);
    return packetize(&body);
}

static struct bytes mc_handshake(const char *host, __s32 intention)
{
    return mc_handshake_host(PROTO_1_21, host, (__u32)strlen(host), intention);
}

// login start of 1.20.2+: name, uuid
static struct bytes mc_login(const char *name)
{
    struct bytes body = {{0}, 0};
    put_varint(&body, 0x00);
    put_varint(&body, (__s32)strlen(name));
    put(&body, name, (__u32)strlen(name));
    for (int i = 0; i < 16; i++)
    {
        put_u8(&body, (__u8)i);
    }
    return packetize(&body);
}

static struct bytes mc_status_request(void)
{
    struct bytes pkt = {{0x01, 0x00}, 2};
    return pkt;
}

static struct bytes mc_ping(void)
{
    struct bytes pkt = {{0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8}, 10};
    return pkt;
}

static const __u8 RAKNET_MAGIC[16] = {0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
                                      0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78};

static struct bytes raknet_ping(void)
{
    struct bytes pkt = {{0x01, 0, 0, 0, 0, 0, 0, 0, 42}, 9};
    put(&pkt, RAKNET_MAGIC, sizeof(RAKNET_MAGIC));
    for (int i = 0; i < 8; i++)
    {
        put_u8(&pkt, 0xAB);
    }
    return pkt;
}

static struct bytes raknet_ocr1(__u8 protocol, __u32 total_len)
{
    struct bytes pkt = {{0x05}, 1};
    put(&pkt, RAKNET_MAGIC, sizeof(RAKNET_MAGIC));
    put_u8(&pkt, protocol);
    if (total_len > pkt.n)
    {
        pkt.n = total_len; // zero padding up to the probed MTU
    }
    return pkt;
}

static struct bytes raknet_ocr2(void)
{
    struct bytes pkt = {{0x07}, 1};
    put(&pkt, RAKNET_MAGIC, sizeof(RAKNET_MAGIC));
    const __u8 address[7] = {4, 10, 0, 0, 1, RAKNET_PORT >> 8, RAKNET_PORT & 0xFF};
    put(&pkt, address, sizeof(address));
    put_u8(&pkt, 1492 >> 8);
    put_u8(&pkt, 1492 & 0xFF);
    for (int i = 0; i < 8; i++)
    {
        put_u8(&pkt, 0xAB);
    }
    return pkt;
}

// a frame set datagram of a connected client
static struct bytes raknet_data(void)
{
    struct bytes pkt = {{0x84, 0, 0, 0, 0x00, 0x00, 0x08, 0x15}, 8};
    return pkt;
}

static struct bytes stun_binding(__u32 attributes_len)
{
    struct bytes pkt = {{0x00, 0x01, (__u8)(attributes_len >> 8), (__u8)attributes_len, 0x21, 0x12, 0xA4, 0x42}, 8};
    pkt.n = 20 + attributes_len; // transaction id and attributes stay zero
    return pkt;
}

static struct bytes dtls_record(void)
{
    struct bytes pkt = {{0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4}, 17};
    return pkt;
}

static struct bytes tls_client_hello(void)
{
    struct bytes pkt = {{0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c, 0x03, 0x03}, 21};
    return pkt;
}

static struct bytes text(const char *s)
{
    struct bytes pkt = {{0}, 0};
    put(&pkt, s, (__u32)strlen(s));
    return pkt;
}

/* ------------------------------------------------------------------------
 * Client helpers
 * --------------------------------------------------------------------- */

// the TCP handshake as the filter sees it: SYN passes, the bare ACK is dropped
static void tcp_handshake(__u32 ip, __u16 port, __u16 dst_port, __u32 isn)
{
    PASSES(tcp_to(ip, port, dst_port, isn, TCP_SYN, NULL, 0));
    DROPS(tcp_to(ip, port, dst_port, isn + 1, TCP_ACK, NULL, 0));
}

static struct frame tcp_data(__u32 ip, __u16 port, __u16 dst_port, __u32 seq, const struct bytes *payload)
{
    return tcp_to(ip, port, dst_port, seq, TCP_ACK | TCP_PSH, payload->b, payload->n);
}

// handshake + login in separate segments; returns the next sequence number
static __u32 java_login(__u32 ip, __u16 port, __u32 isn, int expect_verified)
{
    const struct bytes handshake = mc_handshake("mc.example.com", INTENT_LOGIN);
    const struct bytes login = mc_login("Steve");
    __u32 seq = isn + 1;
    tcp_handshake(ip, port, JAVA_PORT, isn);
    const int verdict = run(tcp_data(ip, port, JAVA_PORT, seq, &handshake));
    CHECK(verdict == (expect_verified ? XDP_PASS : XDP_DROP));
    if (verdict != XDP_PASS)
    {
        return seq;
    }
    seq += handshake.n;
    PASSES(tcp_data(ip, port, JAVA_PORT, seq, &login));
    return seq + login.n;
}

static void raknet_connect(__u32 ip, __u16 port)
{
    const struct bytes ocr1 = raknet_ocr1(11, 1464);
    const struct bytes ocr2 = raknet_ocr2();
    PASSES(udp_to(ip, port, RAKNET_PORT, ocr1.b, ocr1.n));
    PASSES(udp_to(ip, port, RAKNET_PORT, ocr2.b, ocr2.n));
}

/* ------------------------------------------------------------------------
 * Scenarios
 * --------------------------------------------------------------------- */

static void all_features(struct minecraft_filter *s)
{
    s->rodata->IPV6_PROTECT = 1;
    s->rodata->HAS_ALLOW = 1;
    s->rodata->HAS_DENY = 1;
    s->rodata->ADOPT_MODE = 1;
    s->rodata->ADOPT_UNTIL_NS = monotonic_ns() + 60 * SEC;
    s->rodata->HOST_FILTER = 1;
    s->rodata->JAVA_PROTO_MIN = 47;
    s->rodata->JAVA_PROTO_MAX = 1000;
    s->rodata->STATUS_HITS = 10;
    s->rodata->STATUS_BUDGET = 100;
    s->rodata->LOGIN_BUDGET = 100;
    s->rodata->SYN_HITS = 10;
    s->rodata->SYN_BUDGET = 1000;
    s->rodata->TCP_FLOW_PPS = 3000;
    s->rodata->PING_HITS = 10;
    s->rodata->PING_BUDGET = 100;
    s->rodata->UDP_OPEN_HITS = 10;
    s->rodata->UDP_OPEN_BUDGET = 100;
    s->rodata->UDP_FLOW_PPS = 600;
    s->rodata->CHALLENGE_MODE = 1;
    s->rodata->CHALLENGE_PPS = 100;
    s->rodata->GOOD_AFTER_NS = 120 * SEC;
    s->rodata->GOOD_TTL_NS = 86400 * SEC;
}

static void all_features_always(struct minecraft_filter *s)
{
    all_features(s);
    s->rodata->CHALLENGE_MODE = 2;
    s->rodata->ADOPT_MODE = 2;
    s->rodata->ONLINE_NAMES = 0;
    s->rodata->PROMETHEUS = 0;
}

// the verifier has to accept the program with everything switched on
static void test_verifier_accepts_every_feature(void)
{
    LOAD_OR_RETURN(all_features);
    struct bpf_prog_info info = {0};
    __u32 len = sizeof(info);
    if (bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.minecraft_filter), &info, &len) == 0)
    {
        printf("program with every feature enabled: %u bytes translated, %u bytes jited, %u instructions verified\n",
               info.xlated_prog_len, info.jited_prog_len, info.verified_insns);
    }
    LOAD_OR_RETURN(all_features_always);
    LOAD_OR_RETURN(NULL);
}

static void test_unprotected_traffic_passes(void)
{
    LOAD_OR_RETURN(NULL);
    PASSES(tcp_to(CLIENT_IP, 4000, OTHER_PORT, 1, TCP_ACK, "x", 1));
    PASSES(udp_to(CLIENT_IP, 4000, 53, "x", 1));
    // icmp
    PASSES(ipv4_frame(CLIENT_IP, IPPROTO_ICMP, 8));
    // arp
    struct frame arp = {{0}, 42};
    ((struct ethhdr *)arp.b)->h_proto = htons(ETH_P_ARP);
    PASSES(arp);
    CHECK(stat(STAT_INCOMING_PACKETS) == 0);
}

static void test_java_login(void)
{
    LOAD_OR_RETURN(NULL);
    const __u32 seq = java_login(CLIENT_IP, 5000, 1000, 1);
    CHECK(stat(STAT_JAVA_VERIFIED) == 1);

    // verified: anything goes, in any order
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, "data", 4));
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq + 500, TCP_ACK, NULL, 0));
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq + 4, TCP_ACK | TCP_FIN, NULL, 0));

    // the same client from another port is a different flow
    DROPS(tcp_to(CLIENT_IP, 5001, JAVA_PORT, seq, TCP_ACK, "data", 4));
    CHECK(stat(STAT_TCP_UNTRACKED) == 1);
}

static void test_java_login_in_one_segment(void)
{
    LOAD_OR_RETURN(NULL);
    const struct bytes handshake = mc_handshake("mc.example.com", INTENT_LOGIN);
    const struct bytes login = mc_login("Steve");
    const struct bytes both = concat(&handshake, &login);
    tcp_handshake(CLIENT_IP, 5000, JAVA_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5000, JAVA_PORT, 1001, &both));
    CHECK(stat(STAT_JAVA_VERIFIED) == 1);

    // the ack finishing the tcp handshake may carry the data already
    PASSES(tcp_to(CLIENT_IP, 5002, JAVA_PORT, 2000, TCP_SYN, NULL, 0));
    PASSES(tcp_data(CLIENT_IP, 5002, JAVA_PORT, 2001, &both));
    CHECK(stat(STAT_JAVA_VERIFIED) == 2);
}

static void test_java_status(void)
{
    LOAD_OR_RETURN(NULL);
    const struct bytes handshake = mc_handshake("mc.example.com", INTENT_STATUS);
    const struct bytes request = mc_status_request();
    const struct bytes ping = mc_ping();
    __u32 seq = 1001;

    tcp_handshake(CLIENT_IP, 5000, JAVA_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5000, JAVA_PORT, seq, &handshake));
    seq += handshake.n;
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0)); // pure ack of server data
    PASSES(tcp_data(CLIENT_IP, 5000, JAVA_PORT, seq, &request));
    seq += request.n;
    PASSES(tcp_data(CLIENT_IP, 5000, JAVA_PORT, seq, &ping));
    seq += ping.n;
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK | TCP_FIN, NULL, 0));
    // a finished ping has nothing more to say
    DROPS(tcp_data(CLIENT_IP, 5000, JAVA_PORT, seq, &ping));
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
    CHECK(stat(STAT_JAVA_STATUS) == 1);
    CHECK(stat(STAT_JAVA_VERIFIED) == 0);
}

static void test_java_rejects_garbage(void)
{
    LOAD_OR_RETURN(NULL);
    const struct bytes handshake = mc_handshake("mc.example.com", INTENT_LOGIN);
    const struct bytes login = mc_login("Steve");

    // data without any tcp handshake
    DROPS(tcp_data(CLIENT_IP, 5000, JAVA_PORT, 1, &handshake));
    // SYN with payload, impossible flags
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1, TCP_SYN, "x", 1));
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1, TCP_SYN | TCP_ACK, NULL, 0));
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1, TCP_SYN | TCP_FIN, NULL, 0));
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1, 0, NULL, 0));
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1, TCP_ACK | TCP_URG, NULL, 0));

    // ack with the wrong sequence number
    PASSES(tcp_to(CLIENT_IP, 5001, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    DROPS(tcp_to(CLIENT_IP, 5001, JAVA_PORT, 5555, TCP_ACK, NULL, 0));

    // garbage instead of the handshake
    tcp_handshake(CLIENT_IP, 5002, JAVA_PORT, 1000);
    const struct bytes garbage = text("GET / HTTP/1.1\r\n\r\n");
    DROPS(tcp_data(CLIENT_IP, 5002, JAVA_PORT, 1001, &garbage));

    // legacy ping
    tcp_handshake(CLIENT_IP, 5003, JAVA_PORT, 1000);
    DROPS(tcp_to(CLIENT_IP, 5003, JAVA_PORT, 1001, TCP_ACK, "\xFE\x01", 2));
    DROPS(tcp_data(CLIENT_IP, 5003, JAVA_PORT, 1001, &handshake)); // connection is gone

    // valid handshake, then a login with a name longer than 16 characters
    tcp_handshake(CLIENT_IP, 5004, JAVA_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5004, JAVA_PORT, 1001, &handshake));
    const struct bytes long_name = mc_login("ThisNameIsWayTooLongForMojang");
    DROPS(tcp_data(CLIENT_IP, 5004, JAVA_PORT, 1001 + handshake.n, &long_name));

    // retransmitted handshake: dropped, and the connection with it after a few
    tcp_handshake(CLIENT_IP, 5005, JAVA_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5005, JAVA_PORT, 1001, &handshake));
    for (int i = 0; i < 5; i++)
    {
        DROPS(tcp_data(CLIENT_IP, 5005, JAVA_PORT, 1001, &handshake));
    }
    DROPS(tcp_data(CLIENT_IP, 5005, JAVA_PORT, 1001 + handshake.n, &login));

    // first fragment, truncated tcp header
    struct frame fragment = tcp_to(CLIENT_IP, 5006, JAVA_PORT, 1000, TCP_SYN, NULL, 0);
    ((struct iphdr *)(fragment.b + sizeof(struct ethhdr)))->frag_off = htons(0x2000);
    DROPS(fragment);
    CHECK(stat(STAT_FRAGMENT_DROPPED) == 1);
    struct frame truncated = tcp_to(CLIENT_IP, 5006, JAVA_PORT, 1000, TCP_SYN, NULL, 0);
    truncated.n -= 4;
    DROPS(truncated);

    CHECK(stat(STAT_JAVA_VERIFIED) == 0);
}

static void with_host_filter(struct minecraft_filter *s)
{
    s->rodata->HOST_FILTER = 1;
}

// reference implementation of hash_host() for names that need no normalizing
static __u64 fnv1a64(const char *s)
{
    __u64 hash = 0xCBF29CE484222325ULL;
    for (; *s; s++)
    {
        hash = (hash ^ (__u8)*s) * 0x100000001B3ULL;
    }
    return hash;
}

static void java_host(__u16 port, const void *host, __u32 host_len, __s32 intention, int expected)
{
    const struct bytes handshake = mc_handshake_host(PROTO_1_21, host, host_len, intention);
    tcp_handshake(CLIENT_IP, port, JAVA_PORT, 1000);
    CHECK(run(tcp_data(CLIENT_IP, port, JAVA_PORT, 1001, &handshake)) == expected);
}

static void test_java_host_filter(void)
{
    LOAD_OR_RETURN(with_host_filter);
    const __u8 one = 1;
    __u64 key = fnv1a64("mc.example.com");
    CHECK(bpf_map__update_elem(skel->maps.allowed_hosts, &key, sizeof(key), &one, sizeof(one), BPF_ANY) == 0);
    key = fnv1a64("198.51.100.200");
    CHECK(bpf_map__update_elem(skel->maps.allowed_hosts, &key, sizeof(key), &one, sizeof(one), BPF_ANY) == 0);

    java_host(5000, "mc.example.com", 14, INTENT_LOGIN, XDP_PASS);
    java_host(5001, "MC.Example.COM", 14, INTENT_STATUS, XDP_PASS);
    java_host(5002, "mc.example.com.", 15, INTENT_LOGIN, XDP_PASS);        // SRV target with root dot
    java_host(5003, "mc.example.com\0FML\0", 19, INTENT_LOGIN, XDP_PASS);   // Forge marker
    java_host(5004, "mc.example.com.\0FML3\0", 21, INTENT_LOGIN, XDP_PASS);
    java_host(5005, "198.51.100.200", 14, INTENT_LOGIN, XDP_PASS);

    java_host(5010, "evil.example.com", 16, INTENT_LOGIN, XDP_DROP);
    java_host(5011, "mc.example.co", 13, INTENT_LOGIN, XDP_DROP);
    java_host(5012, "mc.example.comm", 15, INTENT_STATUS, XDP_DROP);
    java_host(5013, "10.0.0.1", 8, INTENT_LOGIN, XDP_DROP);
    java_host(5014, "", 0, INTENT_LOGIN, XDP_DROP);
    java_host(5015, "mc.example.com..", 16, INTENT_LOGIN, XDP_DROP);
    char long_host[200];
    memset(long_host, 'a', sizeof(long_host));
    java_host(5016, long_host, sizeof(long_host), INTENT_LOGIN, XDP_DROP);
    java_host(5017, long_host, 65, INTENT_LOGIN, XDP_DROP);
    CHECK(stat(STAT_JAVA_BAD_HOST) == 8);

    // the longest name the filter can match
    long_host[64] = 0;
    __u64 long_key = fnv1a64(long_host);
    CHECK(bpf_map__update_elem(skel->maps.allowed_hosts, &long_key, sizeof(long_key), &one, sizeof(one), BPF_ANY) == 0);
    java_host(5018, long_host, 64, INTENT_LOGIN, XDP_PASS);

    // a rejected handshake takes the whole connection with it
    const struct bytes login = mc_login("Steve");
    DROPS(tcp_data(CLIENT_IP, 5010, JAVA_PORT, 1001, &login));
}

static void with_protocol_range(struct minecraft_filter *s)
{
    s->rodata->JAVA_PROTO_MIN = 754; // 1.16.5
    s->rodata->JAVA_PROTO_MAX = 800;
}

static void test_java_protocol_range(void)
{
    LOAD_OR_RETURN(with_protocol_range);
    const struct bytes old_login = mc_handshake_host(47, "h", 1, INTENT_LOGIN);
    const struct bytes new_login = mc_handshake_host(900, "h", 1, INTENT_LOGIN);
    const struct bytes ok_login = mc_handshake_host(754, "h", 1, INTENT_LOGIN);
    const struct bytes old_status = mc_handshake_host(-1, "h", 1, INTENT_STATUS);

    tcp_handshake(CLIENT_IP, 5000, JAVA_PORT, 1000);
    DROPS(tcp_data(CLIENT_IP, 5000, JAVA_PORT, 1001, &old_login));
    tcp_handshake(CLIENT_IP, 5001, JAVA_PORT, 1000);
    DROPS(tcp_data(CLIENT_IP, 5001, JAVA_PORT, 1001, &new_login));
    tcp_handshake(CLIENT_IP, 5002, JAVA_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5002, JAVA_PORT, 1001, &ok_login));
    // server list pingers send whatever version they like
    tcp_handshake(CLIENT_IP, 5003, JAVA_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5003, JAVA_PORT, 1001, &old_status));
    CHECK(stat(STAT_JAVA_BAD_PROTO) == 2);
}

static void with_ip_limits(struct minecraft_filter *s)
{
    s->rodata->SYN_HITS = 3;
    s->rodata->STATUS_HITS = 2;
    s->rodata->PING_HITS = 2;
    s->rodata->UDP_OPEN_HITS = 2;
}

static void test_per_ip_limits(void)
{
    LOAD_OR_RETURN(with_ip_limits);
    const struct bytes status = mc_handshake("h", INTENT_STATUS);
    const struct bytes ping = raknet_ping();
    const struct bytes ocr1 = raknet_ocr1(11, 1464);

    // SYNs
    for (__u16 i = 0; i < 3; i++)
    {
        PASSES(tcp_to(CLIENT_IP, 5000 + i, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    }
    DROPS(tcp_to(CLIENT_IP, 5003, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    DROPS(tcp_to(CLIENT_IP, 5003, GUARD_PORT, 1000, TCP_SYN, NULL, 0));
    PASSES(tcp_to(CLIENT_IP + 1, 5003, JAVA_PORT, 1000, TCP_SYN, NULL, 0)); // other ips are not affected
    CHECK(stat(STAT_SYN_THROTTLED) == 2);

    // status requests (on the connections opened above)
    for (__u16 i = 0; i < 2; i++)
    {
        DROPS(tcp_to(CLIENT_IP, 5000 + i, JAVA_PORT, 1001, TCP_ACK, NULL, 0));
        PASSES(tcp_data(CLIENT_IP, 5000 + i, JAVA_PORT, 1001, &status));
    }
    DROPS(tcp_to(CLIENT_IP, 5002, JAVA_PORT, 1001, TCP_ACK, NULL, 0));
    DROPS(tcp_data(CLIENT_IP, 5002, JAVA_PORT, 1001, &status));
    CHECK(stat(STAT_STATUS_THROTTLED) == 1);

    // RakNet pings and new sessions
    for (__u16 i = 0; i < 2; i++)
    {
        PASSES(udp_to(CLIENT_IP, 6000 + i, RAKNET_PORT, ping.b, ping.n));
        PASSES(udp_to(CLIENT_IP, 6000 + i, RAKNET_PORT, ocr1.b, ocr1.n));
    }
    DROPS(udp_to(CLIENT_IP, 6002, RAKNET_PORT, ping.b, ping.n));
    DROPS(udp_to(CLIENT_IP, 6002, RAKNET_PORT, ocr1.b, ocr1.n));
    // resent while probing the MTU: not a new opener
    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, ocr1.b, ocr1.n));
    CHECK(stat(STAT_PING_THROTTLED) == 1);
    CHECK(stat(STAT_UDP_OPEN_THROTTLED) == 1);

    // a new window resets everything
    sleep_ms(1100);
    PASSES(tcp_to(CLIENT_IP, 5003, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    PASSES(udp_to(CLIENT_IP, 6002, RAKNET_PORT, ping.b, ping.n));
    PASSES(udp_to(CLIENT_IP, 6002, RAKNET_PORT, ocr1.b, ocr1.n));
}

static void with_challenge_always(struct minecraft_filter *s)
{
    s->rodata->CHALLENGE_MODE = 2;
}

static void test_challenge(void)
{
    LOAD_OR_RETURN(with_challenge_always);
    const struct frame syn = tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0);
    const struct bytes ping = raknet_ping();
    const struct bytes ocr1 = raknet_ocr1(11, 1464);
    const struct bytes stun = stun_binding(8);

    // unknown ip: the first SYN is dropped, a duplicate right after it too
    DROPS(syn);
    DROPS(syn);
    // other unknown ips, each with its own first sighting
    DROPS(udp_to(CLIENT_IP + 1, 6000, RAKNET_PORT, ping.b, ping.n));
    DROPS(udp_to(CLIENT_IP + 2, 6000, RAKNET_PORT, ocr1.b, ocr1.n));
    DROPS(udp_to(CLIENT_IP + 3, 6000, ICE_PORT, stun.b, stun.n));
    CHECK(stat(STAT_CHALLENGE_DROPPED) == 5);

    sleep_ms(400);
    // a different SYN of the same ip is another first sighting
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1001, TCP_SYN, NULL, 0));
    // the retransmits pass
    PASSES(syn);
    PASSES(udp_to(CLIENT_IP + 1, 6000, RAKNET_PORT, ping.b, ping.n));
    PASSES(udp_to(CLIENT_IP + 2, 6000, RAKNET_PORT, ocr1.b, ocr1.n));
    PASSES(udp_to(CLIENT_IP + 3, 6000, ICE_PORT, stun.b, stun.n));
    CHECK(stat(STAT_CHALLENGE_PASSED) == 4);
    CHECK(stat(STAT_NEW_IP) == 4);

    // the ip is known now, nothing else is challenged
    PASSES(tcp_to(CLIENT_IP, 5001, JAVA_PORT, 7777, TCP_SYN, NULL, 0));
    PASSES(udp_to(CLIENT_IP, 6001, RAKNET_PORT, ping.b, ping.n));
    PASSES(udp_to(CLIENT_IP + 1, 6001, RAKNET_PORT, ocr1.b, ocr1.n));

    // and the challenged connection works like any other
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1001, TCP_ACK, NULL, 0));
    const struct bytes handshake = mc_handshake("h", INTENT_LOGIN);
    PASSES(tcp_data(CLIENT_IP, 5000, JAVA_PORT, 1001, &handshake));
}

static void with_challenge_auto(struct minecraft_filter *s)
{
    s->rodata->CHALLENGE_MODE = 1;
    s->rodata->CHALLENGE_PPS = 5;
    s->rodata->CHALLENGE_HOLD_NS = 1500 * MS;
}

static void test_challenge_arms_under_flood(void)
{
    LOAD_OR_RETURN(with_challenge_auto);

    // a known ip from calm times
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    sleep_ms(1100);

    // a flood of unknown ips: the first few of a second get through ...
    int passed = 0;
    for (__u32 i = 1; i <= 50; i++)
    {
        passed += run(tcp_to(0x0B000000u + i, 5000, JAVA_PORT, i, TCP_SYN, NULL, 0)) == XDP_PASS;
    }
    CHECK(passed == 5);
    CHECK(stat(STAT_CHALLENGE_DROPPED) == 45);
    // ... while known ips are not bothered at all
    PASSES(tcp_to(CLIENT_IP, 5001, JAVA_PORT, 1, TCP_SYN, NULL, 0));

    // a real newcomer during the flood gets in with his retransmit
    DROPS(tcp_to(CLIENT_IP + 9, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    sleep_ms(1000);
    PASSES(tcp_to(CLIENT_IP + 9, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));

    // still armed (hold time), disarmed once the flood has been over for a while
    DROPS(tcp_to(CLIENT_IP + 10, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    sleep_ms(1700);
    PASSES(tcp_to(CLIENT_IP + 11, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
}

static void with_budgets(struct minecraft_filter *s)
{
    s->rodata->SYN_BUDGET = 6;
    s->rodata->LOGIN_BUDGET = 2;
    s->rodata->STATUS_BUDGET = 1;
    s->rodata->PING_BUDGET = 2;
    s->rodata->UDP_OPEN_BUDGET = 2;
    s->rodata->GOOD_AFTER_NS = 1 * SEC;
    s->rodata->GOOD_TTL_NS = 60 * SEC;
}

static void test_budgets_and_good_ips(void)
{
    LOAD_OR_RETURN(with_budgets);
    const struct bytes login = mc_handshake("h", INTENT_LOGIN);
    const struct bytes status = mc_handshake("h", INTENT_STATUS);
    const struct bytes ping = raknet_ping();
    const struct bytes ocr1 = raknet_ocr1(11, 1464);
    const __u32 player = CLIENT_IP + 100;

    // a player who stays connected becomes a proven player
    __u32 seq = java_login(player, 4000, 1, 1);
    sleep_ms(1100);
    PASSES(tcp_to(player, 4000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
    CHECK(stat(STAT_GOOD_IP) == 1);
    sleep_ms(1100); // fresh second for the budgets

    // logins: two per second for everyone else
    for (__u16 i = 0; i < 3; i++)
    {
        tcp_handshake(CLIENT_IP + i, 5000, JAVA_PORT, 1000);
        CHECK(run(tcp_data(CLIENT_IP + i, 5000, JAVA_PORT, 1001, &login)) == (i < 2 ? XDP_PASS : XDP_DROP));
    }
    // status: one per second
    tcp_handshake(CLIENT_IP + 3, 5000, JAVA_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP + 3, 5000, JAVA_PORT, 1001, &status));
    tcp_handshake(CLIENT_IP + 4, 5000, JAVA_PORT, 1000);
    DROPS(tcp_data(CLIENT_IP + 4, 5000, JAVA_PORT, 1001, &status));
    // SYNs: six per second, five are used up
    PASSES(tcp_to(CLIENT_IP + 5, 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    DROPS(tcp_to(CLIENT_IP + 6, 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    CHECK(stat(STAT_TCP_BUDGET_DROPPED) == 3);

    // RakNet pings and sessions: two per second each
    for (__u16 i = 0; i < 3; i++)
    {
        CHECK(run(udp_to(CLIENT_IP + i, 6000, RAKNET_PORT, ping.b, ping.n)) == (i < 2 ? XDP_PASS : XDP_DROP));
        CHECK(run(udp_to(CLIENT_IP + i, 6001, RAKNET_PORT, ocr1.b, ocr1.n)) == (i < 2 ? XDP_PASS : XDP_DROP));
    }
    CHECK(stat(STAT_UDP_BUDGET_DROPPED) == 2);

    // the proven player is served no matter how empty the budgets are
    tcp_handshake(player, 4001, JAVA_PORT, 1000);
    PASSES(tcp_data(player, 4001, JAVA_PORT, 1001, &login));
    tcp_handshake(player, 4002, JAVA_PORT, 1000);
    PASSES(tcp_data(player, 4002, JAVA_PORT, 1001, &status));
    PASSES(udp_to(player, 6000, RAKNET_PORT, ping.b, ping.n));
    PASSES(udp_to(player, 6001, RAKNET_PORT, ocr1.b, ocr1.n));

    // everyone else is back in the next second
    sleep_ms(1100);
    tcp_handshake(CLIENT_IP + 7, 5000, JAVA_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP + 7, 5000, JAVA_PORT, 1001, &login));
    PASSES(udp_to(CLIENT_IP + 7, 6000, RAKNET_PORT, ping.b, ping.n));
}

static void with_flow_limits(struct minecraft_filter *s)
{
    s->rodata->TCP_FLOW_PPS = 5;
    s->rodata->UDP_FLOW_PPS = 5;
    s->rodata->TCP_IDLE_NS = 1500 * MS;
    s->rodata->UDP_IDLE_NS = 1500 * MS;
}

static void test_flow_rate_and_idle(void)
{
    LOAD_OR_RETURN(with_flow_limits);
    const struct bytes data = raknet_data();
    const __u32 seq = java_login(CLIENT_IP, 5000, 1000, 1);
    raknet_connect(CLIENT_IP, 6000);

    // the verifying packet is the first of the window
    for (int i = 0; i < 4; i++)
    {
        PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
        PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    }
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
    DROPS(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    CHECK(stat(STAT_TCP_RATE_LIMITED) == 1);
    CHECK(stat(STAT_UDP_RATE_LIMITED) == 1);

    // next second: flowing again
    sleep_ms(1100);
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));

    // idle for longer than the timeout: both are forgotten
    sleep_ms(1700);
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
    DROPS(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
    DROPS(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
}

static void test_guard(void)
{
    LOAD_OR_RETURN(NULL);
    const struct bytes hello = tls_client_hello();
    const struct bytes get = text("GET /v1/join HTTP/1.1\r\nHost: bedrock.example.com\r\n\r\n");
    const struct bytes post = text("POST /v1/join/1 HTTP/1.1\r\n\r\n");
    const struct bytes handshake = mc_handshake("h", INTENT_LOGIN);
    const struct bytes ssh = text("SSH-2.0-OpenSSH_9.9\r\n");

    tcp_handshake(CLIENT_IP, 5000, GUARD_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5000, GUARD_PORT, 1001, &hello));
    PASSES(tcp_to(CLIENT_IP, 5000, GUARD_PORT, 1001 + hello.n, TCP_ACK, "anything", 8));

    tcp_handshake(CLIENT_IP, 5001, GUARD_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5001, GUARD_PORT, 1001, &get));
    tcp_handshake(CLIENT_IP, 5002, GUARD_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5002, GUARD_PORT, 1001, &post));
    CHECK(stat(STAT_GUARD_VERIFIED) == 3);

    tcp_handshake(CLIENT_IP, 5003, GUARD_PORT, 1000);
    DROPS(tcp_data(CLIENT_IP, 5003, GUARD_PORT, 1001, &handshake));
    DROPS(tcp_data(CLIENT_IP, 5003, GUARD_PORT, 1001, &hello)); // connection is gone
    tcp_handshake(CLIENT_IP, 5004, GUARD_PORT, 1000);
    DROPS(tcp_data(CLIENT_IP, 5004, GUARD_PORT, 1001, &ssh));
    tcp_handshake(CLIENT_IP, 5005, GUARD_PORT, 1000);
    DROPS(tcp_to(CLIENT_IP, 5005, GUARD_PORT, 1001, TCP_ACK, "GET", 3)); // too short to tell
    CHECK(stat(STAT_GUARD_INVALID) == 3);

    // and a TLS hello is not a Minecraft handshake
    tcp_handshake(CLIENT_IP, 5006, JAVA_PORT, 1000);
    DROPS(tcp_data(CLIENT_IP, 5006, JAVA_PORT, 1001, &hello));
}

static void tls_only(struct minecraft_filter *s)
{
    s->rodata->GUARD_HTTP = 0;
}

static void test_guard_tls_only(void)
{
    LOAD_OR_RETURN(tls_only);
    const struct bytes hello = tls_client_hello();
    const struct bytes get = text("GET / HTTP/1.1\r\n\r\n");
    tcp_handshake(CLIENT_IP, 5000, GUARD_PORT, 1000);
    PASSES(tcp_data(CLIENT_IP, 5000, GUARD_PORT, 1001, &hello));
    tcp_handshake(CLIENT_IP, 5001, GUARD_PORT, 1000);
    DROPS(tcp_data(CLIENT_IP, 5001, GUARD_PORT, 1001, &get));
}

static void test_raknet(void)
{
    LOAD_OR_RETURN(NULL);
    const struct bytes ping = raknet_ping();
    const struct bytes ocr1 = raknet_ocr1(11, 1464);
    const struct bytes ocr2 = raknet_ocr2();
    const struct bytes data = raknet_data();
    const __u8 ack[] = {0xc0, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00};

    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, ping.b, ping.n));
    CHECK(stat(STAT_RAKNET_PING) == 1);

    // game traffic before the session exists
    DROPS(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    DROPS(udp_to(CLIENT_IP, 6000, RAKNET_PORT, ocr2.b, ocr2.n));
    CHECK(stat(STAT_UDP_UNTRACKED) == 2);

    raknet_connect(CLIENT_IP, 6000);
    CHECK(stat(STAT_RAKNET_VERIFIED) == 1);
    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, ack, sizeof(ack)));
    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, ocr2.b, ocr2.n)); // resent
    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, ping.b, ping.n));
    // not something a connected client sends
    DROPS(udp_to(CLIENT_IP, 6000, RAKNET_PORT, "\x1c\x00\x00", 3));
    // the session belongs to this address only
    DROPS(udp_to(CLIENT_IP, 6001, RAKNET_PORT, data.b, data.n));
    DROPS(udp_to(CLIENT_IP + 1, 6000, RAKNET_PORT, data.b, data.n));

    // the smaller MTU probes of a client
    const struct bytes ocr1_small = raknet_ocr1(11, 548);
    PASSES(udp_to(CLIENT_IP, 6002, RAKNET_PORT, ocr1.b, ocr1.n));
    PASSES(udp_to(CLIENT_IP, 6002, RAKNET_PORT, ocr1_small.b, ocr1_small.n));
    PASSES(udp_to(CLIENT_IP, 6002, RAKNET_PORT, ocr2.b, ocr2.n));

    // malformed
    struct bytes bad = raknet_ping();
    bad.b[12] ^= 0xFF; // magic
    DROPS(udp_to(CLIENT_IP, 6003, RAKNET_PORT, bad.b, bad.n));
    DROPS(udp_to(CLIENT_IP, 6003, RAKNET_PORT, ping.b, ping.n - 1));
    bad = raknet_ocr1(11, 1464);
    bad.b[3] ^= 0xFF;
    DROPS(udp_to(CLIENT_IP, 6003, RAKNET_PORT, bad.b, bad.n));
    bad = raknet_ocr1(8, 1464); // protocol too old
    DROPS(udp_to(CLIENT_IP, 6003, RAKNET_PORT, bad.b, bad.n));
    bad = raknet_ocr1(12, 1464);
    DROPS(udp_to(CLIENT_IP, 6003, RAKNET_PORT, bad.b, bad.n));
    bad = raknet_ocr1(11, 18); // not padded: no client does that
    DROPS(udp_to(CLIENT_IP, 6003, RAKNET_PORT, bad.b, bad.n));
    DROPS(udp_to(CLIENT_IP, 6003, RAKNET_PORT, "\x09garbage", 8));
    DROPS(udp_to(CLIENT_IP, 6003, RAKNET_PORT, NULL, 0));
    CHECK(stat(STAT_RAKNET_INVALID) == 8);
    CHECK(stat(STAT_MALFORMED) == 1);

    // udp length field lying about the datagram
    struct frame lying = udp_to(CLIENT_IP, 6003, RAKNET_PORT, ping.b, ping.n);
    ((struct udphdr *)(lying.b + sizeof(struct ethhdr) + sizeof(struct iphdr)))->len = htons(1400);
    DROPS(lying);

    // first fragment
    struct frame fragment = udp_to(CLIENT_IP, 6003, RAKNET_PORT, ping.b, ping.n);
    ((struct iphdr *)(fragment.b + sizeof(struct ethhdr)))->frag_off = htons(0x2000);
    DROPS(fragment);
}

static void test_ice(void)
{
    LOAD_OR_RETURN(NULL);
    const struct bytes stun = stun_binding(72);
    const struct bytes dtls = dtls_record();

    // dtls before any connectivity check
    DROPS(udp_to(CLIENT_IP, 7000, ICE_PORT, dtls.b, dtls.n));
    CHECK(stat(STAT_UDP_UNTRACKED) == 1);

    PASSES(udp_to(CLIENT_IP, 7000, ICE_PORT, stun.b, stun.n));
    CHECK(stat(STAT_ICE_VERIFIED) == 1);
    PASSES(udp_to(CLIENT_IP, 7000, ICE_PORT, dtls.b, dtls.n));
    PASSES(udp_to(CLIENT_IP, 7000, ICE_PORT, stun.b, stun.n)); // consent freshness
    PASSES(udp_to(CLIENT_IP, 7000, ICE_PORT, "\x17\xfe\xfd payload", 11));
    // rtp, raknet and garbage have no business here
    DROPS(udp_to(CLIENT_IP, 7000, ICE_PORT, "\x80\x00\x00\x00", 4));
    DROPS(udp_to(CLIENT_IP, 7000, ICE_PORT, "\xff\xff\xff\xff", 4));

    // every port of the range, each its own session
    PASSES(udp_to(CLIENT_IP, 7001, ICE_PORT + 9, stun.b, stun.n));
    DROPS(udp_to(CLIENT_IP, 7001, ICE_PORT, dtls.b, dtls.n));
    PASSES(udp_to(CLIENT_IP, 7001, ICE_PORT + 10, "outside the range", 17));

    // malformed stun
    struct bytes bad = stun_binding(72);
    bad.b[4] ^= 0xFF; // cookie
    DROPS(udp_to(CLIENT_IP, 7002, ICE_PORT, bad.b, bad.n));
    bad = stun_binding(72);
    bad.b[1] = 0x11; // binding response, not a request
    DROPS(udp_to(CLIENT_IP, 7002, ICE_PORT, bad.b, bad.n));
    bad = stun_binding(72);
    DROPS(udp_to(CLIENT_IP, 7002, ICE_PORT, bad.b, bad.n - 4)); // length mismatch
    DROPS(udp_to(CLIENT_IP, 7002, ICE_PORT, bad.b, 10));
}

static void with_lists(struct minecraft_filter *s)
{
    s->rodata->HAS_ALLOW = 1;
    s->rodata->HAS_DENY = 1;
}

struct lpm_key
{
    __u32 prefixlen;
    __u32 addr;
};

static void test_lists(void)
{
    LOAD_OR_RETURN(with_lists);
    const __u8 one = 1;
    struct lpm_key key = {24, htonl(0xCB007100u)}; // 203.0.113.0/24
    CHECK(bpf_map__update_elem(skel->maps.deny_v4, &key, sizeof(key), &one, sizeof(one), BPF_ANY) == 0);
    key = (struct lpm_key){32, htonl(0xC0000207u)}; // 192.0.2.7
    CHECK(bpf_map__update_elem(skel->maps.allow_v4, &key, sizeof(key), &one, sizeof(one), BPF_ANY) == 0);
    const struct bytes ping = raknet_ping();

    DROPS(tcp_to(0xCB007142u, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    DROPS(udp_to(0xCB007101u, 6000, RAKNET_PORT, ping.b, ping.n));
    PASSES(tcp_to(0xCB007142u, 5000, OTHER_PORT, 1, TCP_SYN, NULL, 0)); // only protected ports
    CHECK(stat(STAT_DENYLIST) == 2);

    // allowed: no inspection at all
    PASSES(tcp_to(0xC0000207u, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    PASSES(tcp_to(0xC0000207u, 5000, JAVA_PORT, 2, TCP_ACK, NULL, 0));
    PASSES(tcp_to(0xC0000207u, 5000, JAVA_PORT, 2, TCP_ACK, "whatever", 8));
    PASSES(udp_to(0xC0000207u, 6000, RAKNET_PORT, "whatever", 8));
    PASSES(udp_to(0xC0000207u, 6000, ICE_PORT, "\x16whatever", 9));
    DROPS(tcp_to(0xC0000208u, 5000, JAVA_PORT, 2, TCP_ACK, "whatever", 8));

    // everyone else is filtered as usual
    java_login(CLIENT_IP, 5000, 1000, 1);
}

static void adopt_blind(struct minecraft_filter *s)
{
    s->rodata->ADOPT_MODE = 2;
    s->rodata->ADOPT_UNTIL_NS = monotonic_ns() + 1500 * MS;
}

static void test_adopt_blind(void)
{
    LOAD_OR_RETURN(adopt_blind);
    const struct bytes data = raknet_data();
    const struct bytes dtls = dtls_record();

    // flows from before the filter was attached
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1234, TCP_ACK, "data", 4));
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1238, TCP_ACK, NULL, 0));
    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    PASSES(udp_to(CLIENT_IP, 7000, ICE_PORT, dtls.b, dtls.n));
    CHECK(stat(STAT_TCP_ADOPTED) == 1);
    CHECK(stat(STAT_UDP_ADOPTED) == 2);
    // still nothing that could not be an established flow
    DROPS(tcp_to(CLIENT_IP, 5001, JAVA_PORT, 1, TCP_RST, NULL, 0));
    DROPS(udp_to(CLIENT_IP, 6001, RAKNET_PORT, "\x09garbage", 8));
    DROPS(udp_to(CLIENT_IP, 7001, ICE_PORT, "\xffgarbage", 8));

    sleep_ms(1700);
    // the window is over: adopted flows stay, new unknown ones are dropped
    PASSES(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1238, TCP_ACK, NULL, 0));
    PASSES(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    DROPS(tcp_to(CLIENT_IP, 5002, JAVA_PORT, 1234, TCP_ACK, "data", 4));
    DROPS(udp_to(CLIENT_IP, 6002, RAKNET_PORT, data.b, data.n));
}

static void adopt_socket(struct minecraft_filter *s)
{
    s->rodata->ADOPT_MODE = 1;
    s->rodata->ADOPT_UNTIL_NS = monotonic_ns() + 30 * SEC;
}

// with ADOPT_MODE 1 only connections the kernel really has are adopted
static void test_adopt_socket(void)
{
    LOAD_OR_RETURN(adopt_socket);

    // a real connection over loopback, to the protected port
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    const int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in server = {.sin_family = AF_INET, .sin_port = htons(JAVA_PORT), .sin_addr = {htonl(INADDR_LOOPBACK)}};
    CHECK(bind(listener, (struct sockaddr *)&server, sizeof(server)) == 0);
    CHECK(listen(listener, 8) == 0);
    const int client = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(client, (struct sockaddr *)&server, sizeof(server)) == 0);
    const int accepted = accept(listener, NULL, NULL);
    CHECK(accepted >= 0);
    struct sockaddr_in local = {0};
    socklen_t local_len = sizeof(local);
    getsockname(client, (struct sockaddr *)&local, &local_len);
    const __u16 client_port = ntohs(local.sin_port);

    // a packet of exactly that connection
    struct frame f = tcp_to(INADDR_LOOPBACK, client_port, JAVA_PORT, 1, TCP_ACK, "data", 4);
    ((struct iphdr *)(f.b + sizeof(struct ethhdr)))->daddr = htonl(INADDR_LOOPBACK);
    PASSES(f);
    CHECK(stat(STAT_TCP_ADOPTED) == 1);

    // same addresses, but a port without a connection (only the listener matches)
    f = tcp_to(INADDR_LOOPBACK, (__u16)(client_port ^ 1), JAVA_PORT, 1, TCP_ACK, "data", 4);
    ((struct iphdr *)(f.b + sizeof(struct ethhdr)))->daddr = htonl(INADDR_LOOPBACK);
    DROPS(f);
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1, TCP_ACK, "data", 4));
    CHECK(stat(STAT_TCP_ADOPTED) == 1);

    close(accepted);
    close(client);
    close(listener);
}

static void with_ipv6(struct minecraft_filter *s)
{
    s->rodata->IPV6_PROTECT = 1;
}

static struct frame ipv6_frame(__u8 next_header, __u16 dst_port, int with_extension)
{
    struct frame f = {{0}, 0};
    struct ethhdr *eth = (struct ethhdr *)f.b;
    eth->h_proto = htons(ETH_P_IPV6);
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
    ip6->version = 6;
    ip6->hop_limit = 64;
    __u8 *cursor = (__u8 *)(ip6 + 1);
    if (with_extension)
    {
        ip6->nexthdr = IPPROTO_DSTOPTS;
        cursor[0] = next_header;
        cursor[1] = 1; // 16 bytes
        cursor += 16;
    }
    else
    {
        ip6->nexthdr = next_header;
    }
    cursor[2] = (__u8)(dst_port >> 8);
    cursor[3] = (__u8)dst_port;
    cursor += 20;
    ip6->payload_len = htons((__u16)(cursor - (__u8 *)(ip6 + 1)));
    f.n = (__u32)(cursor - f.b);
    return f;
}

static void test_ipv6(void)
{
    LOAD_OR_RETURN(with_ipv6);
    DROPS(ipv6_frame(IPPROTO_TCP, JAVA_PORT, 0));
    DROPS(ipv6_frame(IPPROTO_UDP, RAKNET_PORT, 0));
    DROPS(ipv6_frame(IPPROTO_UDP, ICE_PORT + 3, 0));
    DROPS(ipv6_frame(IPPROTO_TCP, JAVA_PORT, 1)); // hidden behind an extension header
    PASSES(ipv6_frame(IPPROTO_TCP, OTHER_PORT, 0));
    PASSES(ipv6_frame(IPPROTO_UDP, JAVA_PORT, 0)); // Java is TCP only
    PASSES(ipv6_frame(IPPROTO_ICMPV6, 0, 0));
    CHECK(stat(STAT_IPV6_DROPPED) == 4);

    // without the option IPv6 is none of the filter's business
    LOAD_OR_RETURN(NULL);
    PASSES(ipv6_frame(IPPROTO_TCP, JAVA_PORT, 0));
}

static void test_vlan(void)
{
    LOAD_OR_RETURN(NULL);
    // the same SYN / stray ACK, behind one and two VLAN tags
    for (__u32 tags = 1; tags <= 2; tags++)
    {
        for (int stray = 0; stray <= 1; stray++)
        {
            const struct frame plain = tcp_to(CLIENT_IP, (__u16)(5000 + tags), JAVA_PORT, 1000, stray ? TCP_ACK : TCP_SYN, NULL, 0);
            struct frame tagged = {{0}, plain.n + 4 * tags};
            memcpy(tagged.b, plain.b, 12);
            __u8 *cursor = tagged.b + 12;
            for (__u32 i = 0; i < tags; i++)
            {
                const __u16 tpid = htons(i == 0 && tags == 2 ? ETH_P_8021AD : ETH_P_8021Q);
                const __u16 tci = htons(100);
                memcpy(cursor, &tpid, 2);
                memcpy(cursor + 2, &tci, 2);
                cursor += 4;
            }
            memcpy(cursor, plain.b + 12, plain.n - 12);
            CHECK(run(tagged) == (stray ? XDP_DROP : XDP_PASS));
        }
    }
}

/* ------------------------------------------------------------------------
 * Benchmark (`kernel_test bench`): average cost of one packet on the paths
 * that matter during an attack, with everything switched on. The numbers
 * are pure program time on this cpu; a NIC driver adds its own share.
 * --------------------------------------------------------------------- */

static void bench_config(struct minecraft_filter *s)
{
    all_features(s);
    s->rodata->HAS_ALLOW = 0;
    s->rodata->HAS_DENY = 0;
    s->rodata->ADOPT_MODE = 0;
    s->rodata->CHALLENGE_MODE = 2;
    s->rodata->TCP_FLOW_PPS = 0;
    s->rodata->UDP_FLOW_PPS = 0;
    s->rodata->SYN_HITS = 10;
}

static void bench(const char *what, struct frame frame, int expected)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.b,
                .data_size_in = frame.n,
                .repeat = 2000000);
    if (bpf_prog_test_run_opts(bpf_program__fd(skel->progs.minecraft_filter), &opts))
    {
        printf("%-44s failed\n", what);
        return;
    }
    printf("%-44s %4u ns  %s%s\n", what, opts.duration, opts.retval == XDP_PASS ? "pass" : "drop",
           (int)opts.retval == expected ? "" : "  UNEXPECTED VERDICT");
}

static int run_bench(void)
{
    if (load(bench_config))
    {
        return 1;
    }
    const __u8 one = 1;
    const __u64 key = fnv1a64("mc.example.com");
    bpf_map__update_elem(skel->maps.allowed_hosts, &key, sizeof(key), &one, sizeof(one), BPF_ANY);

    // a logged in player and a connected Bedrock client; both ips are known
    // from an earlier visit, so they are not challenged
    const struct bytes ping = raknet_ping();
    const struct bytes ocr1 = raknet_ocr1(11, 1464);
    const struct bytes data = raknet_data();
    const struct bytes handshake = mc_handshake("mc.example.com", INTENT_LOGIN);
    run(tcp_to(CLIENT_IP, 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    sleep_ms(400);
    const __u32 seq = java_login(CLIENT_IP, 5000, 1000, 1);
    raknet_connect(CLIENT_IP, 6000);

    printf("%-44s %7s  verdict\n", "packet", "cost");
    bench("other port (not protected)", tcp_to(CLIENT_IP, 4000, OTHER_PORT, 1, TCP_ACK, "x", 1), XDP_PASS);
    bench("Java: packet of a verified player", tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, "data", 4), XDP_PASS);
    bench("Bedrock: datagram of a verified session", udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n), XDP_PASS);
    bench("ACK flood (unknown connection)", tcp_to(0x0B000001u, 5000, JAVA_PORT, 1, TCP_ACK, NULL, 0), XDP_DROP);
    bench("SYN flood, unknown ip (challenge)", tcp_to(0x0B000002u, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0), XDP_DROP);
    bench("SYN flood, known ip (per ip limit)", tcp_to(CLIENT_IP, 5001, JAVA_PORT, 1, TCP_SYN, NULL, 0), XDP_DROP);
    bench("handshake flood without tcp handshake", tcp_data(0x0B000003u, 5000, JAVA_PORT, 1, &handshake), XDP_DROP);
    bench("Bedrock: garbage datagram", udp_to(0x0B000004u, 6000, RAKNET_PORT, "\x09garbage", 8), XDP_DROP);
    bench("Bedrock: game data without session", udp_to(0x0B000005u, 6000, RAKNET_PORT, data.b, data.n), XDP_DROP);
    bench("Bedrock: ping flood, unknown ip (challenge)", udp_to(0x0B000006u, 6000, RAKNET_PORT, ping.b, ping.n), XDP_DROP);
    bench("Bedrock: ping flood, known ip (per ip limit)", udp_to(CLIENT_IP, 6001, RAKNET_PORT, ping.b, ping.n), XDP_DROP);
    bench("Bedrock: connection request flood, unknown ip", udp_to(0x0B000007u, 6000, RAKNET_PORT, ocr1.b, ocr1.n), XDP_DROP);
    unload();
    return 0;
}

int main(int argc, char **argv)
{
    // budgets and the challenge trigger are per cpu: stay on one
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(sched_getcpu(), &cpus);
    sched_setaffinity(0, sizeof(cpus), &cpus);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc > 1 && strcmp(argv[1], "bench") == 0)
    {
        return run_bench();
    }

    test_verifier_accepts_every_feature();
    test_unprotected_traffic_passes();
    test_java_login();
    test_java_login_in_one_segment();
    test_java_status();
    test_java_rejects_garbage();
    test_java_host_filter();
    test_java_protocol_range();
    test_per_ip_limits();
    test_challenge();
    test_challenge_arms_under_flood();
    test_budgets_and_good_ips();
    test_flow_rate_and_idle();
    test_guard();
    test_guard_tls_only();
    test_raknet();
    test_ice();
    test_lists();
    test_adopt_blind();
    test_adopt_socket();
    test_ipv6();
    test_vlan();
    unload();

    printf("%u checks, %u failed\n", checks_run, checks_failed);
    return checks_failed ? 1 : 0;
}
