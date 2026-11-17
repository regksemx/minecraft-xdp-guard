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
#define UDPGUARD_PORT 24500
#define VOICE_PORT 24454
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

    s->rodata->VOICE_START_PORT = VOICE_PORT;
    s->rodata->VOICE_END_PORT = VOICE_PORT;
    s->rodata->VOICE_PINGS = 1;

    s->rodata->UDPGUARD_START_PORT = UDPGUARD_PORT;
    s->rodata->UDPGUARD_END_PORT = UDPGUARD_PORT;
    s->rodata->UDPGUARD_FIRST_BYTE = 0xFF;
    s->rodata->UDPGUARD_MIN_LEN = 17;

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

// like run(), but also returns the frame the program left behind
static int run_out(struct frame frame, struct frame *out)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.b,
                .data_size_in = frame.n,
                .data_out = out->b,
                .data_size_out = sizeof(out->b),
                .repeat = 1);
    const int err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.minecraft_filter), &opts);
    if (err)
    {
        printf("FAIL: BPF_PROG_TEST_RUN: %s\n", strerror(-err));
        return -1;
    }
    out->n = opts.data_size_out;
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
    s->rodata->IPV6_MODE = 2;
    s->rodata->FLOW6_SEED = 0x0123456789ABCDEFULL;
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
    s->rodata->PONG_REPLY = 1;
    s->rodata->PONG_MAX_AGE_NS = 20 * SEC;
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

static void with_host_wildcards(struct minecraft_filter *s)
{
    s->rodata->HOST_FILTER = 1;
    s->rodata->HOST_WILDCARDS = 1;
}

static void test_java_host_wildcard(void)
{
    LOAD_OR_RETURN(with_host_wildcards);
    const __u8 one = 1;
    __u64 key = fnv1a64("*.example.su");
    CHECK(bpf_map__update_elem(skel->maps.allowed_hosts, &key, sizeof(key), &one, sizeof(one), BPF_ANY) == 0);
    key = fnv1a64("mc.example.net");
    CHECK(bpf_map__update_elem(skel->maps.allowed_hosts, &key, sizeof(key), &one, sizeof(one), BPF_ANY) == 0);

    java_host(5000, "maestro.example.su", 18, INTENT_LOGIN, XDP_PASS);
    java_host(5001, "MC.Example.SU", 13, INTENT_STATUS, XDP_PASS);
    java_host(5002, "go.example.su.", 14, INTENT_LOGIN, XDP_PASS);           // SRV target with root dot
    java_host(5003, "yt.example.su\0FML3\0", 19, INTENT_LOGIN, XDP_PASS);   // Forge marker
    java_host(5004, "mc.example.net", 14, INTENT_LOGIN, XDP_PASS);          // exact entries still work

    java_host(5010, "example.su", 10, INTENT_LOGIN, XDP_DROP);              // the apex is not covered
    java_host(5011, "a.b.example.su", 14, INTENT_LOGIN, XDP_DROP);          // one label only
    java_host(5012, "play.example.net", 16, INTENT_LOGIN, XDP_DROP);
    java_host(5013, "203.0.113.1", 12, INTENT_STATUS, XDP_DROP);           // a status flood aimed at the bare address
    java_host(5014, "localhost", 9, INTENT_LOGIN, XDP_DROP);
    CHECK(stat(STAT_JAVA_BAD_HOST) == 5);
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

static void with_pong_reply(struct minecraft_filter *s)
{
    s->rodata->PONG_REPLY = 1;
    s->rodata->PONG_MAX_AGE_NS = 1500 * MS;
    s->rodata->PING_HITS = 3;
}

struct pong_value
{
    __u64 updated;
    __u32 len;
    __u32 pad;
    __u8 data[512];
};

static __u16 checksum16(const __u8 *bytes, __u32 len)
{
    __u32 sum = 0;
    for (__u32 i = 0; i < len; i += 2)
    {
        sum += (__u32)bytes[i] << 8 | bytes[i + 1];
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (__u16)~sum;
}

static void test_pong_from_cache(void)
{
    LOAD_OR_RETURN(with_pong_reply);
    struct bytes ping = raknet_ping();
    memcpy(ping.b + 1, "\x01\x02\x03\x04\x05\x06\x07\x08", 8); // ping time
    struct frame in = udp_to(CLIENT_IP, 6000, RAKNET_PORT, ping.b, ping.n);
    memcpy(in.b, "\xaa\xaa\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb\xbb\xbb", 12); // dst mac, src mac
    struct frame out = {{0}, 0};

    // nothing cached yet: the server has to answer
    CHECK(run_out(in, &out) == XDP_PASS);
    CHECK(out.n == in.n && memcmp(out.b, in.b, in.n) == 0);

    // what the server answers: guid, magic, MOTD
    const char *motd = "MCPE;A Bedrock server;800;1.21.50;12;100;1234567890;world;Survival;1;19132;19133;";
    struct pong_value pong = {.updated = monotonic_ns(), .len = 8 + 16 + 2 + (__u32)strlen(motd)};
    memcpy(pong.data, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);
    memcpy(pong.data + 8, RAKNET_MAGIC, 16);
    pong.data[24] = (__u8)(strlen(motd) >> 8);
    pong.data[25] = (__u8)strlen(motd);
    memcpy(pong.data + 26, motd, strlen(motd));
    __u32 zero = 0;
    CHECK(bpf_map__update_elem(skel->maps.pong_cache, &zero, sizeof(zero), &pong, sizeof(pong), BPF_ANY) == 0);

    CHECK(run_out(in, &out) == XDP_TX);
    const __u32 headers = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    CHECK(out.n == headers + 9 + pong.len);
    const struct iphdr *ip = (const struct iphdr *)(out.b + sizeof(struct ethhdr));
    const struct udphdr *udp = (const struct udphdr *)(ip + 1);
    const __u8 *reply = (const __u8 *)(udp + 1);
    // addressed back to the client
    CHECK(memcmp(out.b, "\xbb\xbb\xbb\xbb\xbb\xbb\xaa\xaa\xaa\xaa\xaa\xaa", 12) == 0);
    CHECK(ntohl(ip->saddr) == SERVER_IP && ntohl(ip->daddr) == CLIENT_IP);
    CHECK(ntohs(udp->source) == RAKNET_PORT && ntohs(udp->dest) == 6000);
    // consistent lengths and a valid ip checksum
    CHECK(ntohs(ip->tot_len) == out.n - sizeof(struct ethhdr));
    CHECK(ntohs(udp->len) == out.n - sizeof(struct ethhdr) - sizeof(struct iphdr));
    CHECK(checksum16((const __u8 *)ip, sizeof(*ip)) == 0);
    CHECK(udp->check == 0);
    // the pong: id, the time of this ping, then the server's answer
    CHECK(reply[0] == 0x1c);
    CHECK(memcmp(reply + 1, "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0);
    CHECK(memcmp(reply + 9, pong.data, pong.len) == 0);
    CHECK(stat(STAT_RAKNET_PONG) == 1);

    // behind a VLAN tag the answer keeps the tag
    struct frame tagged = {{0}, in.n + 4};
    memcpy(tagged.b, in.b, 12);
    memcpy(tagged.b + 12, "\x81\x00\x00\x64", 4);
    memcpy(tagged.b + 16, in.b + 12, in.n - 12);
    CHECK(run_out(tagged, &out) == XDP_TX);
    CHECK(out.n == headers + 4 + 9 + pong.len);
    CHECK(memcmp(out.b + 12, "\x81\x00\x00\x64\x08\x00", 6) == 0);
    CHECK(out.b[headers + 4] == 0x1c);
    CHECK(memcmp(out.b + headers + 4 + 9, pong.data, pong.len) == 0);

    // the limits still come first: 3 pings per ip and window, all used
    CHECK(run_out(in, &out) == XDP_DROP);
    CHECK(stat(STAT_PING_THROTTLED) == 1);

    // a pong the loader stopped refreshing is not used anymore
    sleep_ms(1700);
    CHECK(run_out(in, &out) == XDP_PASS);
    CHECK(out.n == in.n && memcmp(out.b, in.b, in.n) == 0);

    // neither is one with a nonsense length
    pong.updated = monotonic_ns();
    pong.len = 513;
    CHECK(bpf_map__update_elem(skel->maps.pong_cache, &zero, sizeof(zero), &pong, sizeof(pong), BPF_ANY) == 0);
    CHECK(run_out(in, &out) == XDP_PASS);
    pong.len = 10;
    CHECK(bpf_map__update_elem(skel->maps.pong_cache, &zero, sizeof(zero), &pong, sizeof(pong), BPF_ANY) == 0);
    CHECK(run_out(udp_to(CLIENT_IP + 1, 6000, RAKNET_PORT, ping.b, ping.n), &out) == XDP_PASS);
    CHECK(stat(STAT_RAKNET_PONG) == 2);

    // the largest pong that fits the cache
    pong.len = 512;
    memset(pong.data + 26, 'x', 512 - 26);
    CHECK(bpf_map__update_elem(skel->maps.pong_cache, &zero, sizeof(zero), &pong, sizeof(pong), BPF_ANY) == 0);
    CHECK(run_out(udp_to(CLIENT_IP + 2, 6000, RAKNET_PORT, ping.b, ping.n), &out) == XDP_TX);
    CHECK(out.n == headers + 9 + 512);
    CHECK(out.b[out.n - 1] == 'x');
}

static void udp_guard_limits(struct minecraft_filter *s)
{
    s->rodata->UDP_OPEN_HITS = 2;
    s->rodata->UDP_FLOW_PPS = 4;
}

static void udp_guard_any_byte(struct minecraft_filter *s)
{
    s->rodata->UDPGUARD_FIRST_BYTE = 256;
}

static void test_udp_guard(void)
{
    LOAD_OR_RETURN(udp_guard_limits);
    __u8 voice[40];
    memset(voice, 0x11, sizeof(voice));
    voice[0] = 0xFF;

    // the first acceptable datagram opens the session
    PASSES(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, voice, sizeof(voice)));
    CHECK(stat(STAT_UDPGUARD_VERIFIED) == 1);
    PASSES(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, voice, 17));
    // wrong first byte or too short: dropped even inside a session
    DROPS(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, voice, 16));
    DROPS(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, "\x01 raknet ping or whatever", 27));
    DROPS(udp_to(CLIENT_IP, 8001, UDPGUARD_PORT, "\x16 dtls or whatever......", 27));
    CHECK(stat(STAT_UDPGUARD_INVALID) == 3);

    // packet rate of one session: 4 per second, 2 are used
    PASSES(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, voice, sizeof(voice)));
    PASSES(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, voice, sizeof(voice)));
    DROPS(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, voice, sizeof(voice)));
    CHECK(stat(STAT_UDP_RATE_LIMITED) == 1);

    // new sessions per ip: 2 per window, one is used
    PASSES(udp_to(CLIENT_IP, 8001, UDPGUARD_PORT, voice, sizeof(voice)));
    DROPS(udp_to(CLIENT_IP, 8002, UDPGUARD_PORT, voice, sizeof(voice)));
    CHECK(stat(STAT_UDP_OPEN_THROTTLED) == 1);
    PASSES(udp_to(CLIENT_IP + 1, 8002, UDPGUARD_PORT, voice, sizeof(voice)));

    // without a fixed first byte only the size counts
    LOAD_OR_RETURN(udp_guard_any_byte);
    PASSES(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, "any first byte will do here", 27));
    DROPS(udp_to(CLIENT_IP, 8001, UDPGUARD_PORT, "too short", 9));

    // unknown ips are challenged like everywhere else
    LOAD_OR_RETURN(with_challenge_always);
    DROPS(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, voice, sizeof(voice)));
    sleep_ms(400);
    PASSES(udp_to(CLIENT_IP, 8000, UDPGUARD_PORT, voice, 30)); // any later datagram of the socket
    PASSES(udp_to(CLIENT_IP, 8001, UDPGUARD_PORT, voice, sizeof(voice)));
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
    const __u64 forever = 0;
    struct lpm_key key = {24, htonl(0xCB007100u)}; // 203.0.113.0/24
    CHECK(bpf_map__update_elem(skel->maps.deny_v4, &key, sizeof(key), &forever, sizeof(forever), BPF_ANY) == 0);
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

    // bans added while running: without an end, with one, and expired
    const __u64 runtime = 1;
    const __u64 soon = monotonic_ns() + 700 * MS;
    const __u64 past = monotonic_ns() - 1 * SEC;
    key = (struct lpm_key){32, htonl(CLIENT_IP + 1)};
    CHECK(bpf_map__update_elem(skel->maps.deny_v4, &key, sizeof(key), &runtime, sizeof(runtime), BPF_ANY) == 0);
    key = (struct lpm_key){32, htonl(CLIENT_IP + 2)};
    CHECK(bpf_map__update_elem(skel->maps.deny_v4, &key, sizeof(key), &soon, sizeof(soon), BPF_ANY) == 0);
    key = (struct lpm_key){32, htonl(CLIENT_IP + 3)};
    CHECK(bpf_map__update_elem(skel->maps.deny_v4, &key, sizeof(key), &past, sizeof(past), BPF_ANY) == 0);
    DROPS(tcp_to(CLIENT_IP + 1, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    DROPS(tcp_to(CLIENT_IP + 2, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    PASSES(tcp_to(CLIENT_IP + 3, 5000, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    sleep_ms(900);
    DROPS(tcp_to(CLIENT_IP + 1, 5001, JAVA_PORT, 1, TCP_SYN, NULL, 0));
    PASSES(tcp_to(CLIENT_IP + 2, 5001, JAVA_PORT, 1, TCP_SYN, NULL, 0)); // the ban is over
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
    s->rodata->IPV6_MODE = 1; // drop
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

/* ------------------------------------------------------------------------
 * IPv6 inspection
 * --------------------------------------------------------------------- */

struct addr6
{
    __u8 b[16];
};

// fd00:<prefix>::<host>
static struct addr6 addr6(__u16 prefix, __u32 host)
{
    struct addr6 a = {{0xfd, 0x00, (__u8)(prefix >> 8), (__u8)prefix}};
    a.b[12] = (__u8)(host >> 24);
    a.b[13] = (__u8)(host >> 16);
    a.b[14] = (__u8)(host >> 8);
    a.b[15] = (__u8)host;
    return a;
}

#define SERVER6 addr6(0, 1)
#define CLIENT6 addr6(0x100, 1)

// rewraps the transport part of an IPv4 frame into IPv6, behind
// `extensions` destination option headers (8 bytes each)
static struct frame to_v6_between(struct frame v4, struct addr6 src, struct addr6 dst, int extensions)
{
    const __u32 l4_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
    const __u32 l4_len = v4.n - l4_offset;
    const __u8 protocol = ((const struct iphdr *)(v4.b + sizeof(struct ethhdr)))->protocol;

    struct frame f = {{0}, 0};
    struct ethhdr *eth = (struct ethhdr *)f.b;
    eth->h_proto = htons(ETH_P_IPV6);
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
    ip6->version = 6;
    ip6->hop_limit = 64;
    memcpy(&ip6->saddr, src.b, 16);
    memcpy(&ip6->daddr, dst.b, 16);
    ip6->payload_len = htons((__u16)(extensions * 8 + l4_len));
    ip6->nexthdr = extensions ? IPPROTO_DSTOPTS : protocol;
    __u8 *cursor = (__u8 *)(ip6 + 1);
    for (int i = 0; i < extensions; i++)
    {
        cursor[0] = i == extensions - 1 ? protocol : IPPROTO_DSTOPTS;
        cursor[1] = 0; // 8 bytes
        cursor += 8;
    }
    memcpy(cursor, v4.b + l4_offset, l4_len);
    f.n = (__u32)(cursor - f.b) + l4_len;
    return f;
}

static struct frame to_v6(struct frame v4, struct addr6 src)
{
    return to_v6_between(v4, src, SERVER6, 0);
}

static struct frame tcp6(struct addr6 src, __u16 src_port, __u16 dst_port, __u32 seq, __u8 flags, const void *payload, __u32 len)
{
    return to_v6(tcp_to(0, src_port, dst_port, seq, flags, payload, len), src);
}

static struct frame udp6(struct addr6 src, __u16 src_port, __u16 dst_port, const void *payload, __u32 len)
{
    return to_v6(udp_to(0, src_port, dst_port, payload, len), src);
}

static void test_ipv6_drop_mode_chains(void)
{
    LOAD_OR_RETURN(with_ipv6);
    const struct frame syn = tcp_to(0, 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0);
    DROPS(to_v6_between(syn, CLIENT6, SERVER6, 0));
    DROPS(to_v6_between(syn, CLIENT6, SERVER6, 4));
    // hidden behind more extension headers than the filter walks
    DROPS(to_v6_between(syn, CLIENT6, SERVER6, 5));
    PASSES(to_v6_between(tcp_to(0, 5000, OTHER_PORT, 1000, TCP_SYN, NULL, 0), CLIENT6, SERVER6, 4));
}

static void with_ipv6_inspect(struct minecraft_filter *s)
{
    s->rodata->IPV6_MODE = 2;
    s->rodata->FLOW6_SEED = 0x0123456789ABCDEFULL;
}

static void test_ipv6_inspect(void)
{
    LOAD_OR_RETURN(with_ipv6_inspect);
    const struct bytes handshake = mc_handshake("mc.example.com", INTENT_LOGIN);
    const struct bytes login = mc_login("Steve");
    const struct bytes ocr1 = raknet_ocr1(11, 1464);
    const struct bytes ocr2 = raknet_ocr2();
    const struct bytes data = raknet_data();
    const struct bytes ping = raknet_ping();
    const struct bytes stun = stun_binding(72);
    const struct bytes dtls = dtls_record();

    // Java: the same sequence as over IPv4
    PASSES(tcp6(CLIENT6, 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    DROPS(tcp6(CLIENT6, 5000, JAVA_PORT, 1001, TCP_ACK, NULL, 0));
    PASSES(tcp6(CLIENT6, 5000, JAVA_PORT, 1001, TCP_ACK | TCP_PSH, handshake.b, handshake.n));
    PASSES(tcp6(CLIENT6, 5000, JAVA_PORT, 1001 + handshake.n, TCP_ACK | TCP_PSH, login.b, login.n));
    CHECK(stat(STAT_JAVA_VERIFIED) == 1);
    PASSES(tcp6(CLIENT6, 5000, JAVA_PORT, 5555, TCP_ACK, "anything", 8));

    // every other flow is unknown: another port, another host, another network
    DROPS(tcp6(CLIENT6, 5001, JAVA_PORT, 5555, TCP_ACK, "anything", 8));
    DROPS(tcp6(addr6(0x100, 2), 5000, JAVA_PORT, 5555, TCP_ACK, "anything", 8));
    DROPS(tcp6(addr6(0x101, 1), 5000, JAVA_PORT, 5555, TCP_ACK, "anything", 8));
    CHECK(stat(STAT_TCP_UNTRACKED) == 3);
    // garbage instead of a handshake
    PASSES(tcp6(CLIENT6, 5002, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    DROPS(tcp6(CLIENT6, 5002, JAVA_PORT, 1001, TCP_ACK | TCP_PSH, "GET / HTTP/1.1", 14));
    DROPS(tcp6(CLIENT6, 5003, JAVA_PORT, 1000, TCP_SYN, "x", 1));
    // payload length lying about the packet
    struct frame lying = tcp6(CLIENT6, 5004, JAVA_PORT, 1000, TCP_SYN, NULL, 0);
    ((struct ipv6hdr *)(lying.b + sizeof(struct ethhdr)))->payload_len = htons(4);
    DROPS(lying);

    // Bedrock, NetherNet, the generic guards
    DROPS(udp6(CLIENT6, 6000, RAKNET_PORT, data.b, data.n));
    PASSES(udp6(CLIENT6, 6000, RAKNET_PORT, ping.b, ping.n));
    PASSES(udp6(CLIENT6, 6000, RAKNET_PORT, ocr1.b, ocr1.n));
    PASSES(udp6(CLIENT6, 6000, RAKNET_PORT, ocr2.b, ocr2.n));
    PASSES(udp6(CLIENT6, 6000, RAKNET_PORT, data.b, data.n));
    DROPS(udp6(CLIENT6, 6001, RAKNET_PORT, data.b, data.n));
    PASSES(udp6(CLIENT6, 7000, ICE_PORT, stun.b, stun.n));
    PASSES(udp6(CLIENT6, 7000, ICE_PORT, dtls.b, dtls.n));
    DROPS(udp6(CLIENT6, 7001, ICE_PORT, dtls.b, dtls.n));
    __u8 voice[20] = {0xFF};
    PASSES(udp6(CLIENT6, 8000, UDPGUARD_PORT, voice, sizeof(voice)));
    DROPS(udp6(CLIENT6, 8000, UDPGUARD_PORT, "\x01 not a voice packet", 21));
    tcp_handshake(CLIENT_IP, 5000, GUARD_PORT, 1000); // (IPv4, for comparison)
    PASSES(tcp6(CLIENT6, 5005, GUARD_PORT, 1000, TCP_SYN, NULL, 0));
    PASSES(tcp6(CLIENT6, 5005, GUARD_PORT, 1001, TCP_ACK | TCP_PSH, "GET /v1/join HTTP/1.1", 21));
    CHECK(stat(STAT_GUARD_VERIFIED) == 1);

    // other ports and protocols are none of the filter's business
    PASSES(tcp6(CLIENT6, 5000, OTHER_PORT, 1, TCP_ACK, "x", 1));
    PASSES(ipv6_frame(IPPROTO_ICMPV6, 0, 0));

    // extension headers do not hide the flow: same connection with or without
    const struct frame syn = tcp_to(0, 5006, JAVA_PORT, 1000, TCP_SYN, NULL, 0);
    const struct frame hs = tcp_to(0, 5006, JAVA_PORT, 1001, TCP_ACK | TCP_PSH, handshake.b, handshake.n);
    PASSES(to_v6_between(syn, CLIENT6, SERVER6, 2));
    DROPS(to_v6_between(tcp_to(0, 5006, JAVA_PORT, 1001, TCP_ACK, NULL, 0), CLIENT6, SERVER6, 1));
    PASSES(to_v6_between(hs, CLIENT6, SERVER6, 4));
    // more headers than anybody sends: dropped unseen
    DROPS(to_v6_between(syn, CLIENT6, SERVER6, 5));
    DROPS(to_v6_between(tcp_to(0, 5006, OTHER_PORT, 1000, TCP_SYN, NULL, 0), CLIENT6, SERVER6, 5));

    // first fragment for a protected port
    struct frame fragment = to_v6_between(syn, addr6(0x100, 9), SERVER6, 1);
    __u8 *header = fragment.b + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    ((struct ipv6hdr *)(fragment.b + sizeof(struct ethhdr)))->nexthdr = IPPROTO_FRAGMENT;
    header[3] = 0x01; // offset 0, more fragments
    DROPS(fragment);
    CHECK(stat(STAT_FRAGMENT_DROPPED) == 1);
    header[2] = 0x01; // not the first one: no ports to look at
    PASSES(fragment);

    // IPv4 keeps working next to it
    java_login(CLIENT_IP, 5007, 1000, 1);
}

static void ipv6_limits(struct minecraft_filter *s)
{
    with_ipv6_inspect(s);
    s->rodata->SYN_HITS = 3;
    s->rodata->HAS_ALLOW = 1;
    s->rodata->HAS_DENY = 1;
}

struct lpm_key6
{
    __u32 prefixlen;
    __u8 addr[16];
};

static void test_ipv6_limits_and_lists(void)
{
    LOAD_OR_RETURN(ipv6_limits);

    // the limits count per /64: three hosts of one network use it up ...
    for (__u32 host = 1; host <= 3; host++)
    {
        PASSES(tcp6(addr6(0x200, host), 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    }
    DROPS(tcp6(addr6(0x200, 4), 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    CHECK(stat(STAT_SYN_THROTTLED) == 1);
    CHECK(stat(STAT_NEW_IP) == 1);
    // ... which does not bother the network next door
    PASSES(tcp6(addr6(0x201, 4), 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));

    // deny: a whole /48, and a single address with a ban that is over
    const __u64 forever = 0;
    const __u64 past = monotonic_ns() - 1 * SEC;
    struct lpm_key6 key = {48, {0xfd, 0x00, 0x03, 0x00}};
    CHECK(bpf_map__update_elem(skel->maps.deny_v6, &key, sizeof(key), &forever, sizeof(forever), BPF_ANY) == 0);
    key.prefixlen = 128;
    memcpy(key.addr, addr6(0x400, 7).b, 16);
    CHECK(bpf_map__update_elem(skel->maps.deny_v6, &key, sizeof(key), &past, sizeof(past), BPF_ANY) == 0);
    DROPS(tcp6(addr6(0x300, 1), 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    DROPS(udp6(addr6(0x300, 2), 6000, RAKNET_PORT, "\x01", 1));
    PASSES(tcp6(addr6(0x300, 1), 5000, OTHER_PORT, 1000, TCP_SYN, NULL, 0));
    PASSES(tcp6(addr6(0x400, 7), 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    CHECK(stat(STAT_DENYLIST) == 2);

    // allow: no inspection at all
    const __u8 one = 1;
    memcpy(key.addr, addr6(0x500, 1).b, 16);
    CHECK(bpf_map__update_elem(skel->maps.allow_v6, &key, sizeof(key), &one, sizeof(one), BPF_ANY) == 0);
    PASSES(tcp6(addr6(0x500, 1), 5000, JAVA_PORT, 2, TCP_ACK, "whatever", 8));
    PASSES(udp6(addr6(0x500, 1), 6000, RAKNET_PORT, "whatever", 8));
    DROPS(tcp6(addr6(0x500, 2), 5000, JAVA_PORT, 2, TCP_ACK, "whatever", 8));
}

// a ban reaches connections that are already verified within a second
static void test_ban_cuts_open_flows(void)
{
    LOAD_OR_RETURN(ipv6_limits);
    const struct bytes handshake = mc_handshake("h", INTENT_LOGIN);
    const struct bytes login = mc_login("Steve");
    const struct bytes data = raknet_data();
    const struct addr6 player6 = addr6(0x600, 1);

    const __u32 seq = java_login(CLIENT_IP, 5000, 1000, 1);
    raknet_connect(CLIENT_IP, 6000);
    PASSES(tcp6(player6, 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));
    PASSES(tcp6(player6, 5000, JAVA_PORT, 1001, TCP_ACK | TCP_PSH, handshake.b, handshake.n));
    PASSES(tcp6(player6, 5000, JAVA_PORT, 1001 + handshake.n, TCP_ACK | TCP_PSH, login.b, login.n));

    const __u64 runtime = 1;
    struct lpm_key key4 = {32, htonl(CLIENT_IP)};
    CHECK(bpf_map__update_elem(skel->maps.deny_v4, &key4, sizeof(key4), &runtime, sizeof(runtime), BPF_ANY) == 0);
    struct lpm_key6 key6 = {64, {0xfd, 0x00, 0x06, 0x00}};
    CHECK(bpf_map__update_elem(skel->maps.deny_v6, &key6, sizeof(key6), &runtime, sizeof(runtime), BPF_ANY) == 0);

    sleep_ms(1100);
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
    DROPS(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    DROPS(tcp6(player6, 5000, JAVA_PORT, 5555, TCP_ACK, NULL, 0));
    // and stay cut after the ban is lifted: the connection is forgotten
    CHECK(bpf_map__delete_elem(skel->maps.deny_v4, &key4, sizeof(key4), 0) == 0);
    DROPS(tcp_to(CLIENT_IP, 5000, JAVA_PORT, seq, TCP_ACK, NULL, 0));
    DROPS(udp_to(CLIENT_IP, 6000, RAKNET_PORT, data.b, data.n));
    java_login(CLIENT_IP, 5001, 1000, 1);
}

static void ipv6_challenge(struct minecraft_filter *s)
{
    with_ipv6_inspect(s);
    s->rodata->CHALLENGE_MODE = 2;
    s->rodata->PONG_REPLY = 1;
    s->rodata->PONG_MAX_AGE_NS = 60 * SEC;
}

static void test_ipv6_challenge(void)
{
    LOAD_OR_RETURN(ipv6_challenge);
    const struct bytes ping = raknet_ping();
    const struct frame syn = tcp6(CLIENT6, 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0);

    DROPS(syn);
    DROPS(udp6(addr6(0x101, 1), 6000, RAKNET_PORT, ping.b, ping.n));
    sleep_ms(400);
    PASSES(syn);
    // the whole /64 is known now
    PASSES(tcp6(addr6(0x100, 77), 5000, JAVA_PORT, 1000, TCP_SYN, NULL, 0));

    // pings are answered from the cache over IPv4 only; over IPv6 the
    // server answers
    struct pong_value pong = {.updated = monotonic_ns(), .len = 8 + 16 + 2 + 5};
    memcpy(pong.data + 8, RAKNET_MAGIC, 16);
    memcpy(pong.data + 24, "\x00\x05MCPE;", 7);
    __u32 zero = 0;
    CHECK(bpf_map__update_elem(skel->maps.pong_cache, &zero, sizeof(zero), &pong, sizeof(pong), BPF_ANY) == 0);
    struct frame out = {{0}, 0};
    const struct frame ping6 = udp6(addr6(0x101, 1), 6000, RAKNET_PORT, ping.b, ping.n);
    CHECK(run_out(ping6, &out) == XDP_PASS);
    CHECK(out.n == ping6.n && memcmp(out.b, ping6.b, ping6.n) == 0);
}

static void ipv6_adopt(struct minecraft_filter *s)
{
    with_ipv6_inspect(s);
    s->rodata->ADOPT_MODE = 1;
    s->rodata->ADOPT_UNTIL_NS = monotonic_ns() + 30 * SEC;
}

static void test_ipv6_adopt_socket(void)
{
    LOAD_OR_RETURN(ipv6_adopt);

    // a real connection over the IPv6 loopback, to the protected port
    const int listener = socket(AF_INET6, SOCK_STREAM, 0);
    const int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in6 server = {.sin6_family = AF_INET6, .sin6_port = htons(JAVA_PORT), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    if (bind(listener, (struct sockaddr *)&server, sizeof(server)) != 0)
    {
        printf("note: no IPv6 loopback here, skipping the IPv6 adoption test\n");
        close(listener);
        return;
    }
    CHECK(listen(listener, 8) == 0);
    const int client = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(connect(client, (struct sockaddr *)&server, sizeof(server)) == 0);
    const int accepted = accept(listener, NULL, NULL);
    struct sockaddr_in6 local = {0};
    socklen_t local_len = sizeof(local);
    getsockname(client, (struct sockaddr *)&local, &local_len);
    const __u16 client_port = ntohs(local.sin6_port);

    struct addr6 loopback = {{0}};
    loopback.b[15] = 1;
    PASSES(to_v6_between(tcp_to(0, client_port, JAVA_PORT, 1, TCP_ACK, "data", 4), loopback, loopback, 0));
    CHECK(stat(STAT_TCP_ADOPTED) == 1);
    DROPS(to_v6_between(tcp_to(0, (__u16)(client_port ^ 1), JAVA_PORT, 1, TCP_ACK, "data", 4), loopback, loopback, 0));
    DROPS(tcp6(CLIENT6, 5000, JAVA_PORT, 1, TCP_ACK, "data", 4));
    CHECK(stat(STAT_TCP_ADOPTED) == 1);

    close(accepted);
    close(client);
    close(listener);
}

// a Simple Voice Chat datagram: magic, connection id, payload length, payload
static struct bytes voice_packet(__u8 connection, __u32 payload_len)
{
    struct bytes pkt = {{0xFF}, 1};
    for (int i = 0; i < 16; i++)
    {
        put_u8(&pkt, connection);
    }
    put_varint(&pkt, (__s32)payload_len);
    for (__u32 i = 0; i < payload_len; i++)
    {
        put_u8(&pkt, (__u8)(i * 7 + connection)); // stands in for ciphertext
    }
    return pkt;
}

#define VOICE_AUTH 29 // IV, packet type, tag: authenticate and keep-alive
#define VOICE_MIC 120 // a typical frame of audio

static struct bytes voice_ping(void)
{
    struct bytes pkt = {{0xFF, 0x58, 0xbc, 0x9a, 0xe9, 0xc7, 0xa8, 0x45, 0xe4,
                         0xa1, 0x1c, 0xef, 0xbb, 0x67, 0x19, 0x94, 0x25, 24}, 18};
    pkt.n += 24; // ping id and timestamp
    return pkt;
}

static void voice_limits(struct minecraft_filter *s)
{
    s->rodata->UDP_OPEN_HITS = 3;
    s->rodata->PING_HITS = 2;
    s->rodata->VOICE_FLOW_PPS = 6;
}

static void test_voice(void)
{
    LOAD_OR_RETURN(voice_limits);
    const struct bytes auth = voice_packet(0xA1, VOICE_AUTH);
    const struct bytes mic = voice_packet(0xA1, VOICE_MIC);
    const struct bytes large = voice_packet(0xA1, 1315); // the largest audio frame, two length bytes

    // the first well-formed packet opens the session
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, auth.b, auth.n));
    CHECK(stat(STAT_VOICE_VERIFIED) == 1);
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, mic.b, mic.n));
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, large.b, large.n));

    // not voice chat: wrong magic, a length that does not match the
    // datagram, a payload too short to be encrypted, trailing bytes
    struct bytes bad = voice_packet(0xA1, VOICE_MIC);
    bad.b[0] = 0xFE;
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, bad.b, bad.n));
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, mic.b, mic.n - 1));
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, mic.b, mic.n + 1));
    bad = voice_packet(0xA1, 28);
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, bad.b, bad.n));
    bad = raknet_ping();
    DROPS(udp_to(CLIENT_IP, 8001, VOICE_PORT, bad.b, bad.n));
    DROPS(udp_to(CLIENT_IP, 8001, VOICE_PORT, "\xff", 1));
    CHECK(stat(STAT_VOICE_INVALID) == 6);
    CHECK(stat(STAT_VOICE_VERIFIED) == 1);

    // packet rate of one session: 6 per second, 3 are used
    for (int i = 0; i < 3; i++)
    {
        PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, mic.b, mic.n));
    }
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, mic.b, mic.n));
    CHECK(stat(STAT_UDP_RATE_LIMITED) == 1);

    // a session is bound to its connection id: every other id from the
    // same address has to open a session of its own, 3 per ip and window
    sleep_ms(1100);
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, mic.b, mic.n));
    const struct bytes other = voice_packet(0xB2, VOICE_MIC);
    const struct bytes third = voice_packet(0xC3, VOICE_MIC);
    const struct bytes fourth = voice_packet(0xD4, VOICE_MIC);
    const struct bytes fifth = voice_packet(0xE5, VOICE_MIC);
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, other.b, other.n));
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, other.b, other.n));
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, third.b, third.n));
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, fourth.b, fourth.n));
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, fifth.b, fifth.n));
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, mic.b, mic.n)); // the first id lost the address
    CHECK(stat(STAT_VOICE_VERIFIED) == 4);
    CHECK(stat(STAT_UDP_OPEN_THROTTLED) == 2);
    PASSES(udp_to(CLIENT_IP + 1, 8000, VOICE_PORT, fifth.b, fifth.n)); // other ips are not affected

    // the ping of external tools: no session, limited per ip
    const struct bytes ping = voice_ping();
    PASSES(udp_to(CLIENT_IP + 2, 8000, VOICE_PORT, ping.b, ping.n));
    PASSES(udp_to(CLIENT_IP + 2, 8000, VOICE_PORT, ping.b, ping.n));
    DROPS(udp_to(CLIENT_IP + 2, 8000, VOICE_PORT, ping.b, ping.n));
    CHECK(stat(STAT_VOICE_PING) == 2);
    CHECK(stat(STAT_PING_THROTTLED) == 1);
    CHECK(stat(STAT_VOICE_VERIFIED) == 5); // a ping opens nothing
    // the ping id with any other length is nothing the server would answer
    struct bytes long_ping = voice_ping();
    long_ping.b[17] = 29;
    long_ping.n += 5;
    DROPS(udp_to(CLIENT_IP + 3, 8000, VOICE_PORT, long_ping.b, long_ping.n));

    // over IPv6 and behind the challenge like everything else
    LOAD_OR_RETURN(ipv6_challenge);
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, auth.b, auth.n));
    DROPS(udp6(CLIENT6, 8000, VOICE_PORT, auth.b, auth.n));
    sleep_ms(400);
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, auth.b, auth.n)); // the client repeats its authentication
    PASSES(udp6(CLIENT6, 8000, VOICE_PORT, auth.b, auth.n));
    PASSES(udp6(CLIENT6, 8000, VOICE_PORT, mic.b, mic.n));
    DROPS(udp6(CLIENT6, 8000, VOICE_PORT, mic.b, mic.n - 1));
}

static void voice_without_pings(struct minecraft_filter *s)
{
    s->rodata->VOICE_PINGS = 0;
}

static void test_voice_without_pings(void)
{
    LOAD_OR_RETURN(voice_without_pings);
    const struct bytes ping = voice_ping();
    const struct bytes auth = voice_packet(0xA1, VOICE_AUTH);
    DROPS(udp_to(CLIENT_IP, 8000, VOICE_PORT, ping.b, ping.n));
    PASSES(udp_to(CLIENT_IP, 8000, VOICE_PORT, auth.b, auth.n));
    CHECK(stat(STAT_VOICE_INVALID) == 1);
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
    test_java_host_wildcard();
    test_java_protocol_range();
    test_per_ip_limits();
    test_challenge();
    test_challenge_arms_under_flood();
    test_budgets_and_good_ips();
    test_flow_rate_and_idle();
    test_guard();
    test_guard_tls_only();
    test_raknet();
    test_pong_from_cache();
    test_ice();
    test_udp_guard();
    test_lists();
    test_adopt_blind();
    test_adopt_socket();
    test_ipv6();
    test_ipv6_drop_mode_chains();
    test_ipv6_inspect();
    test_ipv6_limits_and_lists();
    test_ban_cuts_open_flows();
    test_ipv6_challenge();
    test_ipv6_adopt_socket();
    test_voice();
    test_voice_without_pings();
    test_vlan();
    unload();

    printf("%u checks, %u failed\n", checks_run, checks_failed);
    return checks_failed ? 1 : 0;
}
