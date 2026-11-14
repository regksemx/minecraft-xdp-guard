/*
 * Packet flood generator for dev/e2e/load.py: sends hand-built frames with
 * random (spoofed) source addresses through an AF_PACKET socket, as fast as
 * the interface takes them. Only meant for the veth pair of the test setup.
 *
 *   flood <interface> <dst mac> <dst ip> <kind> <seconds> <threads> [pps]
 *
 * pps is the total rate over all threads; without it the flood runs as fast
 * as it can.
 *
 * kinds: syn, ack, handshake, ping, ocr1, junk, stun, replay (every SYN is
 * sent twice, 300ms apart, like a flood that knows about the challenge)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64
#define REPLAY_ROUND 2048

static const uint8_t RAKNET_MAGIC[16] = {0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
                                         0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78};

static int ifindex;
static uint8_t dst_mac[6];
static uint32_t dst_ip;
static const char *kind;
static double deadline;
static double thread_pps; // per thread, 0 = unlimited
static unsigned long long sent_total;
static pthread_mutex_t total_lock = PTHREAD_MUTEX_INITIALIZER;

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint64_t next_random(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *state = x;
}

static uint16_t ip_checksum(const struct iphdr *ip)
{
    const uint16_t *words = (const uint16_t *)ip;
    uint32_t sum = 0;
    for (int i = 0; i < 10; i++)
    {
        sum += words[i];
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

// builds one frame of the configured kind; returns its length
static size_t build(uint8_t *frame, uint64_t *rng)
{
    const uint64_t r = next_random(rng);
    const int tcp = !strcmp(kind, "syn") || !strcmp(kind, "ack") || !strcmp(kind, "handshake") || !strcmp(kind, "replay");
    uint8_t payload[1500];
    size_t payload_len = 0;
    uint16_t dport = tcp ? 25565 : 19132;
    uint8_t flags = 0x02; // SYN

    if (!strcmp(kind, "ack"))
    {
        flags = 0x10;
    }
    else if (!strcmp(kind, "handshake"))
    {
        // length, id, protocol 767, host "mc.e2e.test", port 25565, login
        static const uint8_t handshake[] = {0x12, 0x00, 0xff, 0x05, 0x0b, 'm', 'c', '.', 'e', '2', 'e', '.',
                                            't', 'e', 's', 't', 0x63, 0xdd, 0x02};
        memcpy(payload, handshake, sizeof(handshake));
        payload_len = sizeof(handshake);
        flags = 0x18;
    }
    else if (!strcmp(kind, "ping"))
    {
        payload[0] = 0x01;
        memset(payload + 1, 0, 8);
        memcpy(payload + 9, RAKNET_MAGIC, 16);
        memset(payload + 25, 0xab, 8);
        payload_len = 33;
    }
    else if (!strcmp(kind, "ocr1"))
    {
        memset(payload, 0, 1464);
        payload[0] = 0x05;
        memcpy(payload + 1, RAKNET_MAGIC, 16);
        payload[17] = 11;
        payload_len = 1464;
    }
    else if (!strcmp(kind, "junk"))
    {
        for (int i = 0; i < 32; i++)
        {
            payload[i] = (uint8_t)(r >> (i % 8 * 8)) ^ (uint8_t)i;
        }
        payload_len = 32;
    }
    else if (!strcmp(kind, "stun"))
    {
        static const uint8_t stun[] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42};
        memset(payload, 0, 20);
        memcpy(payload, stun, sizeof(stun));
        payload_len = 20;
        dport = 27020;
    }

    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest, dst_mac, 6);
    memset(eth->h_source, 0x02, 6);
    eth->h_proto = htons(ETH_P_IP);

    const size_t l4_len = (tcp ? sizeof(struct tcphdr) : sizeof(struct udphdr)) + payload_len;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    memset(ip, 0, sizeof(*ip));
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    ip->tot_len = htons((uint16_t)(sizeof(*ip) + l4_len));
    ip->saddr = htonl(0x0B000000u | (uint32_t)(r & 0xFFFFFF)); // 11.0.0.0/8, never a real client
    ip->daddr = dst_ip;
    ip->check = ip_checksum(ip);

    const uint16_t sport = (uint16_t)(1024 + ((r >> 24) % 60000));
    if (tcp)
    {
        struct tcphdr *th = (struct tcphdr *)(ip + 1);
        memset(th, 0, sizeof(*th));
        th->source = htons(sport);
        th->dest = htons(dport);
        th->seq = (uint32_t)(r >> 32);
        th->doff = 5;
        ((uint8_t *)th)[13] = flags;
        th->window = htons(64240);
        memcpy(th + 1, payload, payload_len);
    }
    else
    {
        struct udphdr *uh = (struct udphdr *)(ip + 1);
        uh->source = htons(sport);
        uh->dest = htons(dport);
        uh->len = htons((uint16_t)l4_len);
        uh->check = 0;
        memcpy(uh + 1, payload, payload_len);
    }
    return sizeof(*eth) + sizeof(*ip) + l4_len;
}

static void *worker(void *arg)
{
    uint64_t rng = 0x9E3779B97F4A7C15ULL * (uint64_t)((long)arg + 1);
    const int replay = !strcmp(kind, "replay");
    const int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0)
    {
        perror("socket");
        return NULL;
    }
    const int one = 1;
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
    struct sockaddr_ll addr = {.sll_family = AF_PACKET, .sll_ifindex = ifindex, .sll_halen = 6};
    memcpy(addr.sll_addr, dst_mac, 6);

    static __thread uint8_t frames[BATCH][1600];
    struct mmsghdr messages[BATCH];
    struct iovec iov[BATCH];
    memset(messages, 0, sizeof(messages));
    for (int i = 0; i < BATCH; i++)
    {
        iov[i].iov_base = frames[i];
        messages[i].msg_hdr.msg_iov = &iov[i];
        messages[i].msg_hdr.msg_iovlen = 1;
        messages[i].msg_hdr.msg_name = &addr;
        messages[i].msg_hdr.msg_namelen = sizeof(addr);
    }

    unsigned long long sent = 0;
    const double started = now();
    while (now() < deadline)
    {
        // pacing: sleep whenever this thread is ahead of its rate
        if (thread_pps > 0)
        {
            const double ahead = (double)sent / thread_pps - (now() - started);
            if (ahead > 0)
            {
                usleep((useconds_t)(ahead * 1e6));
            }
        }
        // a replaying flood sends every round of frames a second time
        const uint64_t round_seed = rng;
        for (int pass = 0; pass < (replay ? 2 : 1); pass++)
        {
            uint64_t round_rng = round_seed;
            for (int batch = 0; batch < (replay ? REPLAY_ROUND / BATCH : 1); batch++)
            {
                for (int i = 0; i < BATCH; i++)
                {
                    iov[i].iov_len = build(frames[i], &round_rng);
                }
                const int n = sendmmsg(fd, messages, BATCH, 0);
                if (n > 0)
                {
                    sent += (unsigned long long)n;
                }
            }
            rng = round_rng;
            if (replay && pass == 0)
            {
                usleep(300000);
            }
        }
    }
    close(fd);
    pthread_mutex_lock(&total_lock);
    sent_total += sent;
    pthread_mutex_unlock(&total_lock);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 7 && argc != 8)
    {
        fprintf(stderr, "usage: flood <interface> <dst mac> <dst ip> <kind> <seconds> <threads> [pps]\n");
        return 2;
    }
    ifindex = (int)if_nametoindex(argv[1]);
    unsigned mac[6];
    if (!ifindex || sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
    {
        fprintf(stderr, "bad interface or mac\n");
        return 2;
    }
    for (int i = 0; i < 6; i++)
    {
        dst_mac[i] = (uint8_t)mac[i];
    }
    dst_ip = inet_addr(argv[3]);
    kind = argv[4];
    const double seconds = atof(argv[5]);
    const long threads = atol(argv[6]);
    thread_pps = argc == 8 ? atof(argv[7]) / (double)threads : 0;

    const double start = now();
    deadline = start + seconds;
    pthread_t ids[64];
    for (long i = 0; i < threads && i < 64; i++)
    {
        pthread_create(&ids[i], NULL, worker, (void *)i);
    }
    for (long i = 0; i < threads && i < 64; i++)
    {
        pthread_join(ids[i], NULL);
    }
    printf("%llu %.0f\n", sent_total, (double)sent_total / (now() - start));
    return 0;
}
