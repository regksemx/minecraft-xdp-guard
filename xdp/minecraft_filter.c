/*
 * minecraft_filter - XDP program protecting Minecraft servers against L7
 * (D)DoS attacks: Java Edition (TCP), Bedrock Edition (RakNet over UDP),
 * NetherNet (WebRTC over UDP plus its TLS/HTTP signaling over TCP).
 *
 * Every packet aimed at a protected port has to belong to a flow that proved
 * to be a real client:
 *
 *   Java     TCP handshake, then the Minecraft handshake followed by either
 *            status + ping or the login packet, all with tracked sequence
 *            numbers. Only a completed login is promoted to the fast path.
 *   Guard    TCP handshake, then a TLS ClientHello or an HTTP request.
 *   RakNet   OpenConnectionRequest1, then OpenConnectionRequest2 from the
 *            same address. Unconnected pings are answered but rate limited.
 *   ICE      A STUN binding request, then only STUN and DTLS.
 *   UDP guard  Nothing but a first byte and a minimum size (voice chat).
 *
 * Verified flows skip inspection and pay for a single map lookup. All other
 * traffic is dropped at the driver level, before the kernel spends anything
 * on it.
 *
 * Packets that ask for new state ("openers": SYN, status handshake, ping,
 * OpenConnectionRequest1, first STUN) are limited three ways:
 *
 *   per source ip   counters in a lazily reset window (ip_table)
 *   per cpu         a budget per second, not spent by proven players
 *   unknown ips     while a cpu sees a flood of them, an opener is only let
 *                   through as a retransmit (retry_table), which spoofed
 *                   sources never send
 *
 * Nothing here uses timers or needs userspace: state expires lazily and the
 * LRU maps recycle what nobody touches, so the maps can stay pinned and
 * survive a restart of the loader.
 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "config.h"
#include "protocol.h"
#include "bedrock.h"
#include "stats.h"

// fragment bits of iphdr->frag_off (kernel-internal net/ip.h, not uapi)
#ifndef IP_MF
#define IP_MF 0x2000 // flag: "more fragments"
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF // "fragment offset" part
#endif

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000ULL
#endif

// 802.1Q / 802.1ad tag (kernel-internal linux/if_vlan.h, not uapi)
struct vlan_tag
{
    __be16 tci;
    __be16 encapsulated_proto;
};

// OpenConnectionRequest1 datagrams accepted per pending RakNet client (the
// client resends it while probing the MTU), and how long such a client may
// take until its OpenConnectionRequest2
#define RAKNET_MAX_OCR1 32
#define RAKNET_PENDING_NS (30 * NSEC_PER_SEC)

// deepest frame offset a handshake host name may start at (see handshake_host_hash)
#define MAX_HOST_OFFSET 2048

// IPv6 extension headers walked to find the transport header
#define IPV6_MAX_EXT_HEADERS 4

/* ------------------------------------------------------------------------
 * Maps. All max_entries are placeholders, the loader sets the configured
 * capacities ([xdp] section) before the program is loaded.
 * --------------------------------------------------------------------- */

// TCP connections in the middle of the inspection sequence
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ipv4_flow_key);
    __type(value, struct initial_state);
} pending_tcp SEC(".maps");

// TCP connections that passed inspection
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv4_flow_key);
    __type(value, struct flow_entry);
} verified_tcp SEC(".maps");

// RakNet clients between OpenConnectionRequest1 and OpenConnectionRequest2
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ipv4_flow_key);
    __type(value, struct udp_pending);
} pending_udp SEC(".maps");

// UDP sessions that passed inspection
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv4_flow_key);
    __type(value, struct flow_entry);
} verified_udp SEC(".maps");

// known source ips: rate limit counters and the good mark
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);
    __type(value, struct ip_state);
} ip_table SEC(".maps");

// retransmit challenge, see retry_table_check() in common.h
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1048576);
    __type(key, __u32);
    __type(value, __u64);
} retry_table SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cpu_state);
} cpu_table SEC(".maps");

// only used when PROMETHEUS is enabled, see stats.h
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
} stats_map SEC(".maps");

// source networks that are never inspected / always dropped, filled by the loader
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
} allow_v4 SEC(".maps");

// the deny list can also be changed while the filter runs (`xdp-loader
// deny`). The value says how long an entry is valid: DENY_CONFIG and
// DENY_RUNTIME never expire, anything else is the ktime the ban ends
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, __u64);
} deny_v4 SEC(".maps");

// the server's answer to an unconnected ping, see struct pong_cache
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pong_cache);
} pong_cache SEC(".maps");

// hashes of the host names players may connect with (see hash_host)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} allowed_hosts SEC(".maps");

/* ------------------------------------------------------------------------
 * Per packet context
 * --------------------------------------------------------------------- */

struct packet
{
    struct xdp_md *ctx;
    const void *data;
    const void *data_end;
    struct statistics *stats; // NULL unless PROMETHEUS
    __u64 now;                // coarse monotonic clock, one read per packet
    __u64 len;                // frame length, for the byte counters
    __u32 l3_offset;          // offset of the IPv4 header inside the frame
    struct ipv4_flow_key flow;
};

static __always_inline __u32 drop_packet(const struct packet *p)
{
    count_stat(p->stats, STAT_DROPPED_PACKETS, 1);
    count_stat(p->stats, STAT_DROPPED_BYTES, p->len);
    return XDP_DROP;
}

// time since `since`; never negative when another cpu stored a timestamp
// that is a clock tick ahead of the one this cpu read
static __always_inline __u64 elapsed(const __u64 now, const __u64 since)
{
    return now > since ? now - since : 0;
}

enum port_class
{
    PORT_UNPROTECTED = 0,
    PORT_JAVA,
    PORT_GUARD,
    PORT_RAKNET,
    PORT_ICE,
    PORT_UDP_GUARD,
};

static __always_inline __u8 port_in_range(const __u32 port, const __u32 start, const __u32 end)
{
    return start && port >= start && port <= end;
}

static __always_inline __u32 tcp_port_class(const __u32 port)
{
    if (port_in_range(port, JAVA_START_PORT, JAVA_END_PORT))
    {
        return PORT_JAVA;
    }
    if (port_in_range(port, GUARD_START_PORT, GUARD_END_PORT))
    {
        return PORT_GUARD;
    }
    return PORT_UNPROTECTED;
}

static __always_inline __u32 udp_port_class(const __u32 port)
{
    if (port_in_range(port, RAKNET_START_PORT, RAKNET_END_PORT))
    {
        return PORT_RAKNET;
    }
    if (port_in_range(port, ICE_START_PORT, ICE_END_PORT))
    {
        return PORT_ICE;
    }
    if (port_in_range(port, UDPGUARD_START_PORT, UDPGUARD_END_PORT))
    {
        return PORT_UDP_GUARD;
    }
    return PORT_UNPROTECTED;
}

/* ------------------------------------------------------------------------
 * Allow / deny lists
 * --------------------------------------------------------------------- */

enum list_verdict
{
    LIST_UNLISTED = 0,
    LIST_ALLOWED,
    LIST_DENIED,
};

// only reached by packets that are not on the verified fast path
static __always_inline __u32 check_lists(const struct packet *p)
{
    if (!HAS_ALLOW && !HAS_DENY)
    {
        return LIST_UNLISTED;
    }
    const struct lpm_v4_key key = {.prefixlen = 32, .addr = p->flow.src_ip};
    if (HAS_DENY)
    {
        // an expired ban is ignored here and removed by the next
        // `xdp-loader deny` call or restart
        const __u64 *until = bpf_map_lookup_elem(&deny_v4, &key);
        if (until && (*until <= DENY_RUNTIME || p->now < *until))
        {
            count_stat(p->stats, STAT_DENYLIST, 1);
            return LIST_DENIED;
        }
    }
    if (HAS_ALLOW && bpf_map_lookup_elem(&allow_v4, &key))
    {
        count_stat(p->stats, STAT_ALLOWLIST, 1);
        return LIST_ALLOWED;
    }
    return LIST_UNLISTED;
}

/* ------------------------------------------------------------------------
 * Openers: per ip limits, per cpu budgets, retransmit challenge
 * --------------------------------------------------------------------- */

static __always_inline struct cpu_state *cpu_state_get(const __u64 now)
{
    __u32 zero = 0;
    struct cpu_state *cpu = bpf_map_lookup_elem(&cpu_table, &zero);
    if (!cpu)
    {
        return NULL; // per-cpu array index 0 always exists, this is unreachable
    }
    if (elapsed(now, cpu->sec_start) >= NSEC_PER_SEC)
    {
        cpu->sec_start = now;
        cpu->unknown = 0;
        __builtin_memset(cpu->used, 0, sizeof(cpu->used));
    }
    return cpu;
}

/*
 * Returns 1 if an opener from an unknown source ip may go on: either no
 * challenge is active on this cpu, or it is the retransmit of an opener the
 * challenge dropped before.
 */
static __always_inline __u8 challenge_passed(const struct packet *p, const __u32 kind, const __u32 extra)
{
    if (CHALLENGE_MODE == 0)
    {
        return 1;
    }
    if (CHALLENGE_MODE == 1)
    {
        struct cpu_state *cpu = cpu_state_get(p->now);
        if (!cpu)
        {
            return 0;
        }
        // too many unknown ips within this second: arm the challenge, and
        // keep it armed until the flood has been over for a while
        if (++cpu->unknown > CHALLENGE_PPS)
        {
            cpu->challenge_until = p->now + CHALLENGE_HOLD_NS;
        }
        if (p->now >= cpu->challenge_until)
        {
            return 1;
        }
    }

    __u64 hash = (((__u64)p->flow.src_ip << 32) | p->flow.dst_ip) ^ RETRY_SEED;
    hash = mix64(hash + kind);
    hash = mix64(hash ^ ((__u64)p->flow.src_port << 48) ^ ((__u64)p->flow.dst_port << 32) ^ extra);

    __u32 index = (__u32)hash & RETRY_MASK;
    __u64 *slot = bpf_map_lookup_elem(&retry_table, &index);
    if (!slot)
    {
        return 0; // the loader sizes the table to RETRY_MASK + 1, this is unreachable
    }
    if (retry_table_check(slot, hash, p->now, RETRY_MIN_TICKS, RETRY_MAX_TICKS))
    {
        count_stat(p->stats, STAT_CHALLENGE_PASSED, 1);
        return 1;
    }
    count_stat(p->stats, STAT_CHALLENGE_DROPPED, 1);
    return 0;
}

enum admit_result
{
    ADMIT_OK = 0,
    ADMIT_THROTTLED,  // per ip limit
    ADMIT_BUDGET,     // per cpu budget
    ADMIT_CHALLENGED, // unknown ip, first sighting while the challenge is active
    ADMIT_ERROR,
};

/*
 * Decides whether an opener may create new state.
 *
 * ip_limit   max openers of this kind per source ip and window, 0 = unlimited
 * cpu_budget max openers of this kind per cpu and second from ips without
 *            the good mark, 0 = unlimited
 * challenge  whether an unknown ip has to pass the retransmit challenge
 *            (only possible for packets the client retransmits unchanged)
 * extra      distinguishes openers of the same flow in the challenge
 *
 * The order keeps a spoofed flood cheap: its random sources are never
 * known, so each packet costs one failed hash lookup and one array slot,
 * and nothing is inserted anywhere.
 */
static __always_inline __u32 admit(const struct packet *p, const __u32 kind, const __u32 ip_limit, const __u32 cpu_budget, const __u8 challenge, const __u32 extra)
{
    __u8 good = 0;
    struct ip_state *ip = bpf_map_lookup_elem(&ip_table, &p->flow.src_ip);
    if (ip)
    {
        if (elapsed(p->now, ip->window_start) >= LIMIT_WINDOW_NS)
        {
            ip->window_start = p->now;
            __builtin_memset(ip->hits, 0, sizeof(ip->hits));
        }
        good = ip->good_until > p->now;
        // not atomic on purpose: racing cpus can only lose single counts
        if (ip_limit && kind < IP_HIT_KINDS && ++ip->hits[kind] > ip_limit)
        {
            return ADMIT_THROTTLED;
        }
    }
    else if (challenge && !challenge_passed(p, kind, extra))
    {
        return ADMIT_CHALLENGED;
    }

    if (cpu_budget && !good)
    {
        struct cpu_state *cpu = cpu_state_get(p->now);
        if (!cpu)
        {
            return ADMIT_ERROR;
        }
        if (++cpu->used[kind] > cpu_budget)
        {
            return ADMIT_BUDGET;
        }
    }

    if (!ip)
    {
        struct ip_state fresh = {.window_start = p->now};
        if (kind < IP_HIT_KINDS)
        {
            fresh.hits[kind] = 1;
        }
        if (bpf_map_update_elem(&ip_table, &p->flow.src_ip, &fresh, BPF_ANY) < 0)
        {
            count_stat(p->stats, STAT_TABLE_FULL, 1);
            return ADMIT_ERROR;
        }
        count_stat(p->stats, STAT_NEW_IP, 1);
    }
    return ADMIT_OK;
}

/* ------------------------------------------------------------------------
 * Verified flows
 * --------------------------------------------------------------------- */

// a game flow lived long enough: its source ip is a proven player from now on
static __always_inline void mark_ip_good(const struct packet *p)
{
    struct ip_state *ip = bpf_map_lookup_elem(&ip_table, &p->flow.src_ip);
    if (ip)
    {
        ip->good_until = p->now + GOOD_TTL_NS;
    }
    else
    {
        const struct ip_state fresh = {.window_start = p->now, .good_until = p->now + GOOD_TTL_NS};
        if (bpf_map_update_elem(&ip_table, &p->flow.src_ip, &fresh, BPF_ANY) < 0)
        {
            return;
        }
    }
    count_stat(p->stats, STAT_GOOD_IP, 1);
}

enum flow_verdict
{
    FLOW_PASS = 0,
    FLOW_EXPIRED,
    FLOW_LIMITED,
};

/*
 * Accounts one packet of a verified flow. The only write on the hot path is
 * the packet counter; everything else happens once per second and flow.
 */
static __always_inline __u32 flow_touch(const struct packet *p, struct flow_entry *flow, const __u64 idle_ns, const __u32 pps)
{
    const __u64 age = elapsed(p->now, flow->win_start);
    if (age < NSEC_PER_SEC)
    {
        // not atomic on purpose: racing cpus can only lose single counts
        if (pps && ++flow->win_pkts > pps)
        {
            return FLOW_LIMITED;
        }
        return FLOW_PASS;
    }
    if (age > idle_ns)
    {
        return FLOW_EXPIRED;
    }
    flow->win_start = p->now;
    flow->win_pkts = 1;
    if (GOOD_AFTER_NS && !flow->good_marked && (flow->kind == FLOW_JAVA || flow->kind == FLOW_RAKNET) &&
        elapsed(p->now, flow->created) >= GOOD_AFTER_NS)
    {
        flow->good_marked = 1;
        mark_ip_good(p);
    }
    return FLOW_PASS;
}

// promotes the flow of this packet to the fast path; returns 0 on failure
static __always_inline __u8 verify_flow(const struct packet *p, void *map, const __u8 kind)
{
    const struct flow_entry fresh = {
        .win_start = p->now,
        .created = p->now,
        .win_pkts = 1,
        .kind = kind,
    };
    if (bpf_map_update_elem(map, &p->flow, &fresh, BPF_ANY) < 0)
    {
        count_stat(p->stats, STAT_TABLE_FULL, 1);
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------------
 * TCP: Minecraft Java and the generic guard
 * --------------------------------------------------------------------- */

/*
 * Hashes the server address of a handshake for the host filter; returns 0
 * if it can not be an allowed host (too long, out of bounds).
 *
 * A global function on purpose: the verifier checks it once on its own,
 * instead of walking the rest of the program again for every way the loop
 * over the host name can end. That is also why it gets an offset instead of
 * a packet pointer, only the context and scalars can cross that boundary.
 * The caller has already checked that the host lies inside the payload.
 */
__noinline __u64 handshake_host_hash(struct xdp_md *ctx, __u32 offset, __u32 host_len)
{
    const void *data = (const void *)(long)ctx->data;
    const void *data_end = (const void *)(long)ctx->data_end;
    // the bound also keeps the pointer below the verifier's limit for
    // packet offsets; a handshake never starts that deep inside a frame
    if (offset > MAX_HOST_OFFSET)
    {
        return 0;
    }
    const __u8 *host = (const __u8 *)data + offset;
    __u64 hash = 0;
    if (!hash_host(host, host_len, data_end, data_end, &hash))
    {
        return 0;
    }
    return hash ? hash : 1;
}

// flag combinations that never occur on legitimate client traffic
static __always_inline __u8 detect_tcp_bypass(const struct tcphdr *tcp)
{
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) || // none of SYN/ACK/FIN/RST set
        (tcp->syn && tcp->ack) ||                             // SYN+ACK from outside is never a client
        (tcp->syn && (tcp->fin || tcp->rst)) ||               // SYN+FIN / SYN+RST are always forged
        tcp->urg)                                             // URG is unused by the protocol
    {
        return 1;
    }
    return 0;
}

// returns 1 if the kernel has an established socket for this flow (the
// service runs on this host, in this network namespace)
static __always_inline __u8 kernel_has_connection(const struct packet *p)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.saddr = p->flow.src_ip;
    tuple.ipv4.daddr = p->flow.dst_ip;
    tuple.ipv4.sport = p->flow.src_port;
    tuple.ipv4.dport = p->flow.dst_port;

    struct bpf_sock *sk = bpf_sk_lookup_tcp(p->ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    if (!sk)
    {
        return 0;
    }
    const __u8 established = sk->state == BPF_TCP_ESTABLISHED;
    bpf_sk_release(sk);
    return established;
}

static __always_inline __u32 handle_tcp(struct packet *p, const struct iphdr *ip, const struct tcphdr *tcp, const __u32 tcp_hdr_len, const __u8 guard)
{
    if (detect_tcp_bypass(tcp))
    {
        count_stat(p->stats, STAT_TCP_BYPASS, 1);
        goto drop;
    }

    // new connection: limit it, then start tracking it
    if (tcp->syn)
    {
        count_stat(p->stats, STAT_TCP_SYN, 1);

        // drop SYNs carrying payload (e.g. TCP fast open): the data would
        // reach the backend without ever passing the inspection state machine
        if (bpf_ntohs(ip->tot_len) > (ip->ihl * 4) + tcp_hdr_len)
        {
            count_stat(p->stats, STAT_TCP_BYPASS, 1);
            goto drop;
        }

        const __u32 listed = check_lists(p);
        if (listed == LIST_DENIED)
        {
            goto drop;
        }
        if (listed == LIST_ALLOWED)
        {
            return XDP_PASS;
        }

        // a retransmitted SYN repeats the sequence number, which makes it
        // recognizable for the retransmit challenge
        const __u32 admitted = admit(p, OPEN_SYN, SYN_HITS, SYN_BUDGET, 1, tcp->seq);
        if (admitted != ADMIT_OK)
        {
            if (admitted == ADMIT_THROTTLED)
            {
                count_stat(p->stats, STAT_SYN_THROTTLED, 1);
            }
            else if (admitted == ADMIT_BUDGET)
            {
                count_stat(p->stats, STAT_TCP_BUDGET_DROPPED, 1);
            }
            goto drop;
        }

        // track the connection: the next packet has to be the ACK finishing
        // the TCP handshake, with the sequence number following this SYN
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, bpf_ntohl(tcp->seq) + 1);
        if (bpf_map_update_elem(&pending_tcp, &p->flow, &new_state, BPF_ANY) < 0)
        {
            count_stat(p->stats, STAT_TABLE_FULL, 1);
            goto drop;
        }
        return XDP_PASS;
    }

    // verified connections skip all further inspection
    struct flow_entry *flow = bpf_map_lookup_elem(&verified_tcp, &p->flow);
    if (flow)
    {
        const __u32 touched = flow_touch(p, flow, TCP_IDLE_NS, TCP_FLOW_PPS);
        if (touched == FLOW_PASS)
        {
            return XDP_PASS;
        }
        if (touched == FLOW_LIMITED)
        {
            count_stat(p->stats, STAT_TCP_RATE_LIMITED, 1);
            goto drop;
        }
        // idle for too long: forget the connection, the packet is handled
        // like one of an unknown flow
        bpf_map_delete_elem(&verified_tcp, &p->flow);
    }

    const __u32 listed = check_lists(p);
    if (listed == LIST_DENIED)
    {
        goto drop;
    }
    if (listed == LIST_ALLOWED)
    {
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&pending_tcp, &p->flow);
    if (!initial_state)
    {
        // neither tracked nor verified. Right after the filter was attached
        // this may be a connection that already existed: adopt it instead
        // of cutting every player off
        if (ADOPT_MODE && p->now < ADOPT_UNTIL_NS && tcp->ack && !tcp->rst &&
            (ADOPT_MODE == 2 || kernel_has_connection(p)) && verify_flow(p, &verified_tcp, FLOW_ADOPTED))
        {
            count_stat(p->stats, STAT_TCP_ADOPTED, 1);
            return XDP_PASS;
        }
        count_stat(p->stats, STAT_TCP_UNTRACKED, 1);
        goto drop;
    }

    const __u8 *tcp_payload = (const __u8 *)tcp + tcp_hdr_len;

    // ip total length - ip header - tcp header = length of the tcp payload
    const __u16 ip_tot_len = bpf_ntohs(ip->tot_len);
    const __u16 tcp_payload_len = ip_tot_len - (ip->ihl * 4) - tcp_hdr_len;
    const __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    // tcp packet split over multiple ethernet frames, we don't support that
    if (tcp_payload_end > (const __u8 *)p->data_end)
    {
        goto drop;
    }

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        // not an ack, or not the ack matching our SYN
        if (!tcp->ack || initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            goto drop;
        }

        // advance the state machine before the early drop below, the next
        // packet has to be matched against AWAIT_MC_HANDSHAKE
        initial_state->state = state = AWAIT_MC_HANDSHAKE;

        // the empty ack finishing the TCP handshake is dropped on purpose:
        // the backend will accept the first data packet as that ack, which
        // elegantly limits backend connections to clients whose first
        // packet passed inspection. If the ack already carries payload,
        // fall through into payload inspection instead
        if (tcp_payload >= tcp_payload_end)
        {
            goto drop;
        }
    }

    if (tcp_payload < tcp_payload_end)
    {
        // payload without an ack flag is never legitimate mid-handshake
        if (!tcp->ack)
        {
            goto drop_connection;
        }

        // we fully track the tcp sequence, so a mismatch here is either a
        // retransmission or an out-of-order packet: drop the packet, and
        // drop the whole connection once that happens too often. Everything
        // that survives this check is exactly the in-order byte stream the
        // backend would see, which is what allows the hard punishments below
        if (initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            if (++initial_state->fails > MAX_OUT_OF_ORDER)
            {
                goto drop_connection;
            }
            goto drop;
        }

        if (state == AWAIT_MC_HANDSHAKE)
        {
            if (guard)
            {
                if (!inspect_guard_data(tcp_payload, tcp_payload_end, p->data_end))
                {
                    count_stat(p->stats, STAT_GUARD_INVALID, 1);
                    goto drop_connection;
                }
                if (!verify_flow(p, &verified_tcp, FLOW_GUARD))
                {
                    goto drop_connection;
                }
                bpf_map_delete_elem(&pending_tcp, &p->flow);
                count_stat(p->stats, STAT_GUARD_VERIFIED, 1);
                return XDP_PASS;
            }

            // if the status request or login packet is in the same tcp
            // segment as the handshake, inspect_handshake returns a
            // DIRECT_READ_* state and advances tcp_payload to the rest
            const __u8 *host = tcp_payload;
            __u32 host_len = 0;
            const __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, p->data_end, &initial_state->protocol, &tcp_payload, &host, &host_len);
            if (!next_state)
            {
                // even with retransmissions the handshake of a legitimate
                // client is always parseable, this connection is bogus
                count_stat(p->stats, STAT_JAVA_INVALID, 1);
                goto drop;
            }
            if (next_state == RECEIVED_LEGACY_PING)
            {
                goto drop_connection;
            }

            // everything below drops the handshake itself when it rejects
            // the connection: the backend never gets data, so its kernel
            // never even completes the TCP handshake
            if (HOST_FILTER)
            {
                const __u64 host_hash = handshake_host_hash(p->ctx, (__u32)(host - (const __u8 *)p->data), host_len);
                if (!host_hash || !bpf_map_lookup_elem(&allowed_hosts, &host_hash))
                {
                    count_stat(p->stats, STAT_JAVA_BAD_HOST, 1);
                    goto drop_connection;
                }
            }

            if (next_state == AWAIT_STATUS_REQUEST || next_state == DIRECT_READ_STATUS_REQUEST)
            {
                if (STATUS_HITS || STATUS_BUDGET)
                {
                    const __u32 admitted = admit(p, OPEN_STATUS, STATUS_HITS, STATUS_BUDGET, 0, 0);
                    if (admitted != ADMIT_OK)
                    {
                        count_stat(p->stats, admitted == ADMIT_THROTTLED ? STAT_STATUS_THROTTLED : STAT_TCP_BUDGET_DROPPED, 1);
                        goto drop_connection;
                    }
                }
                count_stat(p->stats, STAT_JAVA_STATUS, 1);
            }
            else
            {
                const __s32 protocol = initial_state->protocol;
                if ((JAVA_PROTO_MIN && protocol < JAVA_PROTO_MIN) || (JAVA_PROTO_MAX && protocol > JAVA_PROTO_MAX))
                {
                    count_stat(p->stats, STAT_JAVA_BAD_PROTO, 1);
                    goto drop_connection;
                }
                if (LOGIN_BUDGET && admit(p, OPEN_LOGIN, 0, LOGIN_BUDGET, 0, 0) != ADMIT_OK)
                {
                    count_stat(p->stats, STAT_TCP_BUDGET_DROPPED, 1);
                    goto drop_connection;
                }
            }

            if (next_state == DIRECT_READ_STATUS_REQUEST)
            {
                goto read_status;
            }
            if (next_state == DIRECT_READ_LOGIN)
            {
                goto read_login;
            }
            initial_state->state = next_state;
            goto update_state;
        }
        if (state == AWAIT_STATUS_REQUEST)
        read_status:
        {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, p->data_end))
            {
                count_stat(p->stats, STAT_JAVA_INVALID, 1);
                goto drop;
            }
            initial_state->state = AWAIT_PING;
            goto update_state;
        }
        if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, p->data_end))
            {
                count_stat(p->stats, STAT_JAVA_INVALID, 1);
                goto drop;
            }
            initial_state->state = PING_COMPLETE;
            goto update_state;
        }
        if (state == AWAIT_LOGIN)
        read_login:
        {
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, p->data_end, initial_state->protocol))
            {
                count_stat(p->stats, STAT_JAVA_INVALID, 1);
                goto drop;
            }
            // tracking ends here, no need to update the expected sequence
            if (!verify_flow(p, &verified_tcp, FLOW_JAVA))
            {
                goto drop_connection;
            }
            bpf_map_delete_elem(&pending_tcp, &p->flow);
            count_stat(p->stats, STAT_JAVA_VERIFIED, 1);
            return XDP_PASS;
        }
        if (state == PING_COMPLETE)
        {
            // a finished ping flow has nothing more to say
            goto drop_connection;
        }
    }
    else if (state == AWAIT_MC_HANDSHAKE)
    {
        // empty acks are not allowed while the first payload is pending,
        // otherwise an attacker could sit on a half-inspected connection
        goto drop;
    }

    // empty segments in the remaining states (pure acks, FIN/RST teardown)
    return XDP_PASS;

// shared exit paths: jumping here instead of duplicating these blocks keeps
// the generated program drastically smaller
drop_connection:
    count_stat(p->stats, STAT_DROP_CONNECTION, 1);
    bpf_map_delete_elem(&pending_tcp, &p->flow);
    // fall through
drop:
    return drop_packet(p);
update_state:
    initial_state->expected_sequence += tcp_payload_len;
    count_stat(p->stats, STAT_STATE_SWITCH, 1);
    return XDP_PASS;
}

/* ------------------------------------------------------------------------
 * UDP: Bedrock RakNet and NetherNet ICE
 * --------------------------------------------------------------------- */

#define RAKNET_UNCONNECTED_PONG 0x1c
#define PONG_HEADER_LEN 9 // id, echoed ping time

static __always_inline __u16 ipv4_header_checksum(const struct iphdr *ip)
{
    const __u16 *words = (const __u16 *)ip;
    __u32 sum = 0;
    for (__u32 i = 0; i < sizeof(*ip) / 2; i++)
    {
        sum += words[i];
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

/*
 * Turns an unconnected ping into the server's pong and sends it straight
 * back out of the interface, so server list pings never reach the server.
 * Returns XDP_PASS (let the server answer) whenever the cached pong can not
 * be used.
 */
static __always_inline __u32 answer_ping(const struct packet *p, const struct iphdr *ip, const __u8 *payload, const __u32 payload_len)
{
    __u32 zero = 0;
    const struct pong_cache *pong = bpf_map_lookup_elem(&pong_cache, &zero);
    if (!pong)
    {
        return XDP_PASS;
    }
    __u32 pong_len = pong->len;
    barrier_var(pong_len);
    if (pong_len < PONG_MIN || pong_len > PONG_MAX || elapsed(p->now, pong->updated) > PONG_MAX_AGE_NS || ip->ihl != 5)
    {
        return XDP_PASS;
    }
    if ((const void *)(payload + PONG_HEADER_LEN) > p->data_end)
    {
        return XDP_PASS;
    }
    const __u64 ping_time = *(const __u64 *)(payload + 1);

    // resize the frame to the pong; all packet pointers are stale afterwards
    const __s32 delta = (__s32)(PONG_HEADER_LEN + pong_len) - (__s32)payload_len;
    if (bpf_xdp_adjust_tail(p->ctx, delta))
    {
        return XDP_PASS;
    }
    void *data = (void *)(long)p->ctx->data;
    const void *data_end = (const void *)(long)p->ctx->data_end;
    const __u32 l3_offset = p->l3_offset & 0x3F;

    struct ethhdr *eth = data;
    struct iphdr *reply_ip = data + l3_offset;
    struct udphdr *reply_udp = (struct udphdr *)(reply_ip + 1);
    __u8 *reply = (__u8 *)(reply_udp + 1);
    if ((const void *)(eth + 1) > data_end || (const void *)(reply + PONG_HEADER_LEN) > data_end)
    {
        return XDP_DROP;
    }

    // back to where it came from
    __u8 mac[ETH_ALEN];
    __builtin_memcpy(mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, mac, ETH_ALEN);

    const __be32 client_ip = reply_ip->saddr;
    reply_ip->saddr = reply_ip->daddr;
    reply_ip->daddr = client_ip;
    reply_ip->tot_len = bpf_htons((__u16)(sizeof(*reply_ip) + sizeof(*reply_udp) + PONG_HEADER_LEN + pong_len));
    reply_ip->ttl = 64;
    reply_ip->check = 0;
    reply_ip->check = ipv4_header_checksum(reply_ip);

    const __be16 client_port = reply_udp->source;
    reply_udp->source = reply_udp->dest;
    reply_udp->dest = client_port;
    reply_udp->len = bpf_htons((__u16)(sizeof(*reply_udp) + PONG_HEADER_LEN + pong_len));
    reply_udp->check = 0; // optional over IPv4

    reply[0] = RAKNET_UNCONNECTED_PONG;
    *(__u64 *)(reply + 1) = ping_time;
    if (bpf_xdp_store_bytes(p->ctx, l3_offset + sizeof(*reply_ip) + sizeof(*reply_udp) + PONG_HEADER_LEN, (void *)pong->data, pong_len))
    {
        return XDP_DROP;
    }
    count_stat(p->stats, STAT_RAKNET_PONG, 1);
    return XDP_TX;
}

// counts why an opener was refused
static __always_inline void count_udp_refusal(const struct packet *p, const __u32 admitted, const enum stat_id throttled)
{
    if (admitted == ADMIT_THROTTLED)
    {
        count_stat(p->stats, throttled, 1);
    }
    else if (admitted == ADMIT_BUDGET)
    {
        count_stat(p->stats, STAT_UDP_BUDGET_DROPPED, 1);
    }
}

static __always_inline __u32 handle_udp(struct packet *p, const struct iphdr *ip, const struct udphdr *udp, const __u32 class)
{
    const __u8 ice = class == PORT_ICE;
    const __u8 guard = class == PORT_UDP_GUARD;
    const __u32 udp_len = bpf_ntohs(udp->len);
    const __u8 *payload = (const __u8 *)(udp + 1);
    if (udp_len <= sizeof(struct udphdr))
    {
        count_stat(p->stats, STAT_MALFORMED, 1);
        goto drop;
    }
    const __u8 *payload_end = payload + (udp_len - sizeof(struct udphdr));
    // length field pointing past the frame, or an empty datagram
    if (payload_end > (const __u8 *)p->data_end || payload + 1 > (const __u8 *)p->data_end)
    {
        count_stat(p->stats, STAT_MALFORMED, 1);
        goto drop;
    }
    const __u8 first = payload[0];

    // the generic guard has one rule for every datagram, session or not
    if (guard && !udp_guard_valid(first, (__u64)(payload_end - payload)))
    {
        count_stat(p->stats, STAT_UDPGUARD_INVALID, 1);
        goto drop;
    }

    // verified sessions only pay for this lookup
    struct flow_entry *session = bpf_map_lookup_elem(&verified_udp, &p->flow);
    if (session)
    {
        const __u32 touched = flow_touch(p, session, UDP_IDLE_NS, UDP_FLOW_PPS);
        if (touched == FLOW_LIMITED)
        {
            count_stat(p->stats, STAT_UDP_RATE_LIMITED, 1);
            goto drop;
        }
        if (touched == FLOW_EXPIRED)
        {
            bpf_map_delete_elem(&verified_udp, &p->flow);
            session = NULL;
        }
        else if (guard)
        {
            return XDP_PASS;
        }
        else if (ice)
        {
            if (ice_first_byte_valid(first))
            {
                return XDP_PASS;
            }
            count_stat(p->stats, STAT_ICE_INVALID, 1);
            goto drop;
        }
        else if (first & RAKNET_CONNECTED_FLAG)
        {
            return XDP_PASS;
        }
        // an offline message of a connected RakNet client (e.g. a ping, or a
        // resent connection request) takes the regular path below
    }

    const __u32 listed = check_lists(p);
    if (listed == LIST_DENIED)
    {
        goto drop;
    }
    if (listed == LIST_ALLOWED)
    {
        return XDP_PASS;
    }

    if (guard)
    {
        // there is no handshake to follow: the first acceptable datagram
        // opens the session. Such services keep sending from the same
        // socket, so any later datagram serves as the retransmit
        const __u32 admitted = admit(p, OPEN_UDP, UDP_OPEN_HITS, UDP_OPEN_BUDGET, 1, 0);
        if (admitted != ADMIT_OK)
        {
            count_udp_refusal(p, admitted, STAT_UDP_OPEN_THROTTLED);
            goto drop;
        }
        if (!verify_flow(p, &verified_udp, FLOW_UDP_GUARD))
        {
            goto drop;
        }
        count_stat(p->stats, STAT_UDPGUARD_VERIFIED, 1);
        return XDP_PASS;
    }

    if (ice)
    {
        // a WebRTC session has to start with an ICE connectivity check
        if (first <= 3 && inspect_stun_binding(payload, payload_end, p->data_end))
        {
            const __u32 admitted = admit(p, OPEN_UDP, UDP_OPEN_HITS, UDP_OPEN_BUDGET, 1, 0);
            if (admitted != ADMIT_OK)
            {
                count_udp_refusal(p, admitted, STAT_UDP_OPEN_THROTTLED);
                goto drop;
            }
            if (!verify_flow(p, &verified_udp, FLOW_ICE))
            {
                goto drop;
            }
            count_stat(p->stats, STAT_ICE_VERIFIED, 1);
            return XDP_PASS;
        }
        if (!ice_first_byte_valid(first))
        {
            count_stat(p->stats, STAT_ICE_INVALID, 1);
            goto drop;
        }
        goto unknown_session;
    }

    if (first == RAKNET_UNCONNECTED_PING || first == RAKNET_UNCONNECTED_PING_OPEN)
    {
        if (!inspect_raknet_ping(payload, payload_end, p->data_end))
        {
            count_stat(p->stats, STAT_RAKNET_INVALID, 1);
            goto drop;
        }
        // the client keeps pinging from the same socket, so a ping is its
        // own retransmit
        const __u32 admitted = admit(p, OPEN_PING, PING_HITS, PING_BUDGET, 1, first);
        if (admitted != ADMIT_OK)
        {
            count_udp_refusal(p, admitted, STAT_PING_THROTTLED);
            goto drop;
        }
        count_stat(p->stats, STAT_RAKNET_PING, 1);
        if (PONG_REPLY)
        {
            return answer_ping(p, ip, payload, udp_len - sizeof(struct udphdr));
        }
        return XDP_PASS;
    }

    if (first == RAKNET_OPEN_CONNECTION_REQUEST_1)
    {
        if (!inspect_raknet_ocr1(payload, payload_end, p->data_end))
        {
            count_stat(p->stats, STAT_RAKNET_INVALID, 1);
            goto drop;
        }
        // the client repeats this request while it probes the MTU: only the
        // first one of a connection attempt is an opener
        struct udp_pending *pending = bpf_map_lookup_elem(&pending_udp, &p->flow);
        if (pending && elapsed(p->now, pending->created) <= RAKNET_PENDING_NS)
        {
            if (++pending->requests > RAKNET_MAX_OCR1)
            {
                count_stat(p->stats, STAT_UDP_OPEN_THROTTLED, 1);
                goto drop;
            }
            return XDP_PASS;
        }
        const __u32 admitted = admit(p, OPEN_UDP, UDP_OPEN_HITS, UDP_OPEN_BUDGET, 1, first);
        if (admitted != ADMIT_OK)
        {
            count_udp_refusal(p, admitted, STAT_UDP_OPEN_THROTTLED);
            goto drop;
        }
        const struct udp_pending fresh = {.created = p->now, .requests = 1};
        if (bpf_map_update_elem(&pending_udp, &p->flow, &fresh, BPF_ANY) < 0)
        {
            count_stat(p->stats, STAT_TABLE_FULL, 1);
            goto drop;
        }
        count_stat(p->stats, STAT_RAKNET_OPEN, 1);
        return XDP_PASS;
    }

    if (first == RAKNET_OPEN_CONNECTION_REQUEST_2)
    {
        if (!inspect_raknet_ocr2(payload, payload_end, p->data_end))
        {
            count_stat(p->stats, STAT_RAKNET_INVALID, 1);
            goto drop;
        }
        if (session)
        {
            return XDP_PASS; // resent while the reply was on its way
        }
        // only clients that sent OpenConnectionRequest1 before may go on
        const struct udp_pending *pending = bpf_map_lookup_elem(&pending_udp, &p->flow);
        if (!pending || elapsed(p->now, pending->created) > RAKNET_PENDING_NS)
        {
            count_stat(p->stats, STAT_UDP_UNTRACKED, 1);
            goto drop;
        }
        if (!verify_flow(p, &verified_udp, FLOW_RAKNET))
        {
            goto drop;
        }
        bpf_map_delete_elem(&pending_udp, &p->flow);
        count_stat(p->stats, STAT_RAKNET_VERIFIED, 1);
        return XDP_PASS;
    }

    if (!(first & RAKNET_CONNECTED_FLAG))
    {
        // no other offline message is ever sent by a client
        count_stat(p->stats, STAT_RAKNET_INVALID, 1);
        goto drop;
    }

unknown_session:
    // well-formed traffic of a session we never saw open. Right after the
    // filter was attached this may be a player who was already connected
    if (ADOPT_MODE && p->now < ADOPT_UNTIL_NS && verify_flow(p, &verified_udp, FLOW_ADOPTED))
    {
        count_stat(p->stats, STAT_UDP_ADOPTED, 1);
        return XDP_PASS;
    }
    count_stat(p->stats, STAT_UDP_UNTRACKED, 1);
drop:
    return drop_packet(p);
}

/* ------------------------------------------------------------------------
 * IPv6: the filter only inspects IPv4, so IPv6 must not become a way
 * around it. With IPV6_PROTECT everything aimed at a protected port is
 * dropped.
 * --------------------------------------------------------------------- */

static __always_inline __u32 handle_ipv6(const void *l3, const void *data_end, const __u64 len)
{
    const struct ipv6hdr *ip6 = l3;
    if ((const void *)(ip6 + 1) > data_end)
    {
        return XDP_PASS;
    }

    __u8 next = ip6->nexthdr;
    const __u8 *cursor = (const __u8 *)(ip6 + 1);

    // skip the extension headers in front of the transport header
    for (__u32 i = 0; i < IPV6_MAX_EXT_HEADERS; i++)
    {
        if (next != IPPROTO_HOPOPTS && next != IPPROTO_ROUTING && next != IPPROTO_DSTOPTS && next != IPPROTO_FRAGMENT)
        {
            break;
        }
        if ((const void *)(cursor + 8) > data_end)
        {
            return XDP_PASS;
        }
        if (next == IPPROTO_FRAGMENT)
        {
            // only the first fragment carries the ports; dropping it is
            // enough, the others can never be reassembled
            if ((cursor[2] << 8 | (cursor[3] & 0xF8)) != 0)
            {
                return XDP_PASS;
            }
            next = cursor[0];
            cursor += 8;
        }
        else
        {
            const __u32 ext_len = ((__u32)cursor[1] + 1) * 8;
            next = cursor[0];
            cursor += ext_len;
        }
    }

    if (next != IPPROTO_TCP && next != IPPROTO_UDP)
    {
        return XDP_PASS;
    }
    // source and destination port sit at the same place in both headers
    if ((const void *)(cursor + 4) > data_end)
    {
        return XDP_PASS;
    }
    const __u32 dest_port = (__u32)cursor[2] << 8 | cursor[3];
    const __u32 class = next == IPPROTO_TCP ? tcp_port_class(dest_port) : udp_port_class(dest_port);
    if (class == PORT_UNPROTECTED)
    {
        return XDP_PASS;
    }

    if (PROMETHEUS)
    {
        __u32 zero = 0;
        struct statistics *stats = bpf_map_lookup_elem(&stats_map, &zero);
        count_stat(stats, STAT_INCOMING_PACKETS, 1);
        count_stat(stats, STAT_INCOMING_BYTES, len);
        count_stat(stats, STAT_IPV6_DROPPED, 1);
        count_stat(stats, STAT_DROPPED_PACKETS, 1);
        count_stat(stats, STAT_DROPPED_BYTES, len);
    }
    return XDP_DROP;
}

/* ------------------------------------------------------------------------
 * XDP entry point
 * --------------------------------------------------------------------- */

SEC("xdp")
__s32 minecraft_filter(struct xdp_md *ctx)
{
    const void *data = (const void *)(long)ctx->data;
    const void *data_end = (const void *)(long)ctx->data_end;

    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end)
    {
        return XDP_DROP;
    }

    __be16 l3_proto = eth->h_proto;
    const void *l3 = eth + 1;
    __u32 l3_offset = sizeof(*eth);

    // up to two VLAN tags (the NIC usually strips them, but not always)
    if (l3_proto == bpf_htons(ETH_P_8021Q) || l3_proto == bpf_htons(ETH_P_8021AD))
    {
        const struct vlan_tag *tag = l3;
        if ((const void *)(tag + 1) > data_end)
        {
            return XDP_DROP;
        }
        l3_proto = tag->encapsulated_proto;
        l3 = tag + 1;
        l3_offset += sizeof(*tag);
        if (l3_proto == bpf_htons(ETH_P_8021Q))
        {
            tag = l3;
            if ((const void *)(tag + 1) > data_end)
            {
                return XDP_DROP;
            }
            l3_proto = tag->encapsulated_proto;
            l3 = tag + 1;
            l3_offset += sizeof(*tag);
        }
    }

    if (l3_proto == bpf_htons(ETH_P_IPV6))
    {
        if (!IPV6_PROTECT)
        {
            return XDP_PASS;
        }
        return handle_ipv6(l3, data_end, (__u64)(data_end - data));
    }

    if (l3_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    const struct iphdr *ip = l3;
    if ((const void *)(ip + 1) > data_end || ip->ihl < 5)
    {
        return XDP_DROP;
    }

    const __u8 l4_proto = ip->protocol;
    if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP)
    {
        return XDP_PASS;
    }

    // non-first fragments (fragment offset != 0) carry no L4 header, so the
    // port check below cannot run on them: pass them up the stack so other
    // services keep receiving their fragmented traffic. Safe for the
    // protected ports because the matching first fragment is dropped after
    // the port check, so reassembly never completes and the kernel discards
    // the rest after the frag timeout. The ports can not be forged via
    // fragment overlap either: they live in bytes 0-3 of the L4 header while
    // the smallest non-first offset is 8 bytes, and linux >= 4.19 drops
    // overlapping fragments outright
    if (ip->frag_off & bpf_htons(IP_OFFSET))
    {
        return XDP_PASS;
    }

    // source and destination port sit at the same place in both headers,
    // the UDP header is the shorter one
    const void *l4 = (const void *)ip + (ip->ihl * 4);
    const struct udphdr *udp = l4;
    if ((const void *)(udp + 1) > data_end)
    {
        return XDP_DROP;
    }

    // everything outside the protected ports is not our business
    const __u32 dest_port = bpf_ntohs(udp->dest);
    const __u32 class = l4_proto == IPPROTO_TCP ? tcp_port_class(dest_port) : udp_port_class(dest_port);
    if (class == PORT_UNPROTECTED)
    {
        return XDP_PASS;
    }

    struct packet p = {
        .ctx = ctx,
        .data = data,
        .data_end = data_end,
        .stats = NULL,
        .now = bpf_ktime_get_coarse_ns(),
        .len = (__u64)(data_end - data),
        .l3_offset = l3_offset,
        .flow = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = udp->source,
            .dst_port = udp->dest,
        },
    };

    if (PROMETHEUS)
    {
        __u32 zero = 0;
        p.stats = bpf_map_lookup_elem(&stats_map, &zero);
        if (!p.stats)
        {
            // per-cpu array index 0 always exists, this is unreachable
            return XDP_DROP;
        }
    }
    count_stat(p.stats, STAT_INCOMING_PACKETS, 1);
    count_stat(p.stats, STAT_INCOMING_BYTES, p.len);

    // first fragment of a fragmented packet (MF set, offset 0) aimed at a
    // protected port: the remaining payload is in fragments the filter never
    // sees, so after kernel reassembly the backend would receive uninspected
    // data. Neither TCP (the MSS keeps segments below the MTU) nor RakNet
    // and WebRTC (both split on their own) rely on IP fragmentation.
    // Dropping the first fragment makes reassembly impossible
    if (ip->frag_off & bpf_htons(IP_MF))
    {
        count_stat(p.stats, STAT_FRAGMENT_DROPPED, 1);
        return drop_packet(&p);
    }

    if (l4_proto == IPPROTO_UDP)
    {
        return handle_udp(&p, ip, udp, class);
    }

    const struct tcphdr *tcp = l4;
    if ((const void *)(tcp + 1) > data_end || tcp->doff < 5)
    {
        count_stat(p.stats, STAT_MALFORMED, 1);
        return drop_packet(&p);
    }
    const __u32 tcp_hdr_len = tcp->doff * 4;
    if ((const void *)tcp + tcp_hdr_len > data_end)
    {
        count_stat(p.stats, STAT_MALFORMED, 1);
        return drop_packet(&p);
    }

    return handle_tcp(&p, ip, tcp, tcp_hdr_len, class == PORT_GUARD);
}

// GPL-compatible on purpose: bpf_sk_lookup_tcp() and the clock helpers are
// only available to GPL-compatible programs
char _license[] SEC("license") = "Dual BSD/GPL";
