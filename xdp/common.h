#ifndef COMMON_H
#define COMMON_H

#include <linux/types.h>

// compiler barrier: prevents clang from merging or reordering the pointer
// arithmetic around bounds checks, which would make the verifier lose track
// of the checked range
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

// maximum amount of out-of-order/retransmitted packets before a tracked
// connection is dropped entirely
#define MAX_OUT_OF_ORDER 4

// big endian constants for comparing against raw packet bytes
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define CONST_BE16(x) ((__u16)__builtin_bswap16(x))
#define CONST_BE32(x) ((__u32)__builtin_bswap32(x))
#define CONST_BE64(x) ((__u64)__builtin_bswap64(x))
#else
#define CONST_BE16(x) ((__u16)(x))
#define CONST_BE32(x) ((__u32)(x))
#define CONST_BE64(x) ((__u64)(x))
#endif

/*
 * Connection states stored in initial_state.state, plus pseudo states only
 * returned by inspect_handshake() (RECEIVED_LEGACY_PING and the DIRECT_READ_*
 * values, which signal that more protocol data follows in the same packet).
 * STATE_INVALID doubles as the generic "parse failed" return value of all
 * inspectors.
 */
enum connection_state
{
    STATE_INVALID = 0,
    AWAIT_ACK = 1,
    AWAIT_MC_HANDSHAKE = 2, // first payload: Java handshake, or TLS/HTTP on guard ports
    RECEIVED_LEGACY_PING = 3, // this connection will be fully dropped
    AWAIT_STATUS_REQUEST = 4,
    AWAIT_LOGIN = 5,
    AWAIT_PING = 6,
    PING_COMPLETE = 7,
    DIRECT_READ_STATUS_REQUEST = 8,
    DIRECT_READ_LOGIN = 9,
};

/*
 * Bounds-check macros.
 *
 * All of them bail out of the CALLING function with `return 0` when the
 * requested bytes are not fully inside both the L4 payload (pend) and the
 * packet (dend). Checking against both bounds with a barrier in between is
 * what convinces the verifier that every later access is safe.
 */

// checks that [ptr, ptr + n) is in bounds; does NOT advance ptr
#define CHECK_BOUNDS_OR_RETURN(ptr, n, pend, dend)        \
    do                                                    \
    {                                                     \
        if ((void *)(ptr) + (n) > (const void *)(dend))   \
            return 0;                                     \
        barrier_var(ptr);                                 \
        if ((void *)(ptr) + (n) > (const void *)(pend))   \
            return 0;                                     \
        barrier_var(ptr);                                 \
    } while (0)

// checks that [ptr, ptr + n) is in bounds and advances ptr past those bytes
#define SKIP_OR_RETURN(ptr, n, pend, dend)                \
    do                                                    \
    {                                                     \
        CHECK_BOUNDS_OR_RETURN(ptr, n, pend, dend);       \
        (ptr) += (n);                                     \
    } while (0)

/*
 * Skips a number of bytes that was read from the packet and range-checked
 * by the caller before.
 *
 * The verifier has to know the bound of what is added to the cursor, but it
 * loses a range check whenever the compiler keeps the checked value in a
 * different register or on the stack. Masking a copy the compiler can not
 * see through gives the verifier a bound that always survives. `mask` has to
 * cover the checked maximum, so it changes nothing for any value that passed
 * the check.
 */
#define SKIP_CHECKED_OR_RETURN(ptr, len, mask, pend, dend)  \
    do                                                      \
    {                                                       \
        __u32 _skip = (__u32)(len);                         \
        barrier_var(_skip);                                 \
        _skip &= (mask);                                    \
        SKIP_OR_RETURN(ptr, _skip, pend, dend);             \
    } while (0)

// reads a fixed-size value into dest and advances ptr past it
#define READ_VAL_OR_RETURN(dest, ptr, pend, dend)               \
    do                                                          \
    {                                                           \
        CHECK_BOUNDS_OR_RETURN(ptr, sizeof(dest), pend, dend);  \
        (dest) = *(const __typeof__(dest) *)(ptr);              \
        (ptr) += sizeof(dest);                                  \
    } while (0)

// returns 0 from the calling function if the condition does not hold
#define ASSERT_OR_RETURN(cond) \
    do                         \
    {                          \
        if (!(cond))           \
            return 0;          \
    } while (0)

// returns 0 from the calling function if val is not in [min, max]
#define ASSERT_IN_RANGE_OR_RETURN(val, min, max) \
    do                                           \
    {                                            \
        if ((val) < (min) || (val) > (max))      \
            return 0;                            \
    } while (0)

// key identifying one TCP or UDP flow (all fields in network byte order)
struct ipv4_flow_key
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};
_Static_assert(sizeof(struct ipv4_flow_key) == 12, "ipv4_flow_key size mismatch!");

// per-connection tracking data while the handshake sequence is inspected
struct initial_state
{
    __u16 state;    // enum connection_state; u16 to keep the struct padding-free
    __u16 fails;    // out-of-order packets seen so far (see MAX_OUT_OF_ORDER)
    __s32 protocol; // minecraft protocol version (signed by protocol definition)
    __u32 expected_sequence;
};
_Static_assert(sizeof(struct initial_state) == 12, "initial_state size mismatch!");

static __always_inline struct initial_state gen_initial_state(const __u16 state, const __s32 protocol, const __u32 expected_sequence)
{
    struct initial_state new_state = {
        .state = state,
        .fails = 0,
        .protocol = protocol,
        .expected_sequence = expected_sequence,
    };
    return new_state;
}

/*
 * What a verified flow is, stored in flow_entry.kind. Only flows that proved
 * to be a real game client (Java login, RakNet session) can earn their source
 * ip the "good" mark, see ip_state.good_until.
 */
enum flow_kind
{
    FLOW_JAVA = 1,    // Java connection that passed handshake + login inspection
    FLOW_GUARD = 2,   // generic TCP guard connection (TLS / HTTP)
    FLOW_RAKNET = 3,  // RakNet session that passed OpenConnectionRequest 1 + 2
    FLOW_ICE = 4,     // WebRTC session opened by a STUN binding request
    FLOW_ADOPTED = 5, // existed before the filter was attached
    FLOW_UDP_GUARD = 6, // generic UDP guard session
};

/*
 * A verified TCP connection or UDP session. Its packets skip inspection and
 * only pay for this entry: a one second packet window that doubles as the
 * last-seen timestamp of the lazy idle expiry (no timers, the entry is
 * dropped by the first packet that finds it expired; the LRU map recycles
 * entries nobody looks at anymore).
 */
struct flow_entry
{
    __u64 win_start;  // ktime the current one second window started
    __u64 created;    // ktime the flow was verified
    __u32 win_pkts;   // packets within the current window
    __u8 kind;        // enum flow_kind
    __u8 good_marked; // the source ip already got its good mark from this flow
    __u16 pad;
};
_Static_assert(sizeof(struct flow_entry) == 24, "flow_entry size mismatch!");

// a RakNet client between OpenConnectionRequest1 and OpenConnectionRequest2
struct udp_pending
{
    __u64 created;
    __u32 requests; // OpenConnectionRequest1 datagrams seen (MTU probing resends them)
    __u32 pad;
};
_Static_assert(sizeof(struct udp_pending) == 16, "udp_pending size mismatch!");

/*
 * "Openers": packets asking the server to create new state. Each kind has a
 * per source ip limit (ip_state.hits) and a per cpu budget (cpu_state.used).
 */
enum opener_kind
{
    OPEN_SYN = 0,     // TCP SYN
    OPEN_STATUS = 1,  // Java status (server list) handshake
    OPEN_PING = 2,    // RakNet unconnected ping
    OPEN_UDP = 3,     // new UDP session (OpenConnectionRequest1 / first STUN)
    OPEN_LOGIN = 4,   // Java login handshake (budget only, no per ip counter)
    OPEN_KINDS = 5,
};
#define IP_HIT_KINDS 4

/*
 * Per source ip state. An ip is "known" as soon as it has an entry; unknown
 * ips have to pass the retransmit challenge while it is active.
 *
 * The counters share one lazily reset window of LIMIT_WINDOW_NS (no timers:
 * the first packet that sees an expired window resets it, and the LRU map
 * recycles idle ips on its own).
 */
struct ip_state
{
    __u64 window_start;       // ktime the current window started
    __u64 good_until;         // ktime until which this ip counts as a proven player
    __u32 hits[IP_HIT_KINDS]; // openers within the window, by enum opener_kind
};
_Static_assert(sizeof(struct ip_state) == 32, "ip_state size mismatch!");

/*
 * Per cpu state, reset lazily every second: how many openers from unproven
 * ips this cpu let through (the budgets) and how many came from unknown ips
 * (which arms the retransmit challenge).
 */
struct cpu_state
{
    __u64 sec_start;        // ktime the current second started
    __u64 challenge_until;  // retransmit challenge is active until this ktime
    __u32 unknown;          // openers from unknown ips within this second
    __u32 used[OPEN_KINDS]; // budget spent within this second, by enum opener_kind
};
_Static_assert(sizeof(struct cpu_state) == 40, "cpu_state size mismatch!");

/*
 * The answer to a RakNet unconnected ping, kept fresh by the loader (it
 * pings the real server every few seconds). `data` is the pong after its
 * first 9 bytes (id and the echoed ping time): server guid, magic, MOTD.
 */
#define PONG_MAX 512
#define PONG_MIN (8 + 16 + 2) // guid, magic, length of an empty MOTD

struct pong_cache
{
    __u64 updated; // ktime of the last refresh
    __u32 len;     // bytes used in data
    __u32 pad;
    __u8 data[PONG_MAX];
};
_Static_assert(sizeof(struct pong_cache) == 16 + PONG_MAX, "pong_cache size mismatch!");

// values of deny_v4 that mark a ban without an end; every other value is
// the ktime at which the ban expires
#define DENY_CONFIG 0  // listed in the config file, replaced on every start
#define DENY_RUNTIME 1 // added while running, kept until it is removed

// IPv4 key of the allow/deny LPM tries (prefixlen first, as the kernel wants)
struct lpm_v4_key
{
    __u32 prefixlen;
    __u32 addr; // network byte order
};
_Static_assert(sizeof(struct lpm_v4_key) == 8, "lpm_v4_key size mismatch!");

// IPv6 key of the allow/deny LPM tries
struct lpm_v6_key
{
    __u32 prefixlen;
    __u8 addr[16];
};
_Static_assert(sizeof(struct lpm_v6_key) == 20, "lpm_v6_key size mismatch!");

// what happens to IPv6 packets aimed at a protected port (IPV6_MODE)
#define IPV6_PASS 0    // not looked at
#define IPV6_DROP 1    // dropped, so IPv6 is no way around the filter
#define IPV6_INSPECT 2 // inspected like IPv4

/*
 * Retransmit challenge table: every slot of the retry_table array holds two
 * entries of 32 bits, each a 16 bit fingerprint and a 16 bit timestamp in
 * RETRY_TICK units. An opener from an unknown ip is only let through when
 * the very same packet was already seen RETRY_MIN_TICKS..RETRY_MAX_TICKS
 * ago: real clients retransmit (TCP SYN after 1s, RakNet and ICE after
 * ~0.5s), spoofed floods with random sources never do.
 *
 * Returns 1 when `hash` is such a retransmit (and consumes the entry),
 * otherwise records the sighting and returns 0. Races between cpus can at
 * worst lose a sighting, costing the client one more retransmit.
 */
#define RETRY_TICK_SHIFT 26 // 2^26 ns = ~67ms per tick, 16 bits wrap after ~73 minutes

static __always_inline __u8 retry_table_check(__u64 *slot, const __u64 hash, const __u64 now, const __u32 min_ticks, const __u32 max_ticks)
{
    const __u32 fp = (__u32)((hash >> 48) & 0xFFFF) | 1; // never 0, so an empty entry never matches
    const __u32 tick = (__u32)(now >> RETRY_TICK_SHIFT) & 0xFFFF;
    const __u32 fresh = (fp << 16) | tick;

    const __u64 value = *slot;
    const __u32 e0 = (__u32)value;
    const __u32 e1 = (__u32)(value >> 32);
    const __u32 age0 = (tick - e0) & 0xFFFF;
    const __u32 age1 = (tick - e1) & 0xFFFF;

    if ((e0 >> 16) == fp)
    {
        if (age0 < min_ticks)
        {
            return 0; // duplicate sent right away: keep the first sighting
        }
        if (age0 <= max_ticks)
        {
            *slot = value & 0xFFFFFFFF00000000ULL;
            return 1;
        }
        *slot = (value & 0xFFFFFFFF00000000ULL) | fresh; // stale, start over
        return 0;
    }
    if ((e1 >> 16) == fp)
    {
        if (age1 < min_ticks)
        {
            return 0;
        }
        if (age1 <= max_ticks)
        {
            *slot = value & 0x00000000FFFFFFFFULL;
            return 1;
        }
        *slot = (value & 0x00000000FFFFFFFFULL) | ((__u64)fresh << 32);
        return 0;
    }

    // first sighting: take the empty entry, else replace the older one
    if (e0 == 0 || (e1 != 0 && age0 >= age1))
    {
        *slot = (value & 0xFFFFFFFF00000000ULL) | fresh;
    }
    else
    {
        *slot = (value & 0x00000000FFFFFFFFULL) | ((__u64)fresh << 32);
    }
    return 0;
}

// 64 bit finalizer of MurmurHash3, used to spread flow tuples over the retry table
static __always_inline __u64 mix64(__u64 x)
{
    x ^= x >> 33;
    x *= 0xFF51AFD7ED558CCDULL;
    x ^= x >> 33;
    x *= 0xC4CEB9FE1A85EC53ULL;
    x ^= x >> 33;
    return x;
}

#endif
