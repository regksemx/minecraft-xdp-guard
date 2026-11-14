#ifndef STATS_H
#define STATS_H

#include <linux/types.h>

#include "config.h"

/*
 * Statistics counters, one per-cpu slot of stats_map.
 *
 * The order MUST match the `statistics!` list in loader/metrics.rs, which
 * mirrors this enum entry by entry (the loader refuses to start when the map
 * value size differs). Append new counters at the end, before STAT_COUNT.
 */
enum stat_id
{
    STAT_INCOMING_PACKETS = 0, // packets aimed at a protected port
    STAT_INCOMING_BYTES,
    STAT_DROPPED_PACKETS,
    STAT_DROPPED_BYTES,

    STAT_DENYLIST,          // dropped by the deny list
    STAT_ALLOWLIST,         // passed by the allow list without inspection
    STAT_IPV6_DROPPED,      // IPv6 aimed at a protected port
    STAT_FRAGMENT_DROPPED,  // first fragment aimed at a protected port
    STAT_MALFORMED,         // broken L4 headers / lengths

    STAT_NEW_IP,            // source ips that became known
    STAT_CHALLENGE_DROPPED, // openers of unknown ips dropped by the retransmit challenge
    STAT_CHALLENGE_PASSED,  // retransmits that passed it
    STAT_GOOD_IP,           // source ips marked as proven players
    STAT_TABLE_FULL,        // a map insert failed

    STAT_TCP_SYN,
    STAT_TCP_BYPASS,        // impossible flag combinations, SYN with payload
    STAT_SYN_THROTTLED,     // per ip SYN limit
    STAT_TCP_BUDGET_DROPPED, // per cpu SYN / status / login budget exhausted
    STAT_TCP_UNTRACKED,     // non-SYN packet of a flow we never saw (ACK floods)
    STAT_TCP_ADOPTED,       // connection from before the filter was attached
    STAT_TCP_RATE_LIMITED,  // verified connection above its packet rate
    STAT_STATE_SWITCH,
    STAT_DROP_CONNECTION,

    STAT_JAVA_VERIFIED,     // logins that passed inspection
    STAT_JAVA_STATUS,       // status handshakes passed
    STAT_STATUS_THROTTLED,  // per ip status limit
    STAT_JAVA_BAD_HOST,     // handshake host not in allowed_hosts
    STAT_JAVA_BAD_PROTO,    // login with a protocol version outside the allowed range
    STAT_JAVA_INVALID,      // handshake / login / status packet failed inspection
    STAT_GUARD_VERIFIED,    // generic TCP guard connections verified
    STAT_GUARD_INVALID,

    STAT_RAKNET_PING,       // unconnected pings passed
    STAT_PING_THROTTLED,    // per ip ping limit
    STAT_RAKNET_OPEN,       // OpenConnectionRequest1 accepted
    STAT_RAKNET_VERIFIED,   // OpenConnectionRequest2 accepted, session verified
    STAT_RAKNET_INVALID,
    STAT_ICE_VERIFIED,
    STAT_ICE_INVALID,
    STAT_UDP_OPEN_THROTTLED, // per ip new session limit
    STAT_UDP_BUDGET_DROPPED, // per cpu ping / session budget exhausted
    STAT_UDP_UNTRACKED,     // datagram of a session we never saw
    STAT_UDP_ADOPTED,       // session from before the filter was attached
    STAT_UDP_RATE_LIMITED,  // verified session above its packet rate

    STAT_COUNT
};

struct statistics
{
    __u64 counters[STAT_COUNT];
};
_Static_assert(sizeof(struct statistics) == STAT_COUNT * 8, "statistics size mismatch!");

/*
 * stats_ptr is NULL whenever PROMETHEUS is 0 (the filter only looks it up
 * when enabled). Since PROMETHEUS lives in .rodata, the verifier knows its
 * value at load time and removes the whole body as dead code when disabled.
 */
static __always_inline void count_stat(struct statistics *stats_ptr, const enum stat_id id, const __u64 amount)
{
    if (!PROMETHEUS || !stats_ptr)
    {
        return;
    }
    stats_ptr->counters[id] += amount;
}

#endif
