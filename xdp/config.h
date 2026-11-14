#ifndef CONFIG_H
#define CONFIG_H

#include <linux/types.h>

/*
 * Runtime configuration.
 *
 * The Rust loader patches these values into the BPF .rodata section via
 * aya's override_global() (with must_exist) before the program is loaded, so
 * all of them are always overridden; the zeros are only placeholders. The
 * types must match the override_global() calls in loader/ebpf.rs exactly.
 * Loaded standalone (without the loader), the all-zero config filters nothing.
 *
 * Because the values live in .rodata the verifier knows them at load time and
 * prunes every disabled feature as dead code, so an unused protection costs
 * nothing per packet.
 *
 * Defining (not just declaring) these in a header is safe because the BPF
 * program is a single translation unit; the native test build replaces this
 * header entirely via its include guard.
 *
 * All *_BUDGET values are per cpu and per second, and only spent by source
 * ips without the "good" mark; 0 means unlimited. All *_HITS values are per
 * source ip and per LIMIT_WINDOW_NS; 0 means unlimited.
 */

/* --- general --------------------------------------------------------- */
volatile const __u8 PROMETHEUS = 0;        // collect statistics in stats_map
volatile const __u8 IPV6_PROTECT = 0;      // drop IPv6 traffic aimed at any protected port
volatile const __u8 HAS_ALLOW = 0;         // allow_v4 has entries
volatile const __u8 HAS_DENY = 0;          // deny_v4 has entries
volatile const __u64 LIMIT_WINDOW_NS = 0;  // length of the per ip rate limit window

/* --- flows that existed before the filter was attached ---------------- */
volatile const __u8 ADOPT_MODE = 0;        // 0 off, 1 TCP only if the kernel has the socket, 2 blind
volatile const __u64 ADOPT_UNTIL_NS = 0;   // ktime until which unknown flows are adopted

/* --- Minecraft Java (TCP) -------------------------------------------- */
volatile const __u32 JAVA_START_PORT = 0;  // first TCP port of the Java range (inclusive), 0 = off
volatile const __u32 JAVA_END_PORT = 0;    // last TCP port of the Java range (inclusive)
volatile const __u8 ONLINE_NAMES = 0;      // enforce online-mode usernames (max 16 chars)
volatile const __u8 HOST_FILTER = 0;       // handshake host must be listed in allowed_hosts
volatile const __s32 JAVA_PROTO_MIN = 0;   // lowest protocol version allowed to log in, 0 = any
volatile const __s32 JAVA_PROTO_MAX = 0;   // highest protocol version allowed to log in, 0 = any
volatile const __u32 STATUS_HITS = 0;      // status (server list) requests per ip
volatile const __u32 STATUS_BUDGET = 0;    // status requests per cpu
volatile const __u32 LOGIN_BUDGET = 0;     // login attempts per cpu

/* --- generic TCP guard (e.g. NetherNet signaling) ---------------------- */
volatile const __u32 GUARD_START_PORT = 0; // 0 = off
volatile const __u32 GUARD_END_PORT = 0;
volatile const __u8 GUARD_TLS = 0;         // first payload may be a TLS ClientHello
volatile const __u8 GUARD_HTTP = 0;        // first payload may be a plain HTTP request

/* --- shared by all TCP ports ----------------------------------------- */
volatile const __u32 SYN_HITS = 0;         // SYNs per ip
volatile const __u32 SYN_BUDGET = 0;       // SYNs per cpu
volatile const __u32 TCP_FLOW_PPS = 0;     // packets per second of one verified connection, 0 = unlimited
volatile const __u64 TCP_IDLE_NS = 0;      // verified connections expire after this long without packets

/* --- Bedrock RakNet (UDP) -------------------------------------------- */
volatile const __u32 RAKNET_START_PORT = 0; // 0 = off
volatile const __u32 RAKNET_END_PORT = 0;
volatile const __u32 RAKNET_PROTO_MIN = 0; // accepted RakNet protocol versions in OpenConnectionRequest1
volatile const __u32 RAKNET_PROTO_MAX = 0;
volatile const __u32 RAKNET_OCR1_MIN = 0;  // minimum UDP payload of OpenConnectionRequest1 (clients pad it to the MTU)
volatile const __u32 PING_HITS = 0;        // unconnected pings per ip
volatile const __u32 PING_BUDGET = 0;      // unconnected pings per cpu

/* --- NetherNet WebRTC (UDP ICE: STUN + DTLS) -------------------------- */
volatile const __u32 ICE_START_PORT = 0;   // 0 = off
volatile const __u32 ICE_END_PORT = 0;

/* --- shared by all UDP ports ----------------------------------------- */
volatile const __u32 UDP_OPEN_HITS = 0;    // new UDP sessions per ip
volatile const __u32 UDP_OPEN_BUDGET = 0;  // new UDP sessions per cpu
volatile const __u32 UDP_FLOW_PPS = 0;     // packets per second of one verified session, 0 = unlimited
volatile const __u64 UDP_IDLE_NS = 0;      // verified sessions expire after this long without packets

/* --- retransmit challenge for unknown source ips ----------------------- */
volatile const __u8 CHALLENGE_MODE = 0;      // 0 off, 1 only while a cpu sees a flood of unknown ips, 2 always
volatile const __u32 CHALLENGE_PPS = 0;      // openers from unknown ips per cpu and second that arm the challenge
volatile const __u64 CHALLENGE_HOLD_NS = 0;  // how long the challenge stays armed after the last trigger
volatile const __u32 RETRY_MASK = 0;         // slots of retry_table - 1 (power of two)
volatile const __u32 RETRY_MIN_TICKS = 0;    // a retransmit is accepted this many ticks after the first sighting ...
volatile const __u32 RETRY_MAX_TICKS = 0;    // ... and no later than this
volatile const __u64 RETRY_SEED = 0;         // random per load, keeps table slots unpredictable

/* --- proven players ---------------------------------------------------- */
volatile const __u64 GOOD_AFTER_NS = 0;    // a game flow has to live this long to mark its ip good, 0 = never
volatile const __u64 GOOD_TTL_NS = 0;      // how long the good mark lasts

#endif
