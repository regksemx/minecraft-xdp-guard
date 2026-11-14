use anyhow::{Context, Result, bail};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::hosts;

/// Default configuration file written on first run, with documentation for
/// every option. Mirrors [`Config::default`].
pub const DEFAULT_CONFIG_TOML: &str = r#"# Minecraft XDP filter configuration.
# This file is applied at load time; restart the loader after editing.
# Every option is listed with its default value.
#
# A port range with start_port = 0 switches that protection off. Ranges are
# inclusive; use the same value twice to protect a single port.

[java]
# Minecraft Java Edition (TCP). Every connection has to send a valid
# handshake followed by either status + ping or a login.
start_port = 25565
end_port = 25565

# Enforce online-mode username rules during login inspection.
# true  -> usernames are limited to 16 characters (Mojang online mode).
# false -> allow the protocol maximum (offline / cracked servers).
online_names = true

# Host names players may connect with (the address they typed, or the target
# of your SRV record). Handshakes for any other host are dropped, which stops
# bots that scan or attack the bare IP address. Not case sensitive; list the
# IP address too if players may use it. Empty = any host is accepted.
# hosts = ["mc.example.com", "play.example.com"]
hosts = []

# Protocol versions allowed to log in (0 = no bound), e.g. protocol_min = 754
# refuses clients older than 1.16.5. Server list pings are never restricted.
protocol_min = 0
protocol_max = 0

[tcp_guard]
# Generic guard for other TCP services where the client talks first, e.g.
# the NetherNet signaling port of Bedrock (TLS / HTTP on TCP 19132): only
# clients whose first payload opens one of the allowed protocols get through.
start_port = 0
end_port = 0
allow_tls = true
allow_http = true

[bedrock]
# Minecraft Bedrock Edition (RakNet over UDP), usually port 19132. A session
# has to open with OpenConnectionRequest 1 and 2; only then game traffic is
# accepted from that address.
start_port = 0
end_port = 0

# RakNet protocol versions accepted in OpenConnectionRequest1.
raknet_protocol_min = 9
raknet_protocol_max = 11

# Minimum size of OpenConnectionRequest1 in bytes. Clients pad it to the MTU
# they probe (at least 548 bytes); floods usually send it bare.
open_request_min_size = 400

# Answer server list pings from the filter itself. The loader asks the real
# server at this address every pong_refresh_secs seconds, and the filter
# replies to players with that answer, so pings (and ping floods) never
# reach the server; the player count in the list is at most that old. Use an
# address the loader can reach without passing the filter, e.g.
# "127.0.0.1:19132". Needs kernel 5.18. Empty = off.
pong_from = ""
pong_refresh_secs = 5

[nethernet]
# NetherNet / WebRTC data channels of Bedrock (UDP). A session has to open
# with a STUN binding request; afterwards only STUN and DTLS are accepted.
ice_start_port = 0
ice_end_port = 0

[udp_guard]
# Generic guard for other UDP services, e.g. a voice chat. There is no
# handshake the filter could follow, so it only checks every datagram (a
# minimum size and, optionally, a fixed first byte) and applies the limits:
# new sessions per IP, the session budget, the challenge for unknown IPs and
# udp_flow_pps per session.
start_port = 0
end_port = 0
# Every datagram has to start with this byte (0-255); -1 = any.
first_byte = -1
# Minimum payload size of every datagram in bytes.
min_size = 1

[limits]
# Limits per source IP, counted within windows of window_secs seconds.
# 0 switches a limit off.
window_secs = 3

# New TCP connections (SYNs).
syn_per_ip = 10
# Java status requests (server list pings).
status_per_ip = 10
# Bedrock unconnected pings (server list pings).
pings_per_ip = 20
# New Bedrock / NetherNet sessions.
udp_sessions_per_ip = 8

# Verified connections are forgotten after this many seconds without a
# packet; the client then has to connect again. Must be between 2 and 86400.
tcp_idle_secs = 60
udp_idle_secs = 30

# Packets per second one verified connection may send (0 = unlimited). A
# player sends a few hundred at most; anything above is dropped.
tcp_flow_pps = 0
udp_flow_pps = 0

[attack]
# Retransmit challenge for source IPs the filter has never seen: their first
# connection attempt is dropped and only its retransmit is let through. Real
# clients retransmit by themselves (TCP after 1s, Bedrock after ~0.5s), so
# all they notice is a slightly slower first connect; spoofed floods never
# retransmit and are dropped for the cost of one array access per packet.
# "auto"   -> only while more than challenge_new_ips_per_sec unknown IPs
#             per second show up. Recommended.
# "always" -> every unknown IP, all the time.
# "off"    -> never.
challenge = "auto"
challenge_new_ips_per_sec = 400
# How long the challenge stays active after the flood ended.
challenge_hold_secs = 30
# A retransmit is accepted this long after the first attempt.
retry_min_ms = 200
retry_max_ms = 10000
# Slots of the challenge table (power of two, 8 bytes each). A flood keeps
# overwriting the table, and a newcomer only gets in if his entry survives
# until he retransmits. At 1.5 million spoofed packets per second (a
# saturated 1 Gbit/s port) about half of the newcomers get in on their first
# retransmit with 1048576 slots, 19 of 20 with 4194304 and practically all
# with 16777216 (128 MiB); the others need one more retransmit.
retry_table_slots = 1048576

# Budgets: how much new work per second the server accepts from IPs that are
# not proven players, in total. 0 = unlimited. Whatever exceeds a budget is
# dropped before it reaches the server, so a bot flood can not take more than
# the budget away from it.
syn_budget = 0
login_budget = 0
status_budget = 0
ping_budget = 0
udp_session_budget = 0

# An IP becomes a proven player once one of its game connections lived for
# good_after_secs (0 = never). Proven players are not subject to the budgets
# above, so they can always reconnect during an attack.
good_after_secs = 180
good_ttl_hours = 72

[lists]
# Addresses or networks ("203.0.113.7", "198.51.100.0/24", "2001:db8::/48").
# allow: never inspected or limited on the protected ports (monitoring,
#        your own proxies). deny: always dropped on the protected ports.
# Bans can also be added while the filter runs, see `xdp-loader deny --help`.
allow = []
deny = []

[xdp]
# How the filter attaches to the network interface.
# "auto"   -> native driver mode if the NIC supports XDP, with automatic
#             fallback to generic mode otherwise. Recommended.
# "driver" -> force native driver mode: fastest, but fails on NICs without
#             XDP support (including most virtual machines).
# "skb"    -> force generic (skb) mode: works on any interface but is
#             slower; use it when the driver misbehaves in native mode.
mode = "auto"

# What happens to IPv6 packets for the protected ports.
# "pass"    -> the filter ignores IPv6. Only safe if the protected services
#              are not reachable over IPv6, otherwise it is a way around.
# "drop"    -> they are dropped.
# "inspect" -> they are inspected and limited exactly like IPv4. The limits
#              per IP count per /64 network. Bedrock pings over IPv6 are
#              always answered by the server (see pong_from).
ipv6 = "pass"

# The tables of verified connections, known IPs and bans are pinned in
# state_dir while the loader runs. With keep_state they stay there (and keep
# their memory) after it exits, so that restarting the loader does not
# disconnect anyone; run the loader with --reset-state to forget connections
# and known IPs. Without keep_state everything is removed on exit.
# The attachment to the interface is pinned there as well: SIGUSR1 stops the
# loader but leaves the filter running, and the next start replaces it
# without a gap.
keep_state = true
state_dir = "/sys/fs/bpf/minecraft-xdp"

# Connections that already existed when the filter was attached (first start,
# or the gap during a restart) are unknown to it. For adopt_secs seconds
# after the start such connections are adopted instead of dropped.
# "socket" -> TCP only if the kernel of this machine has that connection
#             (the server or proxy runs on this host, not in a container
#             behind NAT). UDP sessions are adopted if they look valid.
# "blind"  -> everything that looks like an established connection.
# "off"    -> nothing; players connected at that moment have to reconnect.
adopt = "socket"
adopt_secs = 30

# Sizes of the in-kernel tables below. The maps are preallocated, so higher
# limits cost kernel memory up front, not per connection. When a table is
# full its least recently used entry is replaced.

# TCP connections that have not finished inspection yet.
max_pending_connections = 16384
# Verified TCP connections; keep it well above the expected player count.
max_player_connections = 65536
# Bedrock clients between their two connection requests.
max_pending_udp_sessions = 16384
# Verified Bedrock / NetherNet sessions.
max_udp_sessions = 65536
# Source IPs with rate limit counters and the proven player mark.
max_tracked_ips = 262144

[metrics]
# Collect packet statistics inside the eBPF program. Required for any metrics
# output. Adds a small per-packet cost, so it is disabled by default.
enabled = false

# Address to expose Prometheus metrics on (only used when enabled = true).
# Leave commented out to collect stats without starting the HTTP server.
# The endpoint has no authentication, so only bind to a public address
# (e.g. "0.0.0.0:1999") if you really want it reachable from outside.
# addr = "127.0.0.1:1999"

# How often the in-kernel statistics are read and published, in seconds.
poll_secs = 10

[logging]
# Verbosity of console and file logging:
# "off", "error", "warn", "info", "debug" or "trace".
# The RUST_LOG environment variable overrides this setting at runtime.
level = "info"

# The log file (xdp-loader.log) is rotated once it grows past this many
# megabytes; the 5 most recent rotated files are kept.
file_max_mb = 100
"#;

/// Runtime configuration for the XDP filter, grouped like the TOML file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub java: JavaConfig,
    pub tcp_guard: TcpGuardConfig,
    pub bedrock: BedrockConfig,
    pub nethernet: NetherNetConfig,
    pub udp_guard: UdpGuardConfig,
    pub limits: LimitsConfig,
    pub attack: AttackConfig,
    pub lists: ListsConfig,
    pub xdp: XdpConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
}

/// `[java]` — Minecraft Java Edition (TCP).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JavaConfig {
    /// First port of the inclusive range, 0 = off. Maps to `JAVA_START_PORT`.
    pub start_port: u16,
    /// Last port of the inclusive range. Maps to `JAVA_END_PORT`.
    pub end_port: u16,
    /// Enforce online-mode (<= 16 char) usernames. Maps to `ONLINE_NAMES`.
    pub online_names: bool,
    /// Host names accepted in the handshake; empty = any. Fills the
    /// `allowed_hosts` map and sets `HOST_FILTER`.
    pub hosts: Vec<String>,
    /// Lowest protocol version allowed to log in, 0 = any. Maps to `JAVA_PROTO_MIN`.
    pub protocol_min: i32,
    /// Highest protocol version allowed to log in, 0 = any. Maps to `JAVA_PROTO_MAX`.
    pub protocol_max: i32,
}

impl Default for JavaConfig {
    fn default() -> Self {
        Self {
            start_port: 25565,
            end_port: 25565,
            online_names: true,
            hosts: Vec::new(),
            protocol_min: 0,
            protocol_max: 0,
        }
    }
}

/// `[tcp_guard]` — generic guard for client-speaks-first TCP services.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpGuardConfig {
    /// First port of the inclusive range, 0 = off. Maps to `GUARD_START_PORT`.
    pub start_port: u16,
    /// Last port of the inclusive range. Maps to `GUARD_END_PORT`.
    pub end_port: u16,
    /// Accept a TLS ClientHello as first payload. Maps to `GUARD_TLS`.
    pub allow_tls: bool,
    /// Accept a plain HTTP request as first payload. Maps to `GUARD_HTTP`.
    pub allow_http: bool,
}

impl Default for TcpGuardConfig {
    fn default() -> Self {
        Self {
            start_port: 0,
            end_port: 0,
            allow_tls: true,
            allow_http: true,
        }
    }
}

/// `[bedrock]` — Minecraft Bedrock Edition (RakNet over UDP).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BedrockConfig {
    /// First port of the inclusive range, 0 = off. Maps to `RAKNET_START_PORT`.
    pub start_port: u16,
    /// Last port of the inclusive range. Maps to `RAKNET_END_PORT`.
    pub end_port: u16,
    /// Lowest accepted RakNet protocol version. Maps to `RAKNET_PROTO_MIN`.
    pub raknet_protocol_min: u8,
    /// Highest accepted RakNet protocol version. Maps to `RAKNET_PROTO_MAX`.
    pub raknet_protocol_max: u8,
    /// Minimum size of OpenConnectionRequest1. Maps to `RAKNET_OCR1_MIN`.
    pub open_request_min_size: u32,
    /// Address of the real server whose pong the filter replays, empty =
    /// off. Sets `PONG_REPLY`.
    pub pong_from: String,
    /// Seconds between refreshes of that pong. Sets `PONG_MAX_AGE_NS`.
    pub pong_refresh_secs: u64,
}

impl Default for BedrockConfig {
    fn default() -> Self {
        Self {
            start_port: 0,
            end_port: 0,
            raknet_protocol_min: 9,
            raknet_protocol_max: 11,
            open_request_min_size: 400,
            pong_from: String::new(),
            pong_refresh_secs: 5,
        }
    }
}

/// `[nethernet]` — NetherNet WebRTC data channels (UDP).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetherNetConfig {
    /// First ICE port of the inclusive range, 0 = off. Maps to `ICE_START_PORT`.
    pub ice_start_port: u16,
    /// Last ICE port of the inclusive range. Maps to `ICE_END_PORT`.
    pub ice_end_port: u16,
}

/// `[udp_guard]` — generic guard for UDP services without a handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UdpGuardConfig {
    /// First port of the inclusive range, 0 = off. Maps to `UDPGUARD_START_PORT`.
    pub start_port: u16,
    /// Last port of the inclusive range. Maps to `UDPGUARD_END_PORT`.
    pub end_port: u16,
    /// Required first byte of every datagram, -1 = any. Maps to `UDPGUARD_FIRST_BYTE`.
    pub first_byte: i32,
    /// Minimum payload size of every datagram. Maps to `UDPGUARD_MIN_LEN`.
    pub min_size: u32,
}

impl Default for UdpGuardConfig {
    fn default() -> Self {
        Self {
            start_port: 0,
            end_port: 0,
            first_byte: -1,
            min_size: 1,
        }
    }
}

impl UdpGuardConfig {
    fn validate(&self) -> Result<()> {
        if !(-1..=255).contains(&self.first_byte) {
            bail!(
                "[udp_guard] first_byte must be between 0 and 255, or -1 for any (got {})",
                self.first_byte
            );
        }
        check_range("[udp_guard] min_size", self.min_size as u64, 1, 1472)
    }
}

/// `[limits]` — per source ip limits and the lifetime of verified flows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Length of the per ip window in seconds. Maps to `LIMIT_WINDOW_NS`.
    pub window_secs: u64,
    /// Maps to `SYN_HITS`.
    pub syn_per_ip: u32,
    /// Maps to `STATUS_HITS`.
    pub status_per_ip: u32,
    /// Maps to `PING_HITS`.
    pub pings_per_ip: u32,
    /// Maps to `UDP_OPEN_HITS`.
    pub udp_sessions_per_ip: u32,
    /// Maps to `TCP_IDLE_NS`.
    pub tcp_idle_secs: u64,
    /// Maps to `UDP_IDLE_NS`.
    pub udp_idle_secs: u64,
    /// Maps to `TCP_FLOW_PPS`.
    pub tcp_flow_pps: u32,
    /// Maps to `UDP_FLOW_PPS`.
    pub udp_flow_pps: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            window_secs: 3,
            syn_per_ip: 10,
            status_per_ip: 10,
            pings_per_ip: 20,
            udp_sessions_per_ip: 8,
            tcp_idle_secs: 60,
            udp_idle_secs: 30,
            tcp_flow_pps: 0,
            udp_flow_pps: 0,
        }
    }
}

/// When unknown source ips have to pass the retransmit challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeMode {
    Off,
    Auto,
    Always,
}

/// `[attack]` — what happens while the server is flooded.
///
/// All totals per second are split evenly over the cpus before they are
/// handed to the eBPF program, which keeps its counters per cpu.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttackConfig {
    /// Maps to `CHALLENGE_MODE`.
    pub challenge: ChallengeMode,
    /// Maps to `CHALLENGE_PPS` (per cpu).
    pub challenge_new_ips_per_sec: u32,
    /// Maps to `CHALLENGE_HOLD_NS`.
    pub challenge_hold_secs: u64,
    /// Maps to `RETRY_MIN_TICKS`.
    pub retry_min_ms: u64,
    /// Maps to `RETRY_MAX_TICKS`.
    pub retry_max_ms: u64,
    /// Capacity of `retry_table`, sets `RETRY_MASK`.
    pub retry_table_slots: u32,
    /// Maps to `SYN_BUDGET` (per cpu).
    pub syn_budget: u32,
    /// Maps to `LOGIN_BUDGET` (per cpu).
    pub login_budget: u32,
    /// Maps to `STATUS_BUDGET` (per cpu).
    pub status_budget: u32,
    /// Maps to `PING_BUDGET` (per cpu).
    pub ping_budget: u32,
    /// Maps to `UDP_OPEN_BUDGET` (per cpu).
    pub udp_session_budget: u32,
    /// Maps to `GOOD_AFTER_NS`.
    pub good_after_secs: u64,
    /// Maps to `GOOD_TTL_NS`.
    pub good_ttl_hours: u64,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            challenge: ChallengeMode::Auto,
            challenge_new_ips_per_sec: 400,
            challenge_hold_secs: 30,
            retry_min_ms: 200,
            retry_max_ms: 10_000,
            retry_table_slots: 1 << 20,
            syn_budget: 0,
            login_budget: 0,
            status_budget: 0,
            ping_budget: 0,
            udp_session_budget: 0,
            good_after_secs: 180,
            good_ttl_hours: 72,
        }
    }
}

/// `[lists]` — source networks that bypass or never pass the filter.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListsConfig {
    /// Fills the `allow_v4` map.
    pub allow: Vec<String>,
    /// Fills the `deny_v4` map.
    pub deny: Vec<String>,
}

/// An IPv4 network of the allow/deny lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    /// Network address with the host bits cleared.
    pub addr: Ipv4Addr,
    pub prefix_len: u32,
}

impl Ipv4Net {
    /// Parses `a.b.c.d` or `a.b.c.d/len`; host bits are cleared.
    pub fn parse(text: &str) -> Result<Self> {
        let (addr, prefix_len) = match text.split_once('/') {
            Some((addr, len)) => (
                addr,
                len.trim()
                    .parse::<u32>()
                    .with_context(|| format!("invalid prefix length in '{text}'"))?,
            ),
            None => (text, 32),
        };
        if prefix_len > 32 {
            bail!("prefix length of '{text}' must be between 0 and 32");
        }
        let addr: Ipv4Addr = addr
            .trim()
            .parse()
            .with_context(|| format!("'{text}' is not an IPv4 address or network"))?;
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        Ok(Self {
            addr: Ipv4Addr::from(u32::from(addr) & mask),
            prefix_len,
        })
    }
}

impl Ipv4Net {
    /// Whether `addr` lies inside this network.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        u32::from(addr) & mask == u32::from(self.addr)
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// An IPv6 network of the allow/deny lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Net {
    /// Network address with the host bits cleared.
    pub addr: Ipv6Addr,
    pub prefix_len: u32,
}

impl Ipv6Net {
    /// Parses `a:b::c` or `a:b::/len`; host bits are cleared.
    pub fn parse(text: &str) -> Result<Self> {
        let (addr, prefix_len) = match text.split_once('/') {
            Some((addr, len)) => (
                addr,
                len.trim()
                    .parse::<u32>()
                    .with_context(|| format!("invalid prefix length in '{text}'"))?,
            ),
            None => (text, 128),
        };
        if prefix_len > 128 {
            bail!("prefix length of '{text}' must be between 0 and 128");
        }
        let addr: Ipv6Addr = addr
            .trim()
            .parse()
            .with_context(|| format!("'{text}' is not an IPv6 address or network"))?;
        let mask = if prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - prefix_len)
        };
        Ok(Self {
            addr: Ipv6Addr::from(u128::from(addr) & mask),
            prefix_len,
        })
    }
}

impl fmt::Display for Ipv6Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// A network of the allow/deny lists, of either address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

impl IpNet {
    pub fn parse(text: &str) -> Result<Self> {
        if text.contains(':') {
            Ipv6Net::parse(text).map(IpNet::V6)
        } else {
            Ipv4Net::parse(text).map(IpNet::V4)
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpNet::V4(net) => net.fmt(f),
            IpNet::V6(net) => net.fmt(f),
        }
    }
}

/// Splits a list into its IPv4 and IPv6 networks.
pub fn split_families(nets: &[IpNet]) -> (Vec<Ipv4Net>, Vec<Ipv6Net>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for net in nets {
        match net {
            IpNet::V4(net) => v4.push(*net),
            IpNet::V6(net) => v6.push(*net),
        }
    }
    (v4, v6)
}

impl ListsConfig {
    pub fn allow_nets(&self) -> Result<Vec<IpNet>> {
        self.allow.iter().map(|s| IpNet::parse(s)).collect()
    }

    pub fn deny_nets(&self) -> Result<Vec<IpNet>> {
        self.deny.iter().map(|s| IpNet::parse(s)).collect()
    }
}

/// What happens to IPv6 packets for the protected ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Mode {
    Pass,
    Drop,
    Inspect,
}

/// What to do with flows that existed before the filter was attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdoptMode {
    Off,
    Socket,
    Blind,
}

/// `[xdp]` — how the program attaches, its persistent state and the
/// capacity of its maps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XdpConfig {
    /// XDP attach mode.
    pub mode: ConfigXdpMode,
    /// IPv6 traffic to the protected ports. Maps to `IPV6_MODE`.
    pub ipv6: Ipv6Mode,
    /// Pin the state maps so they survive a restart of the loader.
    pub keep_state: bool,
    /// Directory (on a bpf filesystem) the state maps are pinned in.
    pub state_dir: String,
    /// Maps to `ADOPT_MODE`.
    pub adopt: AdoptMode,
    /// Sets `ADOPT_UNTIL_NS` to this many seconds after the start.
    pub adopt_secs: u64,
    /// Capacity of `pending_tcp`.
    pub max_pending_connections: u32,
    /// Capacity of `verified_tcp`.
    pub max_player_connections: u32,
    /// Capacity of `pending_udp`.
    pub max_pending_udp_sessions: u32,
    /// Capacity of `verified_udp`.
    pub max_udp_sessions: u32,
    /// Capacity of `ip_table`.
    pub max_tracked_ips: u32,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            mode: ConfigXdpMode::Auto,
            ipv6: Ipv6Mode::Pass,
            keep_state: true,
            state_dir: "/sys/fs/bpf/minecraft-xdp".into(),
            adopt: AdoptMode::Socket,
            adopt_secs: 30,
            max_pending_connections: 16384,
            max_player_connections: 65536,
            max_pending_udp_sessions: 16384,
            max_udp_sessions: 65536,
            max_tracked_ips: 262_144,
        }
    }
}

/// XDP attach mode, the `mode` option in `[xdp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigXdpMode {
    /// Native driver mode when the NIC supports it, automatic fallback to
    /// generic mode otherwise.
    Auto,
    /// Force native driver mode, fail when unsupported.
    Driver,
    /// Force generic (skb) mode.
    Skb,
}

impl fmt::Display for ConfigXdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConfigXdpMode::Auto => "auto",
            ConfigXdpMode::Driver => "driver",
            ConfigXdpMode::Skb => "skb",
        })
    }
}

/// `[metrics]` — statistics collection and the Prometheus endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Collect statistics inside the eBPF program. Maps to `PROMETHEUS`.
    pub enabled: bool,
    /// Optional address for the Prometheus HTTP endpoint (e.g. `127.0.0.1:1999`).
    pub addr: Option<String>,
    /// Seconds between reads of the in-kernel statistics map.
    pub poll_secs: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: None,
            poll_secs: 10,
        }
    }
}

/// `[logging]` — console/file log verbosity and rotation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log verbosity, overridable at runtime via the `RUST_LOG` env variable.
    pub level: LogLevel,
    /// Rotate the log file once it grows past this size in megabytes.
    pub file_max_mb: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file_max_mb: 100,
        }
    }
}

/// Log verbosity, the `level` option in `[logging]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

impl Config {
    /// Load the configuration from `path`, creating a documented default file if
    /// it does not exist yet.
    ///
    /// Runs before logging is initialized (the log level lives in here), so the
    /// "wrote defaults" notice goes to stderr directly.
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            eprintln!(
                "Config file '{}' not found, writing documented defaults",
                path.display()
            );
            std::fs::write(path, DEFAULT_CONFIG_TOML).with_context(|| {
                format!("failed to write default config to '{}'", path.display())
            })?;
        }

        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file '{}'", path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file '{}'", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Reject values the eBPF program or loader cannot represent sensibly.
    pub fn validate(&self) -> Result<()> {
        let java = check_ports("[java]", self.java.start_port, self.java.end_port)?;
        let guard = check_ports(
            "[tcp_guard]",
            self.tcp_guard.start_port,
            self.tcp_guard.end_port,
        )?;
        let raknet = check_ports("[bedrock]", self.bedrock.start_port, self.bedrock.end_port)?;
        let ice = check_ports(
            "[nethernet] ice",
            self.nethernet.ice_start_port,
            self.nethernet.ice_end_port,
        )?;
        let udp_guard = check_ports(
            "[udp_guard]",
            self.udp_guard.start_port,
            self.udp_guard.end_port,
        )?;
        if [java, guard, raknet, ice, udp_guard].iter().all(Option::is_none) {
            bail!("nothing to protect: every port range is switched off");
        }
        if overlap(java, guard) {
            bail!("the TCP port ranges of [java] and [tcp_guard] must not overlap");
        }
        if overlap(raknet, ice) || overlap(raknet, udp_guard) || overlap(ice, udp_guard) {
            bail!("the UDP port ranges of [bedrock], [nethernet] and [udp_guard] must not overlap");
        }

        self.java.validate()?;
        self.tcp_guard.validate()?;
        self.bedrock.validate()?;
        self.udp_guard.validate()?;
        self.limits.validate()?;
        self.attack.validate()?;
        self.lists.allow_nets().context("[lists] allow")?;
        self.lists.deny_nets().context("[lists] deny")?;
        self.xdp.validate()?;
        self.metrics.validate()?;
        self.logging.validate()
    }
}

/// Bail with a uniform message unless `min <= value <= max`.
fn check_range(option: &str, value: u64, min: u64, max: u64) -> Result<()> {
    if value < min || value > max {
        bail!("{option} must be between {min} and {max} (got {value})");
    }
    Ok(())
}

/// Validates one port range; `None` means the range is switched off.
fn check_ports(section: &str, start: u16, end: u16) -> Result<Option<(u16, u16)>> {
    if start == 0 {
        if end != 0 {
            bail!("{section} start_port is 0 (off) but end_port is {end}");
        }
        return Ok(None);
    }
    if start > end {
        bail!("{section} start_port ({start}) must be <= end_port ({end})");
    }
    Ok(Some((start, end)))
}

fn overlap(a: Option<(u16, u16)>, b: Option<(u16, u16)>) -> bool {
    match (a, b) {
        (Some((a_start, a_end)), Some((b_start, b_end))) => a_start <= b_end && b_start <= a_end,
        _ => false,
    }
}

impl JavaConfig {
    fn validate(&self) -> Result<()> {
        if self.protocol_min < 0 || self.protocol_max < 0 {
            bail!("[java] protocol_min and protocol_max must not be negative");
        }
        if self.protocol_max != 0 && self.protocol_min > self.protocol_max {
            bail!(
                "[java] protocol_min ({}) must be <= protocol_max ({})",
                self.protocol_min,
                self.protocol_max
            );
        }
        check_range("[java] hosts (entries)", self.hosts.len() as u64, 0, 1024)?;
        for host in &self.hosts {
            hosts::normalize(host).with_context(|| format!("[java] hosts: '{host}'"))?;
        }
        Ok(())
    }
}

impl TcpGuardConfig {
    fn validate(&self) -> Result<()> {
        if self.start_port != 0 && !self.allow_tls && !self.allow_http {
            bail!("[tcp_guard] allows neither TLS nor HTTP, nothing could connect");
        }
        Ok(())
    }
}

impl BedrockConfig {
    fn validate(&self) -> Result<()> {
        if self.raknet_protocol_min > self.raknet_protocol_max {
            bail!(
                "[bedrock] raknet_protocol_min ({}) must be <= raknet_protocol_max ({})",
                self.raknet_protocol_min,
                self.raknet_protocol_max
            );
        }
        check_range(
            "[bedrock] open_request_min_size",
            self.open_request_min_size as u64,
            0,
            1464,
        )?;
        if !self.pong_from.is_empty() {
            if self.start_port == 0 {
                bail!("[bedrock] pong_from is set but the Bedrock ports are switched off");
            }
            self.pong_from
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("[bedrock] pong_from: '{}' is not an address like 127.0.0.1:19132", self.pong_from))?;
        }
        check_range("[bedrock] pong_refresh_secs", self.pong_refresh_secs, 1, 60)
    }
}

impl LimitsConfig {
    fn validate(&self) -> Result<()> {
        check_range("[limits] window_secs", self.window_secs, 1, 86_400)?;
        // the idle check runs on a one second grid, so 1 could expire a
        // connection that is merely between two packets
        check_range("[limits] tcp_idle_secs", self.tcp_idle_secs, 2, 86_400)?;
        check_range("[limits] udp_idle_secs", self.udp_idle_secs, 2, 86_400)
    }
}

impl AttackConfig {
    fn validate(&self) -> Result<()> {
        check_range(
            "[attack] challenge_hold_secs",
            self.challenge_hold_secs,
            1,
            86_400,
        )?;
        check_range("[attack] retry_min_ms", self.retry_min_ms, 70, 900)?;
        check_range("[attack] retry_max_ms", self.retry_max_ms, 2_000, 60_000)?;
        check_range(
            "[attack] retry_table_slots",
            self.retry_table_slots as u64,
            1 << 10,
            1 << 26,
        )?;
        if !self.retry_table_slots.is_power_of_two() {
            bail!(
                "[attack] retry_table_slots must be a power of two (got {})",
                self.retry_table_slots
            );
        }
        check_range("[attack] good_after_secs", self.good_after_secs, 0, 86_400)?;
        check_range("[attack] good_ttl_hours", self.good_ttl_hours, 1, 24 * 365)
    }
}

impl XdpConfig {
    fn validate(&self) -> Result<()> {
        const MAX_ENTRIES: u64 = 1 << 22;
        for (option, value) in [
            ("max_pending_connections", self.max_pending_connections),
            ("max_player_connections", self.max_player_connections),
            ("max_pending_udp_sessions", self.max_pending_udp_sessions),
            ("max_udp_sessions", self.max_udp_sessions),
            ("max_tracked_ips", self.max_tracked_ips),
        ] {
            check_range(&format!("[xdp] {option}"), value as u64, 1, MAX_ENTRIES)?;
        }
        check_range("[xdp] adopt_secs", self.adopt_secs, 0, 3_600)?;
        if self.keep_state && self.state_dir.trim().is_empty() {
            bail!("[xdp] state_dir must not be empty when keep_state is enabled");
        }
        Ok(())
    }
}

impl MetricsConfig {
    fn validate(&self) -> Result<()> {
        check_range("[metrics] poll_secs", self.poll_secs, 1, 3_600)
    }
}

impl LoggingConfig {
    fn validate(&self) -> Result<()> {
        check_range("[logging] file_max_mb", self.file_max_mb, 1, 10_240)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> Config {
        toml::from_str(toml).expect("test toml parses")
    }

    #[test]
    fn embedded_default_matches_struct_default() {
        // The documented template shipped to users must parse and agree with
        // Config::default (commented out options -> defaults).
        let parsed: Config = toml::from_str(DEFAULT_CONFIG_TOML).expect("default toml parses");
        assert_eq!(parsed, Config::default());
        parsed.validate().expect("default config is valid");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("nonsense_key = 1").unwrap_err();
        assert!(err.to_string().contains("nonsense_key"));
        // also inside a section
        assert!(toml::from_str::<Config>("[java]\nnonsense_key = 1").is_err());
        // options of the upstream project that were renamed here
        assert!(toml::from_str::<Config>("[filter]\nhit_count = 1").is_err());
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        let cfg = parse("[limits]\nsyn_per_ip = 0\n\n[metrics]\nenabled = true");
        assert_eq!(cfg.limits.syn_per_ip, 0); // limit disabled
        assert!(cfg.metrics.enabled);
        assert_eq!(cfg.java.start_port, 25565); // default preserved
        assert_eq!(cfg.xdp.mode, ConfigXdpMode::Auto); // untouched section defaulted
    }

    #[test]
    fn rejects_bad_port_ranges() {
        assert!(
            parse("[java]\nstart_port = 30000\nend_port = 25565")
                .validate()
                .is_err()
        );
        assert!(parse("[java]\nstart_port = 0").validate().is_err()); // end_port still set
        assert!(
            parse("[bedrock]\nstart_port = 19132\nend_port = 19100")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn rejects_config_that_protects_nothing() {
        let cfg = parse("[java]\nstart_port = 0\nend_port = 0");
        assert!(cfg.validate().is_err());
        // Bedrock alone is fine
        let cfg = parse(
            "[java]\nstart_port = 0\nend_port = 0\n[bedrock]\nstart_port = 19132\nend_port = 19132",
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_overlapping_ranges_of_one_protocol() {
        let cfg = parse("[tcp_guard]\nstart_port = 25000\nend_port = 26000");
        assert!(cfg.validate().is_err());
        let cfg = parse(
            "[bedrock]\nstart_port = 19132\nend_port = 19140\n\
             [nethernet]\nice_start_port = 19140\nice_end_port = 19149",
        );
        assert!(cfg.validate().is_err());
        // the same number on TCP and UDP is no conflict
        let cfg = parse(
            "[tcp_guard]\nstart_port = 19132\nend_port = 19132\n\
             [bedrock]\nstart_port = 19132\nend_port = 19132",
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_bad_limits() {
        for toml in [
            "[limits]\nwindow_secs = 0",
            "[limits]\nwindow_secs = 86401",
            "[limits]\ntcp_idle_secs = 1",
            "[limits]\nudp_idle_secs = 86401",
            "[attack]\nretry_table_slots = 1000000",
            "[attack]\nretry_table_slots = 512",
            "[attack]\nretry_min_ms = 10",
            "[attack]\nretry_max_ms = 500",
            "[attack]\nchallenge_hold_secs = 0",
            "[attack]\ngood_ttl_hours = 0",
            "[java]\nprotocol_min = 800\nprotocol_max = 700",
            "[java]\nprotocol_min = -1",
            "[bedrock]\nraknet_protocol_min = 12",
            "[bedrock]\nopen_request_min_size = 1500",
            "[bedrock]\npong_from = \"127.0.0.1:19132\"",
            "[bedrock]\nstart_port = 19132\nend_port = 19132\npong_from = \"localhost\"",
            "[bedrock]\nstart_port = 19132\nend_port = 19132\npong_refresh_secs = 0",
            "[udp_guard]\nfirst_byte = 256",
            "[udp_guard]\nfirst_byte = -2",
            "[udp_guard]\nmin_size = 0",
            "[udp_guard]\nstart_port = 19132\nend_port = 19132\n[bedrock]\nstart_port = 19132\nend_port = 19132",
            "[tcp_guard]\nstart_port = 443\nend_port = 443\nallow_tls = false\nallow_http = false",
            "[xdp]\nadopt_secs = 3601",
            "[xdp]\nstate_dir = \"\"",
            "[metrics]\npoll_secs = 0",
        ] {
            assert!(parse(toml).validate().is_err(), "must be rejected: {toml}");
        }
    }

    #[test]
    fn rejects_zero_map_capacity() {
        for option in [
            "max_pending_connections",
            "max_player_connections",
            "max_pending_udp_sessions",
            "max_udp_sessions",
            "max_tracked_ips",
        ] {
            let cfg = parse(&format!("[xdp]\n{option} = 0"));
            assert!(cfg.validate().is_err(), "{option} = 0 must be rejected");
        }
    }

    #[test]
    fn rejects_unknown_enum_values() {
        let err = toml::from_str::<Config>("[xdp]\nmode = \"hardware\"").unwrap_err();
        assert!(err.to_string().contains("hardware"));
        assert!(toml::from_str::<Config>("[xdp]\nadopt = \"all\"").is_err());
        assert!(toml::from_str::<Config>("[xdp]\nipv6 = \"filter\"").is_err());
        assert_eq!(parse("[xdp]\nipv6 = \"inspect\"").xdp.ipv6, Ipv6Mode::Inspect);
        assert!(toml::from_str::<Config>("[attack]\nchallenge = \"on\"").is_err());
        let err = toml::from_str::<Config>("[logging]\nlevel = \"verbose\"").unwrap_err();
        assert!(err.to_string().contains("verbose"));
    }

    #[test]
    fn parses_networks() {
        let net = Ipv4Net::parse("203.0.113.7").unwrap();
        assert_eq!((net.addr, net.prefix_len), (Ipv4Addr::new(203, 0, 113, 7), 32));
        // host bits are cleared
        let net = Ipv4Net::parse("198.51.100.77/24").unwrap();
        assert_eq!((net.addr, net.prefix_len), (Ipv4Addr::new(198, 51, 100, 0), 24));
        let net = Ipv4Net::parse(" 10.1.2.3/8 ").unwrap();
        assert_eq!((net.addr, net.prefix_len), (Ipv4Addr::new(10, 0, 0, 0), 8));
        let net = Ipv4Net::parse("1.2.3.4/0").unwrap();
        assert_eq!((net.addr, net.prefix_len), (Ipv4Addr::new(0, 0, 0, 0), 0));

        for bad in ["", "1.2.3", "1.2.3.4/33", "1.2.3.4/", "example.com", "::1", "1.2.3.4/-1"] {
            assert!(Ipv4Net::parse(bad).is_err(), "must be rejected: {bad}");
        }

        let net = Ipv4Net::parse("198.51.100.0/24").unwrap();
        assert_eq!(net.to_string(), "198.51.100.0/24");
        assert!(net.contains(Ipv4Addr::new(198, 51, 100, 255)));
        assert!(!net.contains(Ipv4Addr::new(198, 51, 101, 0)));
        assert!(Ipv4Net::parse("0.0.0.0/0").unwrap().contains(Ipv4Addr::new(8, 8, 8, 8)));
        let host = Ipv4Net::parse("203.0.113.7").unwrap();
        assert!(host.contains(Ipv4Addr::new(203, 0, 113, 7)));
        assert!(!host.contains(Ipv4Addr::new(203, 0, 113, 8)));
    }

    #[test]
    fn parses_ipv6_networks() {
        let net = Ipv6Net::parse("2001:db8::1").unwrap();
        assert_eq!((net.addr, net.prefix_len), ("2001:db8::1".parse().unwrap(), 128));
        // host bits are cleared
        let net = Ipv6Net::parse("2001:db8:1:2:3:4:5:6/48").unwrap();
        assert_eq!((net.addr, net.prefix_len), ("2001:db8:1::".parse().unwrap(), 48));
        assert_eq!(net.to_string(), "2001:db8:1::/48");
        let net = Ipv6Net::parse("::/0").unwrap();
        assert_eq!((net.addr, net.prefix_len), (Ipv6Addr::UNSPECIFIED, 0));
        for bad in ["2001:db8::/129", "2001:db8::/", "2001:zz::", ":::"] {
            assert!(Ipv6Net::parse(bad).is_err(), "must be rejected: {bad}");
        }

        // the family is told by the colon
        assert!(matches!(IpNet::parse("203.0.113.7").unwrap(), IpNet::V4(_)));
        assert!(matches!(IpNet::parse("2001:db8::/32").unwrap(), IpNet::V6(_)));
        let nets = [
            IpNet::parse("10.0.0.0/8").unwrap(),
            IpNet::parse("fd00::/8").unwrap(),
            IpNet::parse("203.0.113.7").unwrap(),
        ];
        let (v4, v6) = split_families(&nets);
        assert_eq!((v4.len(), v6.len()), (2, 1));
    }

    #[test]
    fn rejects_bad_lists_and_hosts() {
        assert!(parse("[lists]\nallow = [\"nonsense\"]").validate().is_err());
        assert!(parse("[lists]\ndeny = [\"1.2.3.4/40\"]").validate().is_err());
        assert!(parse("[lists]\ndeny = [\"2001:db8::/200\"]").validate().is_err());
        parse("[lists]\nallow = [\"10.0.0.0/8\", \"fd00::/8\"]\ndeny = [\"203.0.113.7\", \"2001:db8::1\"]")
            .validate()
            .unwrap();

        parse("[java]\nhosts = [\"mc.example.com\", \"Play.Example.COM.\", \"203.0.113.7\"]")
            .validate()
            .unwrap();
        assert!(parse("[java]\nhosts = [\"\"]").validate().is_err());
        let too_long = "a".repeat(65);
        assert!(
            parse(&format!("[java]\nhosts = [\"{too_long}\"]"))
                .validate()
                .is_err()
        );
    }
}
