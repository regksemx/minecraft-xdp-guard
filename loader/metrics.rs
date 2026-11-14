use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray};
use aya::{Ebpf, Pod};
use log::{debug, error, info, warn};
use prometheus::{Encoder, IntCounter, TextEncoder, register_int_counter};

use crate::config::Config;
use crate::shutdown::Shutdown;

/// Defines the userspace mirror of `enum stat_id` (see xdp/stats.h) together
/// with one Prometheus counter per entry, so the counter indexes, the per-cpu
/// summing and the published metrics all stay in sync from a single list.
/// The order must match the C enum exactly.
macro_rules! statistics {
    ($($id:ident => $metric:literal, $help:literal;)+) => {
        /// Index of every counter inside [`Statistics`], in C enum order.
        #[allow(non_camel_case_types, clippy::upper_case_acronyms, dead_code)]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        #[repr(usize)]
        pub enum Stat {
            $($id,)+
        }

        /// Number of counters, `STAT_COUNT` in xdp/stats.h.
        pub const STAT_COUNT: usize = [$(Stat::$id,)+].len();

        const METRICS: [(&str, &str); STAT_COUNT] = [$(($metric, $help),)+];

        #[cfg(test)]
        const STAT_NAMES: [&str; STAT_COUNT] = [$(stringify!($id),)+];
    };
}

statistics! {
    IncomingPackets    => "minecraft_incoming_packets", "Packets aimed at a protected port";
    IncomingBytes      => "minecraft_incoming_bytes", "Total incoming bytes";
    DroppedPackets     => "minecraft_dropped_packets", "Total dropped packets";
    DroppedBytes       => "minecraft_dropped_bytes", "Total dropped bytes";

    Denylist           => "minecraft_denylist_dropped", "Packets dropped by the deny list";
    Allowlist          => "minecraft_allowlist_passed", "Packets passed by the allow list without inspection";
    Ipv6Dropped        => "minecraft_ipv6_dropped", "IPv6 packets to protected ports dropped";
    FragmentDropped    => "minecraft_fragments_dropped", "First fragments to protected ports dropped";
    Malformed          => "minecraft_malformed", "Packets with broken L4 headers or lengths";

    NewIp              => "minecraft_new_ips", "Source ips that became known";
    ChallengeDropped   => "minecraft_challenge_dropped", "Openers of unknown ips dropped by the retransmit challenge";
    ChallengePassed    => "minecraft_challenge_passed", "Retransmits that passed the challenge";
    GoodIp             => "minecraft_good_ips", "Source ips marked as proven players";
    TableFull          => "minecraft_table_full", "Failed map inserts";

    TcpSyn             => "minecraft_syn_packets", "Total SYN packets";
    TcpBypass          => "minecraft_tcp_bypass", "Total TCP bypass attempts";
    SynThrottled       => "minecraft_syn_throttled", "SYNs above the per ip limit";
    TcpBudgetDropped   => "minecraft_tcp_budget_dropped", "SYNs, logins and status requests above the per second budget";
    TcpUntracked       => "minecraft_tcp_untracked", "TCP packets of unknown connections";
    TcpAdopted         => "minecraft_tcp_adopted", "TCP connections adopted after the filter was attached";
    TcpRateLimited     => "minecraft_tcp_rate_limited", "Packets of verified TCP connections above their packet rate";
    StateSwitch        => "minecraft_state_switches", "Total state switches";
    DropConnection     => "minecraft_dropped_connections", "Total dropped connections";

    JavaVerified       => "minecraft_verified_connections", "Total verified connections";
    JavaStatus         => "minecraft_status_requests", "Java status handshakes passed";
    StatusThrottled    => "minecraft_status_throttled", "Java status handshakes above the per ip limit";
    JavaBadHost        => "minecraft_bad_host", "Java handshakes for a host that is not allowed";
    JavaBadProto       => "minecraft_bad_protocol", "Java logins with a protocol version that is not allowed";
    JavaInvalid        => "minecraft_invalid_packets", "Java packets that failed inspection";
    GuardVerified      => "minecraft_guard_verified", "TCP guard connections verified";
    GuardInvalid       => "minecraft_guard_invalid", "TCP guard connections with an invalid first payload";

    RaknetPing         => "minecraft_raknet_pings", "RakNet unconnected pings passed";
    PingThrottled      => "minecraft_raknet_pings_throttled", "RakNet unconnected pings above the per ip limit";
    RaknetOpen         => "minecraft_raknet_open_requests", "RakNet OpenConnectionRequest1 accepted";
    RaknetVerified     => "minecraft_raknet_verified", "RakNet sessions verified";
    RaknetInvalid      => "minecraft_raknet_invalid", "RakNet datagrams that failed inspection";
    IceVerified        => "minecraft_ice_verified", "NetherNet sessions verified";
    IceInvalid         => "minecraft_ice_invalid", "NetherNet datagrams that failed inspection";
    UdpOpenThrottled   => "minecraft_udp_sessions_throttled", "New UDP sessions above the per ip limit";
    UdpBudgetDropped   => "minecraft_udp_budget_dropped", "Pings and new UDP sessions above the per second budget";
    UdpUntracked       => "minecraft_udp_untracked", "UDP datagrams of unknown sessions";
    UdpAdopted         => "minecraft_udp_adopted", "UDP sessions adopted after the filter was attached";
    UdpRateLimited     => "minecraft_udp_rate_limited", "Datagrams of verified UDP sessions above their packet rate";
}

/// Userspace mirror of `struct statistics` (one per-cpu slot of `stats_map`).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Statistics {
    counters: [u64; STAT_COUNT],
}

// SAFETY: repr(C) array of plain u64 without padding, valid for any bit
// pattern read from the map.
unsafe impl Pod for Statistics {}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            counters: [0; STAT_COUNT],
        }
    }
}

impl Statistics {
    fn add(&mut self, other: &Statistics) {
        for (total, value) in self.counters.iter_mut().zip(other.counters) {
            *total += value;
        }
    }

    fn get(&self, stat: Stat) -> u64 {
        self.counters[stat as usize]
    }
}

struct Counters {
    counters: Vec<IntCounter>,
}

impl Counters {
    fn new() -> Self {
        Self {
            counters: METRICS
                .iter()
                .map(|(metric, help)| register_int_counter!(*metric, *help).unwrap())
                .collect(),
        }
    }

    /// Publishes cumulative map totals as counter increments. The stats map
    /// is never pinned, so it and this process always die together and
    /// publishing the delta since the last poll keeps proper counter
    /// semantics; on restart both reset together, which Prometheus handles
    /// as a regular counter reset.
    fn publish(&self, total: &Statistics) {
        for (counter, value) in self.counters.iter().zip(total.counters) {
            counter.inc_by(value.saturating_sub(counter.get()));
        }
    }
}

static COUNTERS: LazyLock<Counters> = LazyLock::new(Counters::new);

/// Dropped packets per second from which on the log reports a flood.
const FLOOD_LOG_PPS: u64 = 1000;

/// Reports the start, the course and the end of a flood in the log, so an
/// attack is visible without a metrics stack.
#[derive(Default)]
struct FloodLog {
    last: Statistics,
    active: bool,
}

impl FloodLog {
    fn update(&mut self, total: &Statistics, interval: Duration) {
        let secs = interval.as_secs().max(1);
        let rate = |stat: Stat| total.get(stat).saturating_sub(self.last.get(stat)) / secs;
        let dropped = rate(Stat::DroppedPackets);

        if dropped >= FLOOD_LOG_PPS {
            // the reasons that explain most of the drops, biggest first
            let mut reasons: Vec<(u64, &str)> = [
                (Stat::ChallengeDropped, "challenge"),
                (Stat::TcpUntracked, "unknown tcp"),
                (Stat::UdpUntracked, "unknown udp"),
                (Stat::SynThrottled, "syn per ip"),
                (Stat::TcpBudgetDropped, "tcp budget"),
                (Stat::UdpBudgetDropped, "udp budget"),
                (Stat::StatusThrottled, "status per ip"),
                (Stat::PingThrottled, "ping per ip"),
                (Stat::UdpOpenThrottled, "sessions per ip"),
                (Stat::JavaInvalid, "invalid java"),
                (Stat::JavaBadHost, "bad host"),
                (Stat::RaknetInvalid, "invalid raknet"),
                (Stat::IceInvalid, "invalid ice"),
                (Stat::GuardInvalid, "invalid guard"),
                (Stat::TcpBypass, "tcp flags"),
                (Stat::TcpRateLimited, "tcp flow rate"),
                (Stat::UdpRateLimited, "udp flow rate"),
                (Stat::Denylist, "deny list"),
                (Stat::Ipv6Dropped, "ipv6"),
                (Stat::FragmentDropped, "fragments"),
                (Stat::Malformed, "malformed"),
            ]
            .into_iter()
            .map(|(stat, name)| (rate(stat), name))
            .filter(|(pps, _)| *pps > 0)
            .collect();
            reasons.sort_unstable_by(|a, b| b.0.cmp(&a.0));
            let reasons = reasons
                .iter()
                .take(4)
                .map(|(pps, name)| format!("{name} {pps}"))
                .collect::<Vec<_>>()
                .join(", ");
            warn!(
                "{}: dropping {dropped} of {} packets/s ({reasons}); verified {} logins/s, {} bedrock sessions/s",
                if self.active { "Flood" } else { "Flood started" },
                rate(Stat::IncomingPackets),
                rate(Stat::JavaVerified),
                rate(Stat::RaknetVerified),
            );
            self.active = true;
        } else if self.active {
            info!("Flood ended, dropping {dropped} packets/s");
            self.active = false;
        }
        self.last = *total;
    }
}

/// Starts the metrics machinery if enabled in the config: takes ownership of
/// the stats map, spawns the polling thread and (when an address is
/// configured) the HTTP endpoint. Returns the polling thread's handle.
pub fn start(
    ebpf: &mut Ebpf,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    if !config.metrics.enabled {
        return Ok(None);
    }

    let map = ebpf
        .take_map("stats_map")
        .context("can't take map 'stats_map'")?;
    let stats = PerCpuArray::try_from(map)?;

    match &config.metrics.addr {
        Some(addr) => serve_http(addr.clone()),
        None => info!("Metrics collection enabled but no addr set; HTTP endpoint disabled"),
    }

    let poll_interval = Duration::from_secs(config.metrics.poll_secs);
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("track-stats".into())
        .spawn(move || poll_loop(stats, shutdown, poll_interval))?;
    Ok(Some(handle))
}

/// Sums the per-cpu slices of the stats map and publishes the totals every
/// `poll_interval` until shutdown ends the loop. Read errors are logged and
/// retried next interval: metrics are auxiliary and must never take down the
/// filter itself.
fn poll_loop(
    stats: PerCpuArray<MapData, Statistics>,
    shutdown: Arc<Shutdown>,
    poll_interval: Duration,
) {
    let mut flood_log = FloodLog::default();
    loop {
        match stats.get(&0, 0) {
            Ok(per_cpu) => {
                let mut total = Statistics::default();
                for cpu_stats in per_cpu.iter() {
                    total.add(cpu_stats);
                }
                debug!("Stats: {total:?}");
                COUNTERS.publish(&total);
                flood_log.update(&total, poll_interval);
            }
            Err(e) => {
                error!("Failed to read stats map (retrying next interval): {e}");
            }
        }
        if !shutdown.sleep(poll_interval) {
            return;
        }
    }
}

/// Serves the Prometheus text endpoint on `addr` from its own thread.
fn serve_http(addr: String) {
    thread::spawn(move || {
        let server = match tiny_http::Server::http(&addr) {
            Ok(server) => server,
            Err(e) => {
                error!("Failed to start metrics server: {e}");
                return;
            }
        };
        info!("Prometheus metrics server running on {addr}/metrics");
        for request in server.incoming_requests() {
            if request.url() != "/metrics" {
                let _ = request.respond(tiny_http::Response::empty(404));
                continue;
            }
            debug!("Received metrics request from {:?}", request.remote_addr());
            let mut buffer = vec![];
            if let Err(e) = TextEncoder::new().encode(&prometheus::gather(), &mut buffer) {
                error!("Failed to encode metrics: {e}");
                continue;
            }
            let response = tiny_http::Response::from_data(buffer).with_header(
                tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/plain; version=0.0.4; charset=utf-8"[..],
                )
                .unwrap(),
            );
            let _ = request.respond(response);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `STAT_TCP_SYN` -> `TcpSyn`
    fn camel_case(c_name: &str) -> String {
        c_name
            .trim_start_matches("STAT_")
            .split('_')
            .map(|word| {
                let (first, rest) = word.split_at(1);
                format!("{first}{}", rest.to_ascii_lowercase())
            })
            .collect()
    }

    #[test]
    fn mirrors_the_c_enum() {
        // the list above has to name the entries of `enum stat_id` in
        // xdp/stats.h one by one, in the same order
        let header = include_str!("../xdp/stats.h");
        let body = header
            .split_once("enum stat_id")
            .and_then(|(_, rest)| rest.split_once("STAT_COUNT"))
            .map(|(body, _)| body)
            .expect("enum stat_id not found in xdp/stats.h");
        let c_names: Vec<String> = body
            .lines()
            .filter_map(|line| line.trim().split([',', ' ', '=']).next())
            .filter(|token| token.starts_with("STAT_"))
            .map(camel_case)
            .collect();
        assert_eq!(c_names, STAT_NAMES);
        assert_eq!(Stat::IncomingPackets as usize, 0);
        assert_eq!(Stat::UdpRateLimited as usize, STAT_COUNT - 1);
        assert_eq!(std::mem::size_of::<Statistics>(), STAT_COUNT * 8);
    }

    #[test]
    fn metric_names_are_unique() {
        let mut names: Vec<&str> = METRICS.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), STAT_COUNT);
    }
}
