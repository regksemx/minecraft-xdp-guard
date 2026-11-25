//! Anonymous usage statistics, `[telemetry]` in the config.
//!
//! Every `interval_secs` (30 minutes) one small JSON report is POSTed to
//! `endpoint`. It holds a random id of this installation, the version, the
//! kernel release and architecture, the XDP mode, which protections are
//! switched on, how many players are connected and, when `[metrics]` is
//! enabled, how many packets arrived and were dropped since the last report.
//! Nothing else: no addresses, host names or configuration values.
//!
//! The collector lives in `collector/` of this repository and publishes the
//! totals. Failures are logged at debug level and never affect the filter.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{HashMap, Map, MapData};
use log::{debug, info};
use serde::Serialize;

use crate::config::{Config, ConfigXdpMode, Ipv6Mode};
use crate::ebpf;
use crate::metrics::LATEST_TOTALS;
use crate::shutdown::Shutdown;

/// `MINECRAFT_XDP_TELEMETRY=off` (or `0`, `false`, `no`) disables reporting
/// regardless of the config.
const ENV: &str = "MINECRAFT_XDP_TELEMETRY";
const ID_FILE: &str = "telemetry-id";
const REPORT_VERSION: u8 = 1;

// enum flow_kind in xdp/common.h
const FLOW_JAVA: u8 = 1;
const FLOW_RAKNET: u8 = 3;
const FLOW_ICE: u8 = 4;
const FLOW_ADOPTED: u8 = 5;
const FLOW_VOICE: u8 = 7;

#[derive(Debug, Serialize, PartialEq)]
struct Report {
    v: u8,
    id: String,
    version: &'static str,
    kernel: String,
    arch: &'static str,
    cpus: usize,
    /// `None` when this loader took over the attachment of an earlier one.
    mode: Option<String>,
    features: Vec<&'static str>,
    /// `None` when the tables are not pinned and can not be read.
    players: Option<Players>,
    /// `None` while `[metrics]` is disabled.
    packets: Option<Packets>,
    uptime_secs: u64,
    interval_secs: u64,
}

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Players {
    pub java: u32,
    pub bedrock: u32,
    pub nethernet: u32,
    pub voice: u32,
}

#[derive(Debug, Serialize, PartialEq)]
struct Packets {
    incoming: u64,
    dropped: u64,
}

/// Whether reports are sent: the config, overridden by the environment.
pub fn enabled(config: &Config) -> bool {
    config.telemetry.enabled && !env_disables(std::env::var(ENV).ok().as_deref())
}

fn env_disables(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("off" | "0" | "false" | "no")
    )
}

/// Starts the reporting thread if telemetry is enabled. `config_path` decides
/// where the id of this installation is kept (next to the config).
pub fn start(
    config: &Config,
    config_path: &Path,
    mode: Option<ConfigXdpMode>,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    if !enabled(config) {
        debug!("Telemetry is off");
        return Ok(None);
    }
    let host = config
        .telemetry
        .endpoint
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(&config.telemetry.endpoint)
        .to_string();
    info!(
        "Telemetry: anonymous usage statistics (version, kernel, enabled protections, player and \
         packet counts; no addresses) go to {host} every {} minutes. Turn it off with \
         [telemetry] enabled = false or {ENV}=off",
        config.telemetry.interval_secs / 60
    );

    let id_path = config_path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join(ID_FILE);
    let reporter = Reporter {
        id: instance_id(&id_path),
        endpoint: config.telemetry.endpoint.clone(),
        interval: Duration::from_secs(config.telemetry.interval_secs),
        features: features(config),
        mode: mode.map(|m| m.to_string()),
        state_dir: ebpf::state_dir(config),
        tcp_idle_ns: config.limits.tcp_idle_secs * 1_000_000_000,
        udp_idle_ns: config.limits.udp_idle_secs * 1_000_000_000,
        started: Instant::now(),
    };
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("telemetry".into())
        .spawn(move || reporter.run(&shutdown))?;
    Ok(Some(handle))
}

struct Reporter {
    id: String,
    endpoint: String,
    interval: Duration,
    features: Vec<&'static str>,
    mode: Option<String>,
    state_dir: PathBuf,
    tcp_idle_ns: u64,
    udp_idle_ns: u64,
    started: Instant,
}

impl Reporter {
    fn run(&self, shutdown: &Shutdown) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .user_agent(format!("minecraft-xdp-guard/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        // the first report a few minutes after the start (spread by the id,
        // so that a fleet restarted at once does not report at once), then
        // every interval
        let first =
            Duration::from_secs(60 + u64::from_str_radix(&self.id[..4], 16).unwrap_or(0) % 240)
                .min(self.interval);
        let mut wait = first;
        let mut last_totals = None;
        loop {
            if !shutdown.sleep(wait) {
                return;
            }
            wait = self.interval;
            let totals = LATEST_TOTALS.lock().ok().and_then(|latest| *latest);
            let packets = match (last_totals, totals) {
                (Some((in0, drop0)), Some((in1, drop1))) if in1 >= in0 && drop1 >= drop0 => {
                    Some(Packets {
                        incoming: in1 - in0,
                        dropped: drop1 - drop0,
                    })
                }
                // the first report: everything since the start
                (None, Some((incoming, dropped))) => Some(Packets { incoming, dropped }),
                _ => None,
            };
            last_totals = totals.or(last_totals);
            let report = self.report(packets);
            match agent.post(&self.endpoint).send_json(&report) {
                Ok(_) => debug!("Telemetry report sent: {report:?}"),
                Err(e) => debug!("Telemetry report not sent: {e}"),
            }
        }
    }

    fn report(&self, packets: Option<Packets>) -> Report {
        Report {
            v: REPORT_VERSION,
            id: self.id.clone(),
            version: env!("CARGO_PKG_VERSION"),
            kernel: kernel_release(),
            arch: std::env::consts::ARCH,
            cpus: thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            mode: self.mode.clone(),
            features: self.features.clone(),
            players: self
                .players()
                .map_err(|e| debug!("Telemetry: no player count ({e:#})"))
                .ok(),
            packets,
            uptime_secs: self.started.elapsed().as_secs(),
            interval_secs: self.interval.as_secs(),
        }
    }

    fn players(&self) -> Result<Players> {
        count_players(&self.state_dir, self.tcp_idle_ns, self.udp_idle_ns)
    }
}

/// Verified game connections that saw a packet within their idle
/// timeout. Entries of the tables expire lazily, so old ones are skipped
/// by the time of their last window.
pub fn count_players(state_dir: &Path, tcp_idle_ns: u64, udp_idle_ns: u64) -> Result<Players> {
    let now = monotonic_ns();
    let mut players = Players::default();
    for (name, idle_ns) in [("verified_tcp", tcp_idle_ns), ("verified_udp", udp_idle_ns)] {
        let map = MapData::from_pin(state_dir.join(name))
            .with_context(|| format!("map '{name}' is not pinned"))?;
        let flows = HashMap::<MapData, [u8; 12], [u8; 24]>::try_from(Map::LruHashMap(map))?;
        for (_, entry) in flows.iter().filter_map(Result::ok) {
            let last_window = u64::from_ne_bytes(entry[0..8].try_into().unwrap());
            if now.saturating_sub(last_window) > idle_ns {
                continue;
            }
            match (name, entry[20]) {
                ("verified_tcp", FLOW_JAVA | FLOW_ADOPTED) => players.java += 1,
                ("verified_udp", FLOW_RAKNET | FLOW_ADOPTED) => players.bedrock += 1,
                ("verified_udp", FLOW_ICE) => players.nethernet += 1,
                ("verified_udp", FLOW_VOICE) => players.voice += 1,
                _ => {}
            }
        }
    }
    Ok(players)
}

/// The protections that are switched on, by name.
fn features(config: &Config) -> Vec<&'static str> {
    let mut features = Vec::new();
    let mut add = |on: bool, name| {
        if on {
            features.push(name);
        }
    };
    add(config.java.start_port != 0, "java");
    add(!config.java.hosts.is_empty(), "hosts");
    add(config.bedrock.start_port != 0, "bedrock");
    add(!config.bedrock.pong_from.is_empty(), "pong");
    add(config.nethernet.ice_start_port != 0, "nethernet");
    add(config.tcp_guard.start_port != 0, "tcp_guard");
    add(config.voice.start_port != 0, "voice");
    add(config.udp_guard.start_port != 0, "udp_guard");
    add(config.xdp.ipv6 == Ipv6Mode::Inspect, "ipv6");
    add(config.metrics.enabled, "metrics");
    features
}

/// The id of this installation: random, kept in `path`. If it can not be
/// stored, a new one is used for every run.
fn instance_id(path: &Path) -> String {
    if let Ok(id) = std::fs::read_to_string(path) {
        let id = id.trim();
        if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return id.to_string();
        }
    }
    let id = random_id();
    if let Err(e) = std::fs::write(path, format!("{id}\n")) {
        debug!(
            "Telemetry: could not store the id in '{}' ({e})",
            path.display()
        );
    }
    id
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    // SAFETY: getrandom writes at most `bytes.len()` bytes into the buffer.
    let filled = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if filled != bytes.len() as isize {
        // no entropy available this early is next to impossible; fall back to
        // the clock rather than not reporting
        let now = monotonic_ns() ^ std::process::id() as u64;
        bytes[..8].copy_from_slice(&now.to_ne_bytes());
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `bpf_ktime_get_ns()` of the program: CLOCK_MONOTONIC.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime only writes into the timespec it is given.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn kernel_release() -> String {
    // SAFETY: utsname is plain data and uname fills it in.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return String::new();
    }
    let release: Vec<u8> = uts
        .release
        .iter()
        .take_while(|&&c| c != 0)
        // c_char is i8 on x86_64 and u8 on aarch64
        .map(
            #[allow(clippy::unnecessary_cast)]
            |&c| c as u8,
        )
        .collect();
    String::from_utf8_lossy(&release).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_switch() {
        for off in ["off", "0", "false", "no", " OFF "] {
            assert!(env_disables(Some(off)), "{off}");
        }
        for on in [None, Some("on"), Some("1"), Some("")] {
            assert!(!env_disables(on), "{on:?}");
        }
    }

    #[test]
    fn features_follow_the_config() {
        let mut config = Config::default();
        assert_eq!(features(&config), vec!["java"]);
        config.bedrock.start_port = 19132;
        config.bedrock.end_port = 19132;
        config.xdp.ipv6 = Ipv6Mode::Inspect;
        config.java.hosts = vec!["play.example.com".into()];
        assert_eq!(features(&config), vec!["java", "hosts", "bedrock", "ipv6"]);
    }

    #[test]
    fn instance_id_is_kept() {
        let dir = std::env::temp_dir().join(format!("xdp-telemetry-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(ID_FILE);
        let first = instance_id(&path);
        assert_eq!(first.len(), 32);
        assert_eq!(instance_id(&path), first);
        std::fs::write(&path, "garbage").unwrap();
        assert_ne!(instance_id(&path), first);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn report_has_nothing_but_the_documented_fields() {
        let reporter = Reporter {
            id: "0".repeat(32),
            endpoint: String::new(),
            interval: Duration::from_secs(1800),
            features: vec!["java"],
            mode: Some("driver".into()),
            state_dir: PathBuf::from("/nonexistent"),
            tcp_idle_ns: 0,
            udp_idle_ns: 0,
            started: Instant::now(),
        };
        let json = serde_json::to_value(reporter.report(None)).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "arch",
                "cpus",
                "features",
                "id",
                "interval_secs",
                "kernel",
                "mode",
                "packets",
                "players",
                "uptime_secs",
                "v",
                "version"
            ]
        );
        assert!(
            json["players"].is_null(),
            "unpinned tables give no player count"
        );
    }
}
