//! `xdp-loader report`: sends one telemetry report for a filter that this
//! binary does not run itself, and exits. Meant for a systemd timer next to
//! an older or a differently built filter: it only reads the filter's
//! pinned tables and its Prometheus endpoint, loads and attaches nothing and
//! does not read its config.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::telemetry::{self, Packets, Report};

const USAGE: &str = "\
Usage: xdp-loader report [OPTIONS]

Sends one telemetry report for a running filter and exits. Reads only the
pinned tables and the metrics endpoint of that filter; loads nothing.

Options:
  --state-dir <DIR>     pinned tables of the filter [default: /sys/fs/bpf/minecraft-xdp/v1]
  --metrics <URL>       its Prometheus endpoint, for packet counts
  --endpoint <URL>      where the report goes [default: https://stats.olune.me/v1/report]
  --id-file <FILE>      id of this installation and the last packet counts
                        [default: /var/lib/xdp-guard-report/id]
  --features <a,b>      protections to report [default: java]
  --mode <driver|skb>   XDP mode of the filter
  --version <V>         version of the filter [default: this binary's]
  --interval <SECS>     how often the timer runs [default: 1800]
  --tcp-idle <SECS>     idle timeout of TCP connections [default: 60]
  --udp-idle <SECS>     idle timeout of UDP sessions [default: 30]
  --print               print the report instead of sending it";

struct Options {
    state_dir: PathBuf,
    metrics: Option<String>,
    endpoint: String,
    id_file: PathBuf,
    features: Vec<String>,
    mode: Option<String>,
    version: String,
    interval: u64,
    tcp_idle: u64,
    udp_idle: u64,
    print: bool,
}

fn parse(args: &[String]) -> Result<Option<Options>> {
    let mut o = Options {
        state_dir: "/sys/fs/bpf/minecraft-xdp/v1".into(),
        metrics: None,
        endpoint: "https://stats.olune.me/v1/report".into(),
        id_file: "/var/lib/xdp-guard-report/id".into(),
        features: vec!["java".into()],
        mode: None,
        version: env!("CARGO_PKG_VERSION").into(),
        interval: 1800,
        tcp_idle: 60,
        udp_idle: 30,
        print: false,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .with_context(|| format!("missing value for {arg}"))
        };
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(None);
            }
            "--state-dir" => o.state_dir = value()?.into(),
            "--metrics" => o.metrics = Some(value()?),
            "--endpoint" => o.endpoint = value()?,
            "--id-file" => o.id_file = value()?.into(),
            "--features" => {
                o.features = value()?
                    .split(',')
                    .map(|f| f.trim().to_string())
                    .filter(|f| !f.is_empty())
                    .collect()
            }
            "--mode" => o.mode = Some(value()?),
            "--version" => o.version = value()?,
            "--interval" => o.interval = value()?.parse().context("--interval")?,
            "--tcp-idle" => o.tcp_idle = value()?.parse().context("--tcp-idle")?,
            "--udp-idle" => o.udp_idle = value()?.parse().context("--udp-idle")?,
            "--print" => o.print = true,
            _ => bail!("unexpected argument '{arg}'\n\n{USAGE}"),
        }
    }
    Ok(Some(o))
}

pub fn run(args: &[String]) -> Result<()> {
    let Some(o) = parse(args)? else {
        return Ok(());
    };
    if let Some(dir) = o.id_file.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("can not create '{}'", dir.display()))?;
    }
    let players = telemetry::count_players(
        &o.state_dir,
        o.tcp_idle * 1_000_000_000,
        o.udp_idle * 1_000_000_000,
        false,
    )
    .ok();
    let packets = o
        .metrics
        .as_deref()
        .and_then(|url| packets_since_last(url, &o.id_file));
    let report = Report {
        v: telemetry::REPORT_VERSION,
        id: telemetry::instance_id(&o.id_file),
        version: o.version,
        kernel: telemetry::kernel_release(),
        arch: std::env::consts::ARCH.into(),
        cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        mode: o.mode,
        features: o.features,
        players,
        packets,
        uptime_secs: uptime_secs(),
        interval_secs: o.interval,
    };
    if o.print {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent(format!(
            "minecraft-xdp-guard-report/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .into();
    agent
        .post(&o.endpoint)
        .send_json(&report)
        .with_context(|| format!("report not accepted by {}", o.endpoint))?;
    Ok(())
}

/// Incoming and dropped packets since the previous run, from the filter's
/// Prometheus counters; the totals are kept next to the id. `None` on the
/// first run and after the filter restarted (its counters start over).
fn packets_since_last(url: &str, id_file: &Path) -> Option<Packets> {
    let text = ureq::get(url)
        .call()
        .ok()?
        .into_body()
        .read_to_string()
        .ok()?;
    let counter = |name: &str| -> Option<u64> {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
            .and_then(|v| v.trim().parse::<f64>().ok())
            .map(|v| v as u64)
    };
    let (incoming, dropped) = (
        counter("minecraft_incoming_packets")?,
        counter("minecraft_dropped_packets")?,
    );
    let last_file = id_file.with_extension("last");
    let last = std::fs::read_to_string(&last_file).ok().and_then(|s| {
        let mut parts = s.split_whitespace().map(|p| p.parse::<u64>().ok());
        Some((parts.next()??, parts.next()??))
    });
    let _ = std::fs::write(&last_file, format!("{incoming} {dropped}\n"));
    match last {
        Some((in0, drop0)) if incoming >= in0 && dropped >= drop0 => Some(Packets {
            incoming: incoming - in0,
            dropped: dropped - drop0,
        }),
        _ => None,
    }
}

fn uptime_secs() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|v| v as u64)
        .unwrap_or(0)
}
