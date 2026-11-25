//! `xdp-loader doctor [-c <FILE>]`: checks the machine, the configuration
//! and the running filter, and says what to change. Exits with 1 if any
//! check failed outright.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::Result;
use colored::Colorize;

use crate::config::{Config, Ipv6Mode};
use crate::{deny, ebpf, telemetry};

const USAGE: &str = "\
Usage: xdp-loader doctor [-c <FILE>]

Checks the kernel, the network interface, the configuration and the running
filter, and says what to change. Without -c it reads
/etc/minecraft-xdp/config.toml, else ./config.toml.";

/// Drivers with native XDP support (not complete, the common ones).
const NATIVE_XDP: &[&str] = &[
    "igb",
    "igc",
    "ixgbe",
    "ixgbevf",
    "i40e",
    "iavf",
    "ice",
    "idpf",
    "mlx4_core",
    "mlx4_en",
    "mlx5_core",
    "bnxt_en",
    "virtio_net",
    "ena",
    "gve",
    "hv_netvsc",
    "nfp",
    "qede",
    "sfc",
    "thunder",
    "tun",
    "veth",
    "netdevsim",
];

#[derive(Default)]
struct Report {
    failed: bool,
}

impl Report {
    fn ok(&mut self, what: impl AsRef<str>) {
        println!("  {} {}", "✓".green(), what.as_ref());
    }
    fn warn(&mut self, what: impl AsRef<str>, hint: impl AsRef<str>) {
        println!("  {} {}", "!".yellow().bold(), what.as_ref());
        println!("      {} {}", "→".dimmed(), hint.as_ref());
    }
    fn fail(&mut self, what: impl AsRef<str>, hint: impl AsRef<str>) {
        self.failed = true;
        println!("  {} {}", "✗".red().bold(), what.as_ref());
        println!("      {} {}", "→".dimmed(), hint.as_ref());
    }
}

/// Runs the checks; `Ok(false)` if any failed.
pub fn run(args: &[String]) -> Result<bool> {
    let mut config_path = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(true);
            }
            "-c" | "--config" => config_path = args.next().cloned(),
            _ => anyhow::bail!("unexpected argument '{arg}'\n\n{USAGE}"),
        }
    }
    let config_path = config_path.or_else(|| {
        ["/etc/minecraft-xdp/config.toml", "config.toml"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .map(String::from)
    });

    println!("minecraft-xdp-guard {} doctor", env!("CARGO_PKG_VERSION"));
    let mut r = Report::default();
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;

    // the machine
    let release = kernel_release();
    match kernel_version(&release) {
        Some(v) if v >= (5, 18) => r.ok(format!("kernel {release}")),
        Some(v) if v >= (5, 11) => r.warn(
            format!(
                "kernel {release}: works, but answering Bedrock pings from the filter needs 5.18"
            ),
            "leave [bedrock] pong_from empty or upgrade the kernel",
        ),
        _ => r.fail(
            format!("kernel {release}: 5.11 or newer is needed"),
            "upgrade the kernel",
        ),
    }
    if !root {
        r.warn(
            "not running as root: the filter can not be checked against the kernel",
            "sudo xdp-loader doctor",
        );
    }
    let bpffs = std::fs::read_to_string("/proc/mounts")
        .is_ok_and(|m| m.lines().any(|l| l.contains(" /sys/fs/bpf bpf ")));
    if bpffs {
        r.ok("/sys/fs/bpf is mounted");
    } else {
        r.fail(
            "/sys/fs/bpf is not mounted: state can not be kept",
            "mount -t bpf bpf /sys/fs/bpf",
        );
    }

    // the configuration
    let config = match deny::load_config(config_path.as_deref()) {
        Ok(config) => {
            match &config_path {
                Some(path) => r.ok(format!("config {path} is valid")),
                None => r.warn(
                    "no config.toml found, checking the defaults",
                    "pass -c <FILE>",
                ),
            }
            config
        }
        Err(e) => {
            r.fail(
                format!("config is invalid: {e:#}"),
                "fix the option named above",
            );
            return Ok(false);
        }
    };
    if root {
        match ebpf::check(&config) {
            Ok(()) => r.ok("the kernel accepts the filter with this configuration"),
            Err(e) => r.fail(
                format!("the kernel rejects the filter: {e:#}"),
                "report it with the output above",
            ),
        }
    }

    // the running filter
    let state_dir = ebpf::state_dir(&config);
    let interfaces: Vec<String> = std::fs::read_dir(&state_dir)
        .map(|dir| {
            dir.filter_map(|e| {
                e.ok()?
                    .file_name()
                    .into_string()
                    .ok()?
                    .strip_prefix("link-")
                    .map(String::from)
            })
            .collect()
        })
        .unwrap_or_default();
    if interfaces.is_empty() {
        r.warn(
            "the filter is not attached anywhere (no pinned attachment)",
            "start it: systemctl start minecraft-xdp, or xdp-loader -c <FILE> <INTERFACE>",
        );
    }
    for interface in &interfaces {
        let mode = attached_mode(interface);
        let driver = std::fs::read_link(format!("/sys/class/net/{interface}/device/driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        match (mode.as_deref(), driver.as_deref()) {
            (Some("driver"), _) => r.ok(format!("attached to {interface} in native driver mode")),
            (Some("skb"), Some(d)) if NATIVE_XDP.contains(&d) => r.warn(
                format!("attached to {interface} in generic mode, but its driver {d} supports native XDP"),
                "set [xdp] mode = \"driver\" (or \"auto\") and reload",
            ),
            (Some("skb"), d) => r.warn(
                format!(
                    "attached to {interface} in generic mode (driver {})",
                    d.unwrap_or("unknown")
                ),
                "fine up to about 1 Gbit/s; a NIC with native XDP is several times cheaper",
            ),
            _ => r.warn(
                format!("a pinned attachment for {interface} exists, but the interface shows no XDP program"),
                format!("xdp-loader detach -c <FILE> {interface}, then start the loader again"),
            ),
        }
    }
    if root && !interfaces.is_empty() {
        match telemetry::count_players(
            &state_dir,
            config.limits.tcp_idle_secs * 1_000_000_000,
            config.limits.udp_idle_secs * 1_000_000_000,
        ) {
            Ok(p) => r.ok(format!(
                "players right now: {} Java, {} Bedrock, {} NetherNet, {} voice chat",
                p.java, p.bedrock, p.nethernet, p.voice
            )),
            Err(e) => r.warn(
                format!("players can not be counted: {e:#}"),
                "is [xdp] keep_state off?",
            ),
        }
    }

    // what listens here against what is protected
    let listening = listening_sockets();
    let ports = Protected::of(&config);
    let known = [
        (Proto::Tcp, 25565, "Minecraft Java", "[java]"),
        (Proto::Udp, 19132, "Bedrock", "[bedrock]"),
        (Proto::Tcp, 19132, "NetherNet signaling", "[tcp_guard]"),
        (Proto::Udp, 24454, "Simple Voice Chat", "[voice]"),
    ];
    for (proto, port, what, section) in known {
        let open = listening
            .iter()
            .any(|s| s.proto == proto && s.port == port && !s.loopback);
        if open && !ports.covers(proto, port) {
            r.fail(
                format!(
                    "{} {port} ({what}) is listening but not protected",
                    proto.name()
                ),
                format!("add start_port = {port} and end_port = {port} to {section}"),
            );
        } else if open {
            r.ok(format!(
                "{} {port} ({what}) is listening and protected",
                proto.name()
            ));
        }
    }
    for (proto, port) in ports.list() {
        if !listening.iter().any(|s| s.proto == proto && s.port == port) {
            r.warn(
                format!("{} {port} is protected, but nothing on this host listens on it", proto.name()),
                "fine if it is forwarded to a container or another machine; then set [xdp] adopt = \"blind\"",
            );
        }
    }
    let v6_open = listening
        .iter()
        .any(|s| s.v6 && !s.loopback && ports.covers(s.proto, s.port));
    match config.xdp.ipv6 {
        Ipv6Mode::Pass if v6_open => r.fail(
            "protected ports listen on IPv6, but ipv6 = \"pass\" lets IPv6 floods around the filter",
            "set [xdp] ipv6 = \"inspect\"",
        ),
        Ipv6Mode::Pass => {}
        mode => r.ok(format!("IPv6: {}", format!("{mode:?}").to_lowercase())),
    }

    // the configuration itself
    if config.java.start_port != 0 && config.java.hosts.is_empty() {
        r.warn(
            "[java] hosts is empty: handshakes for the bare IP or any name get through to inspection",
            "list the names players connect with, e.g. hosts = [\"play.example.com\", \"*.example.com\"]",
        );
    }
    if config.metrics.enabled {
        r.ok("metrics on: flood reports in the log, packet counts in the stats");
    } else {
        r.warn(
            "metrics off: no flood reports in the log",
            "set [metrics] enabled = true",
        );
    }
    if telemetry::enabled(&config) {
        r.ok("telemetry on (anonymous, see README#telemetry)");
    } else {
        r.ok("telemetry off");
    }

    if r.failed {
        println!(
            "\n  Fix the {} lines and run the doctor again.",
            "✗".red().bold()
        );
    }
    Ok(!r.failed)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

struct Socket {
    proto: Proto,
    port: u16,
    v6: bool,
    loopback: bool,
}

/// Listening TCP and bound UDP sockets of this network namespace.
fn listening_sockets() -> Vec<Socket> {
    let mut out = Vec::new();
    for (file, proto, v6) in [
        ("/proc/net/tcp", Proto::Tcp, false),
        ("/proc/net/tcp6", Proto::Tcp, true),
        ("/proc/net/udp", Proto::Udp, false),
        ("/proc/net/udp6", Proto::Udp, true),
    ] {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        out.extend(
            text.lines()
                .skip(1)
                .filter_map(|line| parse_socket(line, proto, v6)),
        );
    }
    out
}

/// One line of /proc/net/{tcp,udp}{,6}: `sl local remote st ...`.
fn parse_socket(line: &str, proto: Proto, v6: bool) -> Option<Socket> {
    let mut fields = line.split_whitespace();
    let local = fields.nth(1)?;
    let state = fields.nth(1)?;
    // TCP: LISTEN; UDP: unconnected (bound)
    if (proto == Proto::Tcp && state != "0A") || (proto == Proto::Udp && state != "07") {
        return None;
    }
    let (addr, port) = local.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let loopback = if v6 {
        addr == "00000000000000000000000001000000"
    } else {
        // little endian: 127.x.x.x ends in 7F
        addr.len() == 8 && addr.ends_with("7F")
    };
    Some(Socket {
        proto,
        port,
        v6,
        loopback,
    })
}

/// The port ranges the configuration protects.
struct Protected(Vec<(Proto, u16, u16)>);

impl Protected {
    fn of(c: &Config) -> Self {
        let ranges = [
            (Proto::Tcp, c.java.start_port, c.java.end_port),
            (Proto::Tcp, c.tcp_guard.start_port, c.tcp_guard.end_port),
            (Proto::Udp, c.bedrock.start_port, c.bedrock.end_port),
            (
                Proto::Udp,
                c.nethernet.ice_start_port,
                c.nethernet.ice_end_port,
            ),
            (Proto::Udp, c.voice.start_port, c.voice.end_port),
            (Proto::Udp, c.udp_guard.start_port, c.udp_guard.end_port),
        ];
        Protected(ranges.into_iter().filter(|r| r.1 != 0).collect())
    }

    fn covers(&self, proto: Proto, port: u16) -> bool {
        self.0
            .iter()
            .any(|&(p, a, b)| p == proto && (a..=b).contains(&port))
    }

    /// Single ports only: ICE ranges are bound only while players are on.
    fn list(&self) -> BTreeSet<(Proto, u16)> {
        self.0
            .iter()
            .filter(|r| r.1 == r.2)
            .map(|&(p, a, _)| (p, a))
            .collect()
    }
}

/// `driver` or `skb` from `ip link`, `None` without an XDP program.
fn attached_mode(interface: &str) -> Option<String> {
    let out = Command::new("ip")
        .args(["link", "show", "dev", interface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?;
    if first.contains(" xdpgeneric") {
        Some("skb".into())
    } else if first.contains(" xdp") {
        Some("driver".into())
    } else {
        None
    }
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_lines() {
        let tcp = "   0: 00000000:63DD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1";
        let s = parse_socket(tcp, Proto::Tcp, false).unwrap();
        assert!(s.port == 25565 && !s.loopback && !s.v6);
        let local = "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1";
        assert!(parse_socket(local, Proto::Tcp, false).unwrap().loopback);
        let established = "   2: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 3 1";
        assert!(parse_socket(established, Proto::Tcp, false).is_none());
        let udp6 = "  3: 00000000000000000000000000000000:4ABC 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4 2 0";
        let s = parse_socket(udp6, Proto::Udp, true).unwrap();
        assert!(s.port == 19132 && s.v6 && !s.loopback);
    }

    #[test]
    fn kernel_versions() {
        assert_eq!(kernel_version("6.12.38+deb13-amd64"), Some((6, 12)));
        assert_eq!(kernel_version("5.15.0-117-generic"), Some((5, 15)));
        assert_eq!(kernel_version("6.8.0-117-generic"), Some((6, 8)));
        assert_eq!(kernel_version("garbage"), None);
    }

    #[test]
    fn protected_ports() {
        let mut c = Config::default();
        c.voice.start_port = 24454;
        c.voice.end_port = 24454;
        c.nethernet.ice_start_port = 27020;
        c.nethernet.ice_end_port = 27029;
        let p = Protected::of(&c);
        assert!(
            p.covers(Proto::Tcp, 25565)
                && p.covers(Proto::Udp, 24454)
                && p.covers(Proto::Udp, 27025)
        );
        assert!(!p.covers(Proto::Udp, 25565) && !p.covers(Proto::Udp, 19132));
        assert_eq!(
            p.list().len(),
            2,
            "ranges are not expected to be bound all the time"
        );
    }
}
