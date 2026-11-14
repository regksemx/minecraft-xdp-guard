//! The deny list of the running filter: `xdp-loader deny ...`.
//!
//! The loader pins the `deny_v4` map, so bans can be added and removed while
//! the filter runs, without restarting anything. Every entry carries its
//! lifetime as value (see `DENY_CONFIG` / `DENY_RUNTIME` in xdp/common.h).

use std::borrow::{Borrow, BorrowMut};
use std::io::BufRead;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use aya::Pod;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap, Map, MapData};

use crate::config::{Config, Ipv4Net};
use crate::ebpf::{monotonic_ns, state_dir};

pub const MAP_NAME: &str = "deny_v4";

/// Listed in the config file; replaced on every start of the loader.
const CONFIG: u64 = 0;
/// Added while running, without an end.
const RUNTIME: u64 = 1;

const NSEC_PER_SEC: u64 = 1_000_000_000;

pub const USAGE: &str = "\
Usage: xdp-loader deny [-c <FILE>] <COMMAND>

Changes the deny list of the running filter. Bans take effect immediately,
also cut the connections the banned addresses have open, and survive a
restart of the loader.

Commands:
  add [--ttl <SECS>] <NET>...  Ban addresses or networks (203.0.113.7,
                               198.51.100.0/24), for --ttl seconds or until
                               removed. `add -` reads them from stdin, one
                               per line.
  del <NET>...                 Remove bans
  list                         Show all bans
  flush                        Remove every ban that was added with `add`

Options:
  -c, --config <FILE>  Configuration file of the running loader, to find its
                       state directory [default: config.toml]";

type Trie<T> = LpmTrie<T, u32, u64>;

fn key(net: &Ipv4Net) -> Key<u32> {
    // the trie compares the key bytes front to back: network byte order
    Key::new(net.prefix_len, u32::from(net.addr).to_be())
}

fn net(key: &Key<u32>) -> Ipv4Net {
    Ipv4Net {
        addr: Ipv4Addr::from(u32::from_be(key.data())),
        prefix_len: key.prefix_len(),
    }
}

fn entries<T: Borrow<MapData>>(trie: &Trie<T>) -> Vec<(Ipv4Net, u64)> {
    let mut entries: Vec<(Ipv4Net, u64)> = trie
        .iter()
        .filter_map(Result::ok)
        .map(|(key, until)| (net(&key), until))
        .collect();
    entries.sort_by_key(|(net, _)| (u32::from(net.addr), net.prefix_len));
    entries
}

fn expired(until: u64, now: u64) -> bool {
    until > RUNTIME && until <= now
}

/// Removes bans whose time is up; the filter already ignores them.
fn remove_expired<T: BorrowMut<MapData>>(trie: &mut Trie<T>, now: u64) {
    for (net, until) in entries(trie) {
        if expired(until, now) {
            let _ = trie.remove(&key(&net));
        }
    }
}

/// Brings the pinned deny list in line with the config file on start:
/// entries of an earlier config are replaced by the current ones, bans added
/// at runtime stay.
pub fn sync_config<T: BorrowMut<MapData>>(trie: &mut Trie<T>, nets: &[Ipv4Net]) -> Result<usize> {
    let now = monotonic_ns()?;
    let mut kept = 0;
    for (net, until) in entries(trie) {
        if until == CONFIG || expired(until, now) {
            let _ = trie.remove(&key(&net));
        } else {
            kept += 1;
        }
    }
    for net in nets {
        trie.insert(&key(net), CONFIG, 0)
            .context("failed to fill map 'deny_v4'")?;
    }
    Ok(kept)
}

/// Key of the verified flow maps, `struct ipv4_flow_key` in xdp/common.h.
#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey {
    src_ip: u32, // network byte order
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

// SAFETY: repr(C) struct of integers without padding, valid for any bit
// pattern.
unsafe impl Pod for FlowKey {}

/// Forgets the verified flows of the banned networks, so their established
/// connections are cut as well. Returns how many there were.
fn drop_flows(dir: &Path, nets: &[Ipv4Net]) -> usize {
    let mut dropped = 0;
    for name in ["verified_tcp", "verified_udp"] {
        let Ok(map) = MapData::from_pin(dir.join(name)) else {
            continue;
        };
        let Ok(mut flows) = HashMap::<MapData, FlowKey, [u8; 24]>::try_from(Map::LruHashMap(map))
        else {
            continue;
        };
        let doomed: Vec<FlowKey> = flows
            .keys()
            .filter_map(Result::ok)
            .filter(|flow| {
                let source = Ipv4Addr::from(u32::from_be(flow.src_ip));
                nets.iter().any(|net| net.contains(source))
            })
            .collect();
        for flow in doomed {
            if flows.remove(&flow).is_ok() {
                dropped += 1;
            }
        }
    }
    dropped
}

fn open(dir: &Path) -> Result<Trie<MapData>> {
    let path = dir.join(MAP_NAME);
    let map = MapData::from_pin(&path).with_context(|| {
        format!(
            "cannot open '{}': is the loader running, and is this its config file?",
            path.display()
        )
    })?;
    Ok(LpmTrie::try_from(Map::LpmTrie(map))?)
}

fn parse_nets(args: &[String]) -> Result<Vec<Ipv4Net>> {
    let mut nets = Vec::new();
    for arg in args {
        if arg == "-" {
            for line in std::io::stdin().lock().lines() {
                let line = line.context("failed to read stdin")?;
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    nets.push(Ipv4Net::parse(line)?);
                }
            }
        } else {
            nets.push(Ipv4Net::parse(arg)?);
        }
    }
    if nets.is_empty() {
        bail!("no address given");
    }
    Ok(nets)
}

/// The config of the running loader: the given file, else `config.toml` in
/// the working directory, else the defaults. Never creates a file.
fn load_config(path: Option<&str>) -> Result<Config> {
    match path {
        Some(path) if !Path::new(path).exists() => bail!("config file '{path}' not found"),
        Some(path) => Config::load(Path::new(path)),
        None if Path::new("config.toml").exists() => Config::load(Path::new("config.toml")),
        None => Ok(Config::default()),
    }
}

/// Runs `xdp-loader deny <args>`.
pub fn run(args: &[String]) -> Result<()> {
    let mut config_path = None;
    let mut ttl = None;
    let mut words = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            "-c" | "--config" => {
                config_path = Some(args.next().context("missing value for --config")?.as_str());
            }
            "--ttl" => {
                let secs = args.next().context("missing value for --ttl")?;
                let secs: u64 = secs
                    .parse()
                    .ok()
                    .filter(|secs| (1..=366 * 86_400).contains(secs))
                    .with_context(|| format!("--ttl must be a number of seconds, got '{secs}'"))?;
                ttl = Some(secs);
            }
            _ => words.push(arg.clone()),
        }
    }
    let Some((command, rest)) = words.split_first() else {
        bail!("missing command\n\n{USAGE}");
    };

    let config = load_config(config_path)?;
    let dir = state_dir(&config);
    let mut trie = open(&dir)?;
    let now = monotonic_ns()?;
    remove_expired(&mut trie, now);

    match command.as_str() {
        "add" => {
            let nets = parse_nets(rest)?;
            let until = ttl.map_or(RUNTIME, |secs| now + secs * NSEC_PER_SEC);
            for net in &nets {
                trie.insert(&key(net), until, 0)
                    .with_context(|| format!("failed to ban {net}"))?;
            }
            let dropped = drop_flows(&dir, &nets);
            println!("banned {} ({dropped} open connections cut)", nets.len());
        }
        "del" => {
            let mut removed = 0;
            for net in parse_nets(rest)? {
                match trie.remove(&key(&net)) {
                    Ok(()) => removed += 1,
                    Err(_) => eprintln!("{net} is not on the list"),
                }
            }
            println!("removed {removed}");
        }
        "list" => {
            for (net, until) in entries(&trie) {
                let lifetime = match until {
                    CONFIG => "config file".to_owned(),
                    RUNTIME => "until removed".to_owned(),
                    until => format!("{}s left", (until - now).div_ceil(NSEC_PER_SEC)),
                };
                println!("{net}\t{lifetime}");
            }
        }
        "flush" => {
            let mut removed = 0;
            for (net, until) in entries(&trie) {
                if until != CONFIG && trie.remove(&key(&net)).is_ok() {
                    removed += 1;
                }
            }
            println!("removed {removed}");
        }
        other => bail!("unknown command '{other}'\n\n{USAGE}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip() {
        let original = Ipv4Net::parse("198.51.100.0/24").unwrap();
        let key = key(&original);
        // network byte order in memory, whatever the host is
        let data = key.data();
        assert_eq!(data.to_ne_bytes(), [198, 51, 100, 0]);
        assert_eq!(net(&key), original);
    }

    #[test]
    fn lifetimes() {
        assert!(!expired(CONFIG, 1_000));
        assert!(!expired(RUNTIME, 1_000));
        assert!(expired(999, 1_000));
        assert!(expired(1_000, 1_000));
        assert!(!expired(1_001, 1_000));
    }
}
