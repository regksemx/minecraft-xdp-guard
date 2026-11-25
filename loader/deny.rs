//! The deny list of the running filter: `xdp-loader deny ...`.
//!
//! The loader pins the `deny_v4` and `deny_v6` maps, so bans can be added and
//! removed while the filter runs, without restarting anything. Every entry
//! carries its lifetime as value (see `DENY_CONFIG` / `DENY_RUNTIME` in
//! xdp/common.h).

use std::borrow::{Borrow, BorrowMut};
use std::io::BufRead;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context, Result, bail};
use aya::Pod;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap, Map, MapData};

use crate::config::{Config, IpNet, Ipv4Net, Ipv6Net};
use crate::ebpf::{monotonic_ns, state_dir};

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
                               198.51.100.0/24, 2001:db8::/48), for --ttl
                               seconds or until removed. `add -` reads them
                               from stdin, one per line.
  del <NET>...                 Remove bans
  list                         Show all bans
  flush                        Remove every ban that was added with `add`

Options:
  -c, --config <FILE>  Configuration file of the running loader, to find its
                       state directory [default: config.toml]";

/// One address family of the deny list: its map and how a network becomes
/// the key of that map.
pub trait Family: Copy {
    /// Address part of the trie key, in network byte order.
    type Addr: Pod;
    /// Name of the map in xdp/minecraft_filter.c.
    const MAP: &'static str;

    fn key(&self) -> Key<Self::Addr>;
    fn from_key(key: &Key<Self::Addr>) -> Self;
    fn net(self) -> IpNet;
}

impl Family for Ipv4Net {
    type Addr = u32;
    const MAP: &'static str = "deny_v4";

    fn key(&self) -> Key<u32> {
        // the trie compares the key bytes front to back: network byte order
        Key::new(self.prefix_len, u32::from(self.addr).to_be())
    }

    fn from_key(key: &Key<u32>) -> Self {
        Self {
            addr: Ipv4Addr::from(u32::from_be(key.data())),
            prefix_len: key.prefix_len(),
        }
    }

    fn net(self) -> IpNet {
        IpNet::V4(self)
    }
}

impl Family for Ipv6Net {
    type Addr = [u8; 16];
    const MAP: &'static str = "deny_v6";

    fn key(&self) -> Key<[u8; 16]> {
        Key::new(self.prefix_len, self.addr.octets())
    }

    fn from_key(key: &Key<[u8; 16]>) -> Self {
        Self {
            addr: Ipv6Addr::from(key.data()),
            prefix_len: key.prefix_len(),
        }
    }

    fn net(self) -> IpNet {
        IpNet::V6(self)
    }
}

type Trie<T, F> = LpmTrie<T, <F as Family>::Addr, u64>;

fn entries<F: Family, T: Borrow<MapData>>(trie: &Trie<T, F>) -> Vec<(F, u64)> {
    trie.iter()
        .filter_map(Result::ok)
        .map(|(key, until)| (F::from_key(&key), until))
        .collect()
}

fn expired(until: u64, now: u64) -> bool {
    until > RUNTIME && until <= now
}

/// Brings one pinned deny map in line with the config file on start:
/// entries of an earlier config are replaced by the current ones, bans added
/// at runtime stay (unless their time is up). Returns how many stayed.
pub fn sync_config<F: Family, T: BorrowMut<MapData>>(
    trie: &mut Trie<T, F>,
    nets: &[F],
) -> Result<usize> {
    let now = monotonic_ns()?;
    let mut kept = 0;
    for (net, until) in entries::<F, T>(trie) {
        if until == CONFIG || expired(until, now) {
            let _ = trie.remove(&net.key());
        } else {
            kept += 1;
        }
    }
    for net in nets {
        trie.insert(&net.key(), &CONFIG, 0)
            .with_context(|| format!("failed to fill map '{}'", F::MAP))?;
    }
    Ok(kept)
}

/// Both maps of the running loader, opened from their pins.
struct DenyList {
    v4: Trie<MapData, Ipv4Net>,
    v6: Trie<MapData, Ipv6Net>,
}

fn open<F: Family>(dir: &Path) -> Result<Trie<MapData, F>> {
    let path = dir.join(F::MAP);
    let map = MapData::from_pin(&path).with_context(|| {
        format!(
            "cannot open '{}': is the loader running, and is this its config file?",
            path.display()
        )
    })?;
    Ok(LpmTrie::try_from(Map::LpmTrie(map))?)
}

impl DenyList {
    fn open(dir: &Path) -> Result<Self> {
        Ok(Self {
            v4: open::<Ipv4Net>(dir)?,
            v6: open::<Ipv6Net>(dir)?,
        })
    }

    /// All bans, IPv4 first, each family sorted by address.
    fn entries(&self) -> Vec<(IpNet, u64)> {
        let mut v4 = entries::<Ipv4Net, _>(&self.v4);
        v4.sort_by_key(|(net, _)| (net.addr, net.prefix_len));
        let mut v6 = entries::<Ipv6Net, _>(&self.v6);
        v6.sort_by_key(|(net, _)| (net.addr, net.prefix_len));
        v4.into_iter()
            .map(|(net, until)| (net.net(), until))
            .chain(v6.into_iter().map(|(net, until)| (net.net(), until)))
            .collect()
    }

    fn insert(&mut self, net: &IpNet, until: u64) -> Result<()> {
        match net {
            IpNet::V4(net) => self.v4.insert(&net.key(), &until, 0),
            IpNet::V6(net) => self.v6.insert(&net.key(), &until, 0),
        }
        .with_context(|| format!("failed to ban {net}"))
    }

    fn remove(&mut self, net: &IpNet) -> bool {
        match net {
            IpNet::V4(net) => self.v4.remove(&net.key()),
            IpNet::V6(net) => self.v6.remove(&net.key()),
        }
        .is_ok()
    }

    /// Removes bans whose time is up; the filter already ignores them.
    fn remove_expired(&mut self, now: u64) {
        for (net, until) in self.entries() {
            if expired(until, now) {
                self.remove(&net);
            }
        }
    }
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

/// Forgets the verified flows of banned IPv4 networks, so their established
/// connections are cut at once. Returns how many there were.
///
/// The filter re-checks the deny list for every open connection once per
/// second anyway, which is what cuts IPv6 connections (their flow keys are
/// hashes, see ipv6_keys() in xdp/minecraft_filter.c).
fn drop_flows(dir: &Path, nets: &[IpNet]) -> usize {
    let nets: Vec<&Ipv4Net> = nets
        .iter()
        .filter_map(|net| match net {
            IpNet::V4(net) => Some(net),
            IpNet::V6(_) => None,
        })
        .collect();
    if nets.is_empty() {
        return 0;
    }
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

fn parse_nets(args: &[String]) -> Result<Vec<IpNet>> {
    let mut nets = Vec::new();
    for arg in args {
        if arg == "-" {
            for line in std::io::stdin().lock().lines() {
                let line = line.context("failed to read stdin")?;
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    nets.push(IpNet::parse(line)?);
                }
            }
        } else {
            nets.push(IpNet::parse(arg)?);
        }
    }
    if nets.is_empty() {
        bail!("no address given");
    }
    Ok(nets)
}

/// The config of the running loader: the given file, else `config.toml` in
/// the working directory, else the defaults. Never creates a file.
pub fn load_config(path: Option<&str>) -> Result<Config> {
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
    let mut list = DenyList::open(&dir)?;
    let now = monotonic_ns()?;
    list.remove_expired(now);

    match command.as_str() {
        "add" => {
            let nets = parse_nets(rest)?;
            let until = ttl.map_or(RUNTIME, |secs| now + secs * NSEC_PER_SEC);
            for net in &nets {
                list.insert(net, until)?;
            }
            let dropped = drop_flows(&dir, &nets);
            println!("banned {} ({dropped} open connections cut)", nets.len());
        }
        "del" => {
            let mut removed = 0;
            for net in parse_nets(rest)? {
                if list.remove(&net) {
                    removed += 1;
                } else {
                    eprintln!("{net} is not on the list");
                }
            }
            println!("removed {removed}");
        }
        "list" => {
            for (net, until) in list.entries() {
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
            for (net, until) in list.entries() {
                if until != CONFIG && list.remove(&net) {
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
        let IpNet::V4(original) = IpNet::parse("198.51.100.0/24").unwrap() else {
            panic!("not IPv4");
        };
        let key = original.key();
        // network byte order in memory, whatever the host is
        let data = key.data();
        assert_eq!(data.to_ne_bytes(), [198, 51, 100, 0]);
        assert_eq!(Ipv4Net::from_key(&key), original);

        let IpNet::V6(original) = IpNet::parse("2001:db8:1::/48").unwrap() else {
            panic!("not IPv6");
        };
        let key = original.key();
        assert_eq!(key.prefix_len(), 48);
        assert_eq!(key.data()[..6], [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        assert_eq!(Ipv6Net::from_key(&key), original);
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
