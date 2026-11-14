use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aya::maps::lpm_trie::LpmTrie;
use aya::maps::{HashMap, MapInfo};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::xdp::{XdpLink, XdpLinkId};
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader, include_bytes_aligned};
use log::{info, warn};

use crate::config::{AdoptMode, ChallengeMode, Config, ConfigXdpMode, Ipv6Mode, split_families};
use crate::deny;
use crate::hosts;
use crate::pong;

const NSEC_PER_SEC: u64 = 1_000_000_000;

/// `RETRY_TICK_SHIFT` in xdp/common.h: one tick of the challenge table is
/// 2^26 ns.
const RETRY_TICK_NS: u64 = 1 << 26;

/// Subdirectory of `[xdp] state_dir` the maps are pinned in. Bump it whenever
/// the layout of a pinned map value changes, so that state written by an
/// older version is not picked up (sizes are checked anyway, but a changed
/// meaning of a field would go unnoticed).
const STATE_LAYOUT: &str = "v1";

/// A map that is pinned across restarts, with the shape this version and
/// configuration expect it to have.
struct StateMap {
    name: &'static str,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

/// The maps that are pinned while the loader runs: verified flows, what is
/// known about source ips and the deny list. Pinning lets them outlive a
/// restart and lets `xdp-loader deny` reach them. Sizes mirror xdp/common.h.
fn state_maps(config: &Config) -> [StateMap; 7] {
    [
        StateMap {
            name: "deny_v6",
            key_size: 20,
            value_size: 8,
            max_entries: 65536,
        },
        // connections in the middle of inspection: pinned so that a client
        // connecting right when the loader is replaced does not fail
        StateMap {
            name: "pending_tcp",
            key_size: 12,
            value_size: 12,
            max_entries: config.xdp.max_pending_connections,
        },
        StateMap {
            name: "pending_udp",
            key_size: 12,
            value_size: 16,
            max_entries: config.xdp.max_pending_udp_sessions,
        },
        // the capacity of the deny lists is fixed in xdp/minecraft_filter.c
        StateMap {
            name: "deny_v4",
            key_size: 8,
            value_size: 8,
            max_entries: 65536,
        },
        StateMap {
            name: "verified_tcp",
            key_size: 12,
            value_size: 24,
            max_entries: config.xdp.max_player_connections,
        },
        StateMap {
            name: "verified_udp",
            key_size: 12,
            value_size: 24,
            max_entries: config.xdp.max_udp_sessions,
        },
        StateMap {
            name: "ip_table",
            key_size: 4,
            value_size: 32,
            max_entries: config.xdp.max_tracked_ips,
        },
    ]
}

pub fn state_dir(config: &Config) -> PathBuf {
    Path::new(&config.xdp.state_dir).join(STATE_LAYOUT)
}

/// Where the attachment to `interface` is pinned. As long as this file
/// exists the filter stays attached, with or without a loader process.
fn link_pin(config: &Config, interface: &str) -> PathBuf {
    state_dir(config).join(format!("link-{interface}"))
}

/// The loaded and attached filter.
pub struct Filter {
    pub ebpf: Ebpf,
    /// Pin of the attachment, if it could be pinned.
    link_pin: Option<PathBuf>,
}

impl Filter {
    /// Detaches the filter from the interface. Merely dropping a `Filter`
    /// leaves it attached (if the attachment is pinned), which is how a
    /// restarted loader takes over without a gap and why a crashed loader
    /// does not leave the server unprotected.
    pub fn detach(self) {
        if let Some(pin) = &self.link_pin
            && let Err(e) = std::fs::remove_file(pin)
        {
            warn!("Failed to remove '{}': {e}", pin.display());
        }
        // dropping the program closes the last reference to the link
    }
}

/// `xdp-loader detach`: removes the pinned attachment of a loader that is
/// gone. Returns whether there was one.
pub fn detach_interface(config: &Config, interface: &str) -> Result<bool> {
    let pin = link_pin(config, interface);
    match std::fs::remove_file(&pin) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("failed to remove '{}'", pin.display())),
    }
}

/// Removes the pinned state maps, so the next load starts from scratch.
/// The deny list only goes along when `bans` is set.
pub fn remove_state(config: &Config, bans: bool) {
    let dir = state_dir(config);
    for map in state_maps(config) {
        if map.name.starts_with("deny_") && !bans {
            continue;
        }
        let path = dir.join(map.name);
        match std::fs::remove_file(&path) {
            Ok(()) => info!("Removed pinned map {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("Failed to remove pinned map {}: {e}", path.display()),
        }
    }
    // only succeeds once the directories are empty, which is all we want
    let _ = std::fs::remove_dir(&dir);
    let _ = std::fs::remove_dir(&config.xdp.state_dir);
}

/// Prepares the pin directory and returns the pin path of every state map.
///
/// A map pinned by a previous run is reused as is by the loader, so one that
/// no longer matches the configured capacity (or this version's layout) has
/// to go first; its state is lost, like on a fresh start.
fn prepare_state(config: &Config) -> Result<Vec<(&'static str, PathBuf)>> {
    let dir = state_dir(config);
    std::fs::create_dir_all(&dir).with_context(|| {
        format!(
            "failed to create '{}' (is a bpf filesystem mounted at /sys/fs/bpf?)",
            dir.display()
        )
    })?;

    let mut pins = Vec::new();
    for map in state_maps(config) {
        let path = dir.join(map.name);
        if path.exists() {
            let matches = MapInfo::from_pin(&path).is_ok_and(|pinned| {
                pinned.key_size() == map.key_size
                    && pinned.value_size() == map.value_size
                    && pinned.max_entries() == map.max_entries
            });
            if matches {
                info!("Reusing pinned map {}", path.display());
            } else {
                warn!(
                    "Pinned map {} does not match the configuration anymore, starting it empty",
                    path.display()
                );
                std::fs::remove_file(&path)
                    .with_context(|| format!("failed to remove '{}'", path.display()))?;
            }
        }
        pins.push((map.name, path));
    }
    Ok(pins)
}

/// Splits a total per second over the cpus, since the eBPF program counts
/// per cpu. 0 (unlimited) stays 0, everything else is at least 1.
fn per_cpu(total: u32, cpus: u32) -> u32 {
    if total == 0 { 0 } else { total.div_ceil(cpus).max(1) }
}

/// Current CLOCK_MONOTONIC in nanoseconds, the clock of
/// `bpf_ktime_get_coarse_ns()`.
pub fn monotonic_ns() -> Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, writable timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        bail!(
            "clock_gettime(CLOCK_MONOTONIC) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(ts.tv_sec as u64 * NSEC_PER_SEC + ts.tv_nsec as u64)
}

/// Random seed for the challenge table, so its slots can not be predicted.
fn random_seed() -> u64 {
    use std::io::Read;
    let mut bytes = [0u8; 8];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)) {
        Ok(()) => u64::from_ne_bytes(bytes),
        Err(e) => {
            warn!("Failed to read /dev/urandom ({e}), seeding the challenge table from the clock");
            monotonic_ns().unwrap_or(0x9E37_79B9_7F4A_7C15) ^ u64::from(std::process::id())
        }
    }
}

/// Loads the embedded eBPF object, applies the runtime configuration and
/// attaches the XDP program to `interface`.
///
/// If an earlier loader left its filter attached (it was asked to hand
/// over, or it died), the new program atomically replaces the old one on
/// that attachment: there is no moment without a filter.
///
/// No userspace involvement is needed while it runs: all state expires
/// lazily inside the program.
pub fn load_and_attach(interface: &str, config: &Config) -> Result<Filter> {
    let Loaded {
        mut ebpf,
        pins,
        cpus,
        adopt_mode,
    } = load(config, true)?;
    let program: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;

    // without pinned maps there is no state directory to pin the link in
    let pin = (!pins.is_empty()).then(|| link_pin(config, interface));

    let took_over = match &pin {
        Some(pin) if pin.exists() => match take_over(program, pin) {
            Ok(()) => true,
            Err(e) => {
                // e.g. the interface was recreated; removing the pin detaches
                // whatever is left of the old attachment
                warn!("Could not take over the existing attachment ({e:#}), attaching anew");
                std::fs::remove_file(pin)
                    .with_context(|| format!("failed to remove '{}'", pin.display()))?;
                false
            }
        },
        _ => false,
    };

    if took_over {
        info!("BPF program attached to interface {interface}: took over the existing attachment without a gap");
    } else {
        let (link_id, mode) = attach(program, interface, config.xdp.mode)?;
        if let Some(pin) = &pin {
            // the pin, not this process, keeps the filter attached from now on
            let link = program.take_link(link_id)?;
            let link = FdLink::try_from(link)
                .context("this kernel attaches XDP without a link that could be pinned")?;
            link.pin(pin)
                .with_context(|| format!("failed to pin the attachment at '{}'", pin.display()))?;
        }
        info!("BPF program attached to interface {interface} in {mode} mode");
    }

    log_protection(config, cpus, adopt_mode);
    Ok(Filter {
        ebpf,
        link_pin: pin,
    })
}

/// The program after it passed the verifier, not attached yet.
struct Loaded {
    ebpf: Ebpf,
    /// Pin paths of the state maps; empty if they could not be pinned.
    pins: Vec<(&'static str, PathBuf)>,
    cpus: u32,
    adopt_mode: u8,
}

/// `xdp-loader --check`: loads the program with this configuration into the
/// kernel, which runs it through the verifier, and unloads it again.
/// Nothing is attached and no state of a running loader is touched.
pub fn check(config: &Config) -> Result<()> {
    load(config, false).map(|_| ())
}

/// Loads the embedded eBPF object with the runtime configuration applied.
/// With `use_state` the state maps are pinned (and those of an earlier run
/// reused).
fn load(config: &Config, use_state: bool) -> Result<Loaded> {
    let object = include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/xdp/minecraft_filter.o"
    ));
    info!("Loaded BPF object ({} bytes)", object.len());

    let cpus = aya::util::nr_cpus()
        .map_err(|(what, e)| anyhow::anyhow!("failed to count cpus ({what}): {e}"))?
        as u32;

    // Push the runtime configuration into the program's `volatile const`
    // globals (BPF .rodata). Each Rust type MUST match its C declaration in
    // xdp/config.h exactly, since override_global() patches size_of::<T>()
    // bytes at the symbol's offset. `must_exist = true` fails loudly if a
    // symbol is missing (e.g. renamed on the C side) instead of silently
    // ignoring the configured value.
    let java = &config.java;
    let guard = &config.tcp_guard;
    let bedrock = &config.bedrock;
    let limits = &config.limits;
    let attack = &config.attack;

    let allow = config.lists.allow_nets().context("[lists] allow")?;
    let deny = config.lists.deny_nets().context("[lists] deny")?;
    let allowed_hosts = java
        .hosts
        .iter()
        .map(|host| hosts::normalize(host).map(|host| hosts::hash(&host)))
        .collect::<Result<Vec<u64>>>()
        .context("[java] hosts")?;

    let prometheus = config.metrics.enabled as u8;
    // IPV6_PASS / IPV6_DROP / IPV6_INSPECT in xdp/common.h
    let ipv6_mode: u8 = match config.xdp.ipv6 {
        Ipv6Mode::Pass => 0,
        Ipv6Mode::Drop => 1,
        Ipv6Mode::Inspect => 2,
    };
    let flow6_seed = flow6_seed();
    let (allow_v4, allow_v6) = split_families(&allow);
    let (deny_v4, deny_v6) = split_families(&deny);
    let has_allow = !allow.is_empty() as u8;
    // always on: bans can be added while the filter runs. Looking up an
    // empty list costs next to nothing
    let has_deny: u8 = 1;
    let limit_window_ns = limits.window_secs * NSEC_PER_SEC;

    let adopt_mode: u8 = match config.xdp.adopt {
        _ if config.xdp.adopt_secs == 0 => 0,
        AdoptMode::Off => 0,
        AdoptMode::Socket => 1,
        AdoptMode::Blind => 2,
    };
    let adopt_until_ns = monotonic_ns()? + config.xdp.adopt_secs * NSEC_PER_SEC;

    let java_start_port = u32::from(java.start_port);
    let java_end_port = u32::from(java.end_port);
    let online_names = java.online_names as u8;
    let host_filter = !allowed_hosts.is_empty() as u8;
    let java_proto_min: i32 = java.protocol_min;
    let java_proto_max: i32 = java.protocol_max;
    let status_hits = limits.status_per_ip;
    let status_budget = per_cpu(attack.status_budget, cpus);
    let login_budget = per_cpu(attack.login_budget, cpus);

    let guard_start_port = u32::from(guard.start_port);
    let guard_end_port = u32::from(guard.end_port);
    let guard_tls = guard.allow_tls as u8;
    let guard_http = guard.allow_http as u8;

    let syn_hits = limits.syn_per_ip;
    let syn_budget = per_cpu(attack.syn_budget, cpus);
    let tcp_flow_pps = limits.tcp_flow_pps;
    let tcp_idle_ns = limits.tcp_idle_secs * NSEC_PER_SEC;

    let raknet_start_port = u32::from(bedrock.start_port);
    let raknet_end_port = u32::from(bedrock.end_port);
    let raknet_proto_min = u32::from(bedrock.raknet_protocol_min);
    let raknet_proto_max = u32::from(bedrock.raknet_protocol_max);
    let raknet_ocr1_min = bedrock.open_request_min_size;
    let ping_hits = limits.pings_per_ip;
    let ping_budget = per_cpu(attack.ping_budget, cpus);
    let pong_reply = !bedrock.pong_from.is_empty() as u8;
    let pong_max_age_ns = pong::max_age_secs(config) * NSEC_PER_SEC;

    let ice_start_port = u32::from(config.nethernet.ice_start_port);
    let ice_end_port = u32::from(config.nethernet.ice_end_port);

    let udpguard_start_port = u32::from(config.udp_guard.start_port);
    let udpguard_end_port = u32::from(config.udp_guard.end_port);
    // 256 (UDPGUARD_ANY_BYTE in xdp/bedrock.h) = any first byte
    let udpguard_first_byte = u32::try_from(config.udp_guard.first_byte).unwrap_or(256);
    let udpguard_min_len = config.udp_guard.min_size;

    let udp_open_hits = limits.udp_sessions_per_ip;
    let udp_open_budget = per_cpu(attack.udp_session_budget, cpus);
    let udp_flow_pps = limits.udp_flow_pps;
    let udp_idle_ns = limits.udp_idle_secs * NSEC_PER_SEC;

    let challenge_mode: u8 = match attack.challenge {
        ChallengeMode::Off => 0,
        ChallengeMode::Auto => 1,
        ChallengeMode::Always => 2,
    };
    let challenge_pps = per_cpu(attack.challenge_new_ips_per_sec, cpus);
    let challenge_hold_ns = attack.challenge_hold_secs * NSEC_PER_SEC;
    let retry_mask = attack.retry_table_slots - 1;
    let retry_min_ticks = (attack.retry_min_ms * 1_000_000).div_ceil(RETRY_TICK_NS) as u32;
    let retry_max_ticks = (attack.retry_max_ms * 1_000_000).div_ceil(RETRY_TICK_NS) as u32;
    let retry_seed = random_seed();

    let good_after_ns = attack.good_after_secs * NSEC_PER_SEC;
    let good_ttl_ns = attack.good_ttl_hours * 3600 * NSEC_PER_SEC;

    let pins = if !use_state {
        Vec::new()
    } else {
        if !config.xdp.keep_state {
            // nothing of an earlier run may be picked up
            remove_state(config, true);
        }
        match prepare_state(config) {
            Ok(pins) => pins,
            Err(e) => {
                warn!("Running without pinned maps (no state across restarts, no `xdp-loader deny`): {e:#}");
                Vec::new()
            }
        }
    };

    let mut loader = EbpfLoader::new();
    loader
        .override_global("PROMETHEUS", &prometheus, true)
        .override_global("IPV6_MODE", &ipv6_mode, true)
        .override_global("FLOW6_SEED", &flow6_seed, true)
        .override_global("HAS_ALLOW", &has_allow, true)
        .override_global("HAS_DENY", &has_deny, true)
        .override_global("LIMIT_WINDOW_NS", &limit_window_ns, true)
        .override_global("ADOPT_MODE", &adopt_mode, true)
        .override_global("ADOPT_UNTIL_NS", &adopt_until_ns, true)
        .override_global("JAVA_START_PORT", &java_start_port, true)
        .override_global("JAVA_END_PORT", &java_end_port, true)
        .override_global("ONLINE_NAMES", &online_names, true)
        .override_global("HOST_FILTER", &host_filter, true)
        .override_global("JAVA_PROTO_MIN", &java_proto_min, true)
        .override_global("JAVA_PROTO_MAX", &java_proto_max, true)
        .override_global("STATUS_HITS", &status_hits, true)
        .override_global("STATUS_BUDGET", &status_budget, true)
        .override_global("LOGIN_BUDGET", &login_budget, true)
        .override_global("GUARD_START_PORT", &guard_start_port, true)
        .override_global("GUARD_END_PORT", &guard_end_port, true)
        .override_global("GUARD_TLS", &guard_tls, true)
        .override_global("GUARD_HTTP", &guard_http, true)
        .override_global("SYN_HITS", &syn_hits, true)
        .override_global("SYN_BUDGET", &syn_budget, true)
        .override_global("TCP_FLOW_PPS", &tcp_flow_pps, true)
        .override_global("TCP_IDLE_NS", &tcp_idle_ns, true)
        .override_global("RAKNET_START_PORT", &raknet_start_port, true)
        .override_global("RAKNET_END_PORT", &raknet_end_port, true)
        .override_global("RAKNET_PROTO_MIN", &raknet_proto_min, true)
        .override_global("RAKNET_PROTO_MAX", &raknet_proto_max, true)
        .override_global("RAKNET_OCR1_MIN", &raknet_ocr1_min, true)
        .override_global("PING_HITS", &ping_hits, true)
        .override_global("PING_BUDGET", &ping_budget, true)
        .override_global("PONG_REPLY", &pong_reply, true)
        .override_global("PONG_MAX_AGE_NS", &pong_max_age_ns, true)
        .override_global("ICE_START_PORT", &ice_start_port, true)
        .override_global("ICE_END_PORT", &ice_end_port, true)
        .override_global("UDPGUARD_START_PORT", &udpguard_start_port, true)
        .override_global("UDPGUARD_END_PORT", &udpguard_end_port, true)
        .override_global("UDPGUARD_FIRST_BYTE", &udpguard_first_byte, true)
        .override_global("UDPGUARD_MIN_LEN", &udpguard_min_len, true)
        .override_global("UDP_OPEN_HITS", &udp_open_hits, true)
        .override_global("UDP_OPEN_BUDGET", &udp_open_budget, true)
        .override_global("UDP_FLOW_PPS", &udp_flow_pps, true)
        .override_global("UDP_IDLE_NS", &udp_idle_ns, true)
        .override_global("CHALLENGE_MODE", &challenge_mode, true)
        .override_global("CHALLENGE_PPS", &challenge_pps, true)
        .override_global("CHALLENGE_HOLD_NS", &challenge_hold_ns, true)
        .override_global("RETRY_MASK", &retry_mask, true)
        .override_global("RETRY_MIN_TICKS", &retry_min_ticks, true)
        .override_global("RETRY_MAX_TICKS", &retry_max_ticks, true)
        .override_global("RETRY_SEED", &retry_seed, true)
        .override_global("GOOD_AFTER_NS", &good_after_ns, true)
        .override_global("GOOD_TTL_NS", &good_ttl_ns, true)
        // Replace the placeholder map capacities baked into the object with
        // the configured ones. The names must match the map definitions in
        // xdp/minecraft_filter.c; unlike override_global() there is no
        // must_exist flag, a mismatched name would be silently ignored.
        .map_max_entries("pending_tcp", config.xdp.max_pending_connections)
        .map_max_entries("verified_tcp", config.xdp.max_player_connections)
        .map_max_entries("pending_udp", config.xdp.max_pending_udp_sessions)
        .map_max_entries("verified_udp", config.xdp.max_udp_sessions)
        .map_max_entries("ip_table", config.xdp.max_tracked_ips)
        .map_max_entries("retry_table", attack.retry_table_slots);
    for (name, path) in &pins {
        loader.map_pin_path(name, path.as_path());
    }
    let mut ebpf = loader.load(object).context("failed to load BPF program")?;

    // the lists have to be in place before the first packet is filtered
    fill_hosts(&mut ebpf, &allowed_hosts)?;
    fill_list(&mut ebpf, "allow_v4", &allow_v4)?;
    fill_list(&mut ebpf, "allow_v6", &allow_v6)?;
    let kept_bans = sync_deny(&mut ebpf, &deny_v4)? + sync_deny(&mut ebpf, &deny_v6)?;
    if kept_bans > 0 {
        info!("Deny list: {kept_bans} bans kept from before the restart");
    }

    let program: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;
    program.load()?;

    Ok(Loaded {
        ebpf,
        pins,
        cpus,
        adopt_mode,
    })
}

/// Atomically replaces the program of the attachment pinned at `pin`.
fn take_over(program: &mut Xdp, pin: &Path) -> Result<()> {
    let link = PinnedLink::from_pin(pin).context("cannot open the pinned attachment")?;
    let link = XdpLink::try_from(FdLink::from(link)).context("the pin is not an XDP attachment")?;
    program.attach_to_link(link)?;
    Ok(())
}

/// Attaches the program to `interface`. Auto does its own driver -> skb
/// fallback instead of leaving the choice to the kernel, so the mode that is
/// actually active can be logged.
fn attach(
    program: &mut Xdp,
    interface: &str,
    mode: ConfigXdpMode,
) -> Result<(XdpLinkId, ConfigXdpMode)> {
    match mode {
        ConfigXdpMode::Auto => match program.attach(interface, XdpMode::Driver) {
            Ok(link) => Ok((link, ConfigXdpMode::Driver)),
            Err(err) => {
                info!("'{interface}' does not support native XDP ({err}), using generic skb mode");
                let link = program
                    .attach(interface, XdpMode::Skb)
                    .with_context(|| format!("failed to attach to interface '{interface}'"))?;
                Ok((link, ConfigXdpMode::Skb))
            }
        },
        ConfigXdpMode::Driver => {
            let link = program
                .attach(interface, XdpMode::Driver)
                .with_context(|| {
                    format!(
                        "failed to attach to interface '{interface}' in native driver mode \
                     (the NIC driver may not support XDP; try mode = \"skb\")"
                    )
                })?;
            Ok((link, ConfigXdpMode::Driver))
        }
        ConfigXdpMode::Skb => {
            let link = program.attach(interface, XdpMode::Skb).with_context(|| {
                format!("failed to attach to interface '{interface}' in skb mode")
            })?;
            Ok((link, ConfigXdpMode::Skb))
        }
    }
}

fn fill_hosts(ebpf: &mut Ebpf, hashes: &[u64]) -> Result<()> {
    if hashes.is_empty() {
        return Ok(());
    }
    let map = ebpf
        .map_mut("allowed_hosts")
        .context("map 'allowed_hosts' not found")?;
    let mut map: HashMap<_, u64, u8> = HashMap::try_from(map)?;
    for hash in hashes {
        map.insert(hash, 1, 0)
            .context("failed to fill map 'allowed_hosts'")?;
    }
    Ok(())
}

/// Fills an allow list. Its keys are built like those of the deny list.
fn fill_list<F: deny::Family>(ebpf: &mut Ebpf, name: &str, nets: &[F]) -> Result<()> {
    if nets.is_empty() {
        return Ok(());
    }
    let map = ebpf
        .map_mut(name)
        .with_context(|| format!("map '{name}' not found"))?;
    let mut trie: LpmTrie<_, F::Addr, u8> = LpmTrie::try_from(map)?;
    for net in nets {
        trie.insert(&net.key(), 1, 0)
            .with_context(|| format!("failed to fill map '{name}'"))?;
    }
    Ok(())
}

/// Brings one deny map in line with the config; returns how many bans added
/// at runtime it still holds.
fn sync_deny<F: deny::Family>(ebpf: &mut Ebpf, nets: &[F]) -> Result<usize> {
    let map = ebpf
        .map_mut(F::MAP)
        .with_context(|| format!("map '{}' not found", F::MAP))?;
    deny::sync_config::<F, _>(&mut LpmTrie::try_from(map)?, nets)
}

/// Seed for hashing IPv6 addresses into the flow tables. It has to stay the
/// same for as long as the pinned tables live (until reboot) and must not be
/// known outside: the boot id of the kernel is both.
fn flow6_seed() -> u64 {
    match std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(boot_id) => hosts::hash(boot_id.trim()),
        Err(e) => {
            warn!("Cannot read the boot id ({e}); IPv6 connections will not survive a restart of the loader");
            random_seed()
        }
    }
}

/// One line per protection, so the log shows what is actually enforced.
fn log_protection(config: &Config, cpus: u32, adopt_mode: u8) {
    let ports = |start: u16, end: u16| {
        if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        }
    };
    let java = &config.java;
    if java.start_port != 0 {
        info!(
            "Java: tcp {} ({})",
            ports(java.start_port, java.end_port),
            if java.hosts.is_empty() {
                "any host".to_owned()
            } else {
                format!("{} allowed hosts", java.hosts.len())
            }
        );
    }
    let guard = &config.tcp_guard;
    if guard.start_port != 0 {
        info!("TCP guard: tcp {}", ports(guard.start_port, guard.end_port));
    }
    let bedrock = &config.bedrock;
    if bedrock.start_port != 0 {
        info!(
            "Bedrock RakNet: udp {}",
            ports(bedrock.start_port, bedrock.end_port)
        );
    }
    let nethernet = &config.nethernet;
    if nethernet.ice_start_port != 0 {
        info!(
            "NetherNet ICE: udp {}",
            ports(nethernet.ice_start_port, nethernet.ice_end_port)
        );
    }
    let udp_guard = &config.udp_guard;
    if udp_guard.start_port != 0 {
        info!(
            "UDP guard: udp {}",
            ports(udp_guard.start_port, udp_guard.end_port)
        );
    }
    info!("IPv6 to the protected ports: {:?}", config.xdp.ipv6);
    let attack = &config.attack;
    info!(
        "Challenge: {:?} (table of {} slots, {} MiB); budgets are split over {cpus} cpus",
        attack.challenge,
        attack.retry_table_slots,
        u64::from(attack.retry_table_slots) * 8 >> 20
    );
    if adopt_mode != 0 {
        info!(
            "Adopting existing connections for {}s ({:?})",
            config.xdp.adopt_secs, config.xdp.adopt
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_totals_over_cpus() {
        assert_eq!(per_cpu(0, 12), 0); // unlimited stays unlimited
        assert_eq!(per_cpu(1200, 12), 100);
        assert_eq!(per_cpu(100, 12), 9); // rounded up
        assert_eq!(per_cpu(5, 12), 1); // never rounded down to "unlimited"
        assert_eq!(per_cpu(7, 1), 7);
    }

    #[test]
    fn retry_ticks_cover_the_configured_times() {
        // 200ms -> 3 ticks of ~67ms, 10s -> 150 ticks
        assert_eq!((200u64 * 1_000_000).div_ceil(RETRY_TICK_NS), 3);
        assert_eq!((10_000u64 * 1_000_000).div_ceil(RETRY_TICK_NS), 150);
    }
}
