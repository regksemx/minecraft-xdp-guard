# Minecraft XDP Filter using eBPF – L7 DDoS Protection

A high-performance XDP firewall for Minecraft servers and proxies. It drops
malicious packets at the driver level, before the kernel network stack or the
server spends anything on them.

This is a fork of [Outfluencer/Minecraft-XDP-eBPF](https://github.com/Outfluencer/Minecraft-XDP-eBPF)
(Java Edition, versions 1.8 - 26.3) that adds Bedrock Edition, NetherNet and
an attack mode built for small machines.

| Protected | Transport | What a client has to prove |
|-----------|-----------|----------------------------|
| Minecraft Java | TCP | TCP handshake, valid Minecraft handshake, then status + ping or a login |
| Bedrock (RakNet) | UDP | OpenConnectionRequest 1 and 2 from the same address |
| NetherNet data channels | UDP | STUN binding request first, then only STUN and DTLS |
| Generic TCP guard (NetherNet signaling) | TCP | TCP handshake, then a TLS ClientHello or an HTTP request |
| Simple Voice Chat | UDP | the frame of its packets: magic byte, connection id, a payload length that matches the datagram; a session is bound to its connection id |
| Generic UDP guard | UDP | nothing: every datagram needs a minimum size and optionally a fixed first byte, the limits do the rest |

Everything else aimed at a protected port is dropped. IPv6 is either ignored,
dropped for the protected ports, or inspected by the same rules as IPv4
(`[xdp] ipv6`).

## Features

- **Protocol inspection**: Java handshake, status, ping and login packets
  (bad VarInts, wrong lengths, legacy pings, oversized names), RakNet offline
  messages (magic, protocol version, sizes), STUN, TLS / HTTP openers.
- **Fast path**: a verified connection costs one hash lookup per packet.
- **Host filter**: only handshakes for your own host names get through, which
  stops everything that attacks the bare IP address.
- **Per IP limits**: new connections, status requests, Bedrock pings and new
  Bedrock sessions per source IP.
- **Retransmit challenge**: while a flood of unknown source IPs is running,
  an unknown IP only gets in with the retransmit of its first packet. Real
  clients retransmit by themselves; spoofed floods never do and cost one array
  access per packet.
- **Budgets and proven players**: caps on logins, status requests, pings and
  new sessions per second. IPs that played for a few minutes are exempt, so
  regular players keep getting in while bots fight over the budget.
- **Bedrock pings answered by the filter**: the loader keeps the server's
  pong in a map and the filter replies from it, so server list pings and
  ping floods never reach the server.
- **Packet rate limit** per verified connection.
- **Allow and deny lists** (IPv4 and IPv6 networks). Bans can be added while
  the filter runs, with a lifetime, and cut the banned address off
  immediately.
- **IPv6**: inspected by the same rules, in the same tables.
- **Restart without disconnects and without a gap**: verified connections
  and known IPs live in pinned maps and survive a restart of the loader, and
  a reload swaps the program atomically. A crashed loader leaves the filter
  running. Connections that existed before the first start are adopted.
- **Prometheus metrics** and flood reports in the log.

No timers and no userspace round trips: all state expires lazily inside the
program, and LRU maps bound the memory.

## Installation (Linux)

### Prerequisites
- Linux kernel 5.11 or newer (developed and tested on 6.8)
- Rust toolchain (stable, 1.98 or newer)
- **System Dependencies**:
  ```bash
  sudo apt update
  sudo apt install -y gcc-multilib wget gnupg software-properties-common git libbpf-dev
  ```
  If software-properties-common was not found remove it from the command.
- **LLVM/Clang Toolchain** (19 or newer):
  ```bash
  wget https://apt.llvm.org/llvm.sh
  chmod +x llvm.sh
  sudo ./llvm.sh 21 all
  ```

### Build & Run
1.  **Build the project**:
    ```bash
    ./build.sh
    ```
    The compiled binary will be at `target/release/xdp-loader`. On macOS, or
    to keep the toolchain off the host, build inside the container instead:
    `dev/run.sh cargo build --release`.

2.  **Run the firewall**:
    ```bash
    sudo ./target/release/xdp-loader <network_interface>
    # Example:
    sudo ./target/release/xdp-loader eth0
    ```
    On first run a documented `config.toml` is written to the working
    directory; by default only Java on port 25565 is protected. A complete
    example for a Java + Bedrock + NetherNet entry node is in
    [`deploy/config.edge.toml`](deploy/config.edge.toml), a systemd unit in
    [`deploy/minecraft-xdp.service`](deploy/minecraft-xdp.service).

**Stopping and restarting**

| | Filter | Players |
|---|---|---|
| `SIGTERM`, `SIGINT` (`systemctl stop`) | detached, traffic passes unfiltered | stay connected |
| `SIGUSR1`, `SIGHUP` (`systemctl reload`) | stays attached; the next start replaces the program atomically, without a gap | stay connected |
| loader crashes or is killed | stays attached; the restarted loader takes over | stay connected |

Use `reload` to apply a new configuration or binary. The attachment and the
tables of verified connections, known IPs and bans are pinned in
`/sys/fs/bpf/minecraft-xdp`; `--reset-state` forgets connections and known
IPs, and `xdp-loader detach <interface>` removes the filter of a loader that
is gone.

## Configuration

Runtime behavior is controlled by a `config.toml` file. On first run it is
created automatically with every option documented; edit it and restart the
loader. Use `--config <path>` to point at a different file. All values are
pushed into the eBPF program at load time, so changing them only requires a
restart — **not a rebuild** — and a disabled feature costs nothing per packet.

A port range with `start_port = 0` switches that protection off.

**`[java]`** — Minecraft Java Edition (TCP)

| Option | Default | Description |
|--------|---------|-------------|
| `start_port`, `end_port` | 25565 | Inclusive port range. |
| `online_names` | true | Enforce online-mode usernames (≤16 chars). |
| `hosts` | `[]` | Host names accepted in the handshake (the name players type, SRV targets, the IP if players may use it). Empty = any. |
| `protocol_min`, `protocol_max` | 0 | Protocol versions allowed to log in (0 = no bound). |

**`[tcp_guard]`** — other TCP services where the client talks first

| Option | Default | Description |
|--------|---------|-------------|
| `start_port`, `end_port` | 0 | Inclusive port range, e.g. 19132 for NetherNet signaling. |
| `allow_tls`, `allow_http` | true | What the first payload may be. |

**`[bedrock]`** — Bedrock Edition (RakNet over UDP)

| Option | Default | Description |
|--------|---------|-------------|
| `start_port`, `end_port` | 0 | Inclusive port range, usually 19132. |
| `raknet_protocol_min`, `raknet_protocol_max` | 9, 11 | Accepted RakNet protocol versions. |
| `open_request_min_size` | 400 | Minimum size of OpenConnectionRequest1 (clients pad it to the MTU). |
| `pong_from` | `""` | Address of the real server, e.g. `127.0.0.1:19132`. The filter then answers server list pings itself with that server's last pong; pings never reach the server. Needs kernel 5.18. |
| `pong_refresh_secs` | 5 | How often the loader fetches the pong. |

**`[nethernet]`** — NetherNet WebRTC data channels (UDP)

| Option | Default | Description |
|--------|---------|-------------|
| `ice_start_port`, `ice_end_port` | 0 | Inclusive port range of the ICE candidates. |

**`[voice]`** — [Simple Voice Chat](https://github.com/henkelmax/simple-voice-chat) (UDP)

| Option | Default | Description |
|--------|---------|-------------|
| `start_port`, `end_port` | 0 | Inclusive port range, 24454 unless the voice chat is configured otherwise. |
| `flow_pps` | 200 | Packets per second of one voice session (a talking client sends 50). 0 = unlimited. |
| `allow_pings` | true | Pass the unauthenticated ping of external tools (limited by `pings_per_ip`). |

Voice packets are encrypted, so the filter checks their frame and binds each
session to the connection id that opened it; another id from the same address
is a new session, limited by `udp_sessions_per_ip`, `udp_session_budget` and
the challenge. Written against mod 2.7 (also the packets of 2.5 and 2.6).

**`[udp_guard]`** — other UDP services

| Option | Default | Description |
|--------|---------|-------------|
| `start_port`, `end_port` | 0 | Inclusive port range. |
| `first_byte` | -1 | Every datagram has to start with this byte (0-255), -1 = any. |
| `min_size` | 1 | Minimum payload size of every datagram. |

New sessions count against `udp_sessions_per_ip` and `udp_session_budget`,
unknown IPs are challenged, and `udp_flow_pps` caps each session.

**`[limits]`** — per source IP, within windows of `window_secs`

| Option | Default | Description |
|--------|---------|-------------|
| `window_secs` | 3 | Length of the counting window. |
| `syn_per_ip` | 10 | New TCP connections. |
| `status_per_ip` | 10 | Java status requests. |
| `pings_per_ip` | 20 | Bedrock unconnected pings. |
| `udp_sessions_per_ip` | 8 | New Bedrock / NetherNet sessions. |
| `tcp_idle_secs`, `udp_idle_secs` | 60, 30 | A verified connection is forgotten after this long without packets. |
| `tcp_flow_pps`, `udp_flow_pps` | 0 | Packets per second of one verified connection (0 = unlimited). |

**`[attack]`** — behavior during floods (totals per second, split over the cpus)

| Option | Default | Description |
|--------|---------|-------------|
| `challenge` | `"auto"` | Retransmit challenge for unknown IPs: `"auto"` (only during a flood of unknown IPs), `"always"`, `"off"`. |
| `challenge_new_ips_per_sec` | 400 | Unknown IPs per second that arm the challenge in `"auto"` mode. |
| `challenge_hold_secs` | 30 | How long it stays armed after the flood. |
| `retry_min_ms`, `retry_max_ms` | 200, 10000 | When a retransmit is accepted. |
| `retry_table_slots` | 1048576 | Size of the challenge table (power of two, 8 bytes per slot). Size it for the flood rate the port can carry: 16777216 for 1 Gbit/s. |
| `syn_budget`, `login_budget`, `status_budget`, `ping_budget`, `udp_session_budget` | 0 | New work per second accepted from IPs that are not proven players (0 = unlimited). |
| `good_after_secs` | 180 | A game connection of this age makes its IP a proven player (0 = never). |
| `good_ttl_hours` | 72 | How long that lasts. |

**`[lists]`** — `allow` and `deny`: IPv4 and IPv6 addresses or networks that
are never inspected, or always dropped, on the protected ports.

Bans do not need a restart:

```bash
xdp-loader deny -c /etc/minecraft-xdp/config.toml add --ttl 3600 203.0.113.7   # for an hour
xdp-loader deny -c /etc/minecraft-xdp/config.toml add 198.51.100.0/24          # until removed
xdp-loader deny -c /etc/minecraft-xdp/config.toml list
xdp-loader deny -c /etc/minecraft-xdp/config.toml del 198.51.100.0/24
```

A ban takes effect with the next packet, also cuts the connections the
address has open (IPv6 ones within a second), and survives a restart of the
loader. `add -` reads
addresses from stdin, which makes it easy to feed from an anti-cheat or a
log watcher.

**`[xdp]`** — attachment, state and table sizes

| Option | Default | Description |
|--------|---------|-------------|
| `mode` | `"auto"` | `"auto"` (native if the NIC supports it, else generic), `"driver"`, `"skb"`. |
| `ipv6` | `"pass"` | IPv6 packets for the protected ports: `"pass"` (ignored: only safe if the services are not reachable over IPv6), `"drop"`, `"inspect"` (same rules as IPv4; limits per IP count per /64). |
| `keep_state` | true | Keep verified connections, known IPs and bans across restarts. |
| `state_dir` | `/sys/fs/bpf/minecraft-xdp` | Where the state maps are pinned. |
| `adopt` | `"socket"` | Connections from before the start: `"socket"` (TCP only if this host's kernel has the connection), `"blind"`, `"off"`. |
| `adopt_secs` | 30 | For how long after the start they are adopted. |
| `max_pending_connections` | 16384 | TCP connections mid-inspection. |
| `max_player_connections` | 65536 | Verified TCP connections. |
| `max_pending_udp_sessions` | 16384 | Bedrock clients between their two requests. |
| `max_udp_sessions` | 65536 | Verified UDP sessions. |
| `max_tracked_ips` | 262144 | Source IPs with counters and the proven player mark. |

**`[metrics]`** — `enabled`, `addr` (e.g. `127.0.0.1:1999`, serves `/metrics`),
`poll_secs`. With metrics enabled the log also reports floods: what is being
dropped and why. [`deploy/monitoring`](deploy/monitoring) has a scrape job,
alert rules for vmalert / Prometheus and a Grafana dashboard.

**`[logging]`** — `level`, `file_max_mb`.

## Things to know

- **Host filter and SRV records**: clients that resolve a SRV record send the
  SRV *target* in the handshake, not the name the player typed. List both.
- **The first data packet finishes the TCP handshake.** The filter drops the
  bare ACK of the TCP handshake on purpose, so the server only ever sees
  connections whose first packet passed inspection. This needs protocols
  where the client talks first; do not put SSH, SMTP or MySQL behind the TCP
  guard.
- **Bots with real IPs and valid logins pass**, as they must: that is what
  the per IP limits, the login budget and a limbo / anti-bot plugin are for.
- **IPv6 flows are stored by a hash of their addresses**, keyed with a
  per-boot secret, in the same tables as IPv4 flows; the limits per IP apply
  to the /64 of the source. Fragments and packets with more than four
  extension headers are dropped for the protected ports. Bedrock pings over
  IPv6 are answered by the server, not from the pong cache.
- **Native XDP needs driver support** (igb, ixgbe, i40e, ice, mlx4/5, bnxt,
  virtio_net, ...). Generic mode works everywhere and is several times
  slower, which is still plenty for a 1 Gbit/s port.

## Tests

```bash
dev/run.sh                    # everything, inside a container (needs Docker)
cargo test                    # Rust tests + native C tests of the parsers (ASan/UBSan)
sudo dev/kernel-test.sh       # the real BPF program in the running kernel, packet by packet
sudo dev/kernel-test.sh bench # cost per packet on the important paths
sudo dev/e2e-test.sh          # the real loader between a client and stand-in servers
sudo dev/load-test.sh         # spoofed floods from all cpus while real clients keep playing
```

To find out whether the kernel of a machine accepts the filter, run
`xdp-loader --check -c config.toml` there: it loads the program with that
configuration through the verifier and unloads it again, without attaching
anything or touching a running filter. `dev/kernel-test.sh` goes further and
runs every test against that kernel; it attaches nothing either, but needs
clang, libbpf and bpftool.

## Troubleshooting

### Non-root / Permission Errors
Please always check if you are running as root if any error occurred. If you are not, try again with `sudo`.

### Players can not connect after enabling `hosts`
The name they use is missing from the list; `minecraft_bad_host` in the
metrics counts those handshakes.
