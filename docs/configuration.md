# Configuration reference

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
dropped and why. [`deploy/monitoring`](../deploy/monitoring) has a scrape job,
alert rules for vmalert / Prometheus and a Grafana dashboard.

**`[logging]`** — `level`, `file_max_mb`.

**`[telemetry]`** — `enabled` (default `true`), `endpoint`. See
[Telemetry](../README.md#telemetry).
