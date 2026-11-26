#!/usr/bin/env bash
# minecraft-xdp-guard installer.
#
#   curl -fsSL https://raw.githubusercontent.com/regksemx/minecraft-xdp-guard/main/install.sh | sudo bash
#   ... | sudo bash -s -- --yes --hosts play.example.com,*.example.com
#
# Finds the interface and the game ports, writes /etc/minecraft-xdp/config.toml
# (only on the first install), installs the latest release and a systemd unit,
# and runs `xdp-loader doctor`. Run it again to upgrade: the new binary takes
# over the running filter without disconnecting anybody.
#
# Releases are checked against their SHA256SUMS and, when an authenticated `gh`
# is on the machine, against their GitHub build attestation.
#
# Options:
#   --yes                 do not ask, take what was found
#   --interface IF        the interface players arrive on (default: the one of the default route)
#   --hosts a,b           host names players connect with ([java] hosts)
#   --telemetry           send anonymous counts without asking (see README#telemetry)
#   --no-telemetry        [telemetry] enabled = false, without asking
#   --version vX.Y.Z      a release other than the latest
#   --binary PATH         install this xdp-loader instead of downloading one
#   --no-service          do not install or start the systemd unit (containers)
#   --uninstall           stop the filter and remove binary and unit (config stays)
#   --purge               with --uninstall: also remove config, logs and state
set -euo pipefail

REPO="regksemx/minecraft-xdp-guard"
BIN=/usr/local/sbin/xdp-loader
CONF_DIR=/etc/minecraft-xdp
CONF=$CONF_DIR/config.toml
LOG_DIR=/var/log/minecraft-xdp
UNIT=/etc/systemd/system/minecraft-xdp.service

yes=0 interface="" hosts="" telemetry="" version="latest" binary="" service=1 uninstall=0 purge=0
while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y) yes=1 ;;
        --interface) interface="$2"; shift ;;
        --hosts) hosts="$2"; shift ;;
        --telemetry) telemetry=1 ;;
        --no-telemetry) telemetry=0 ;;
        --version) version="$2"; shift ;;
        --binary) binary="$2"; shift ;;
        --no-service) service=0 ;;
        --uninstall) uninstall=1 ;;
        --purge) purge=1 ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -t 1 ]; then G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' B=$'\e[1m' D=$'\e[2m' N=$'\e[0m'; else G="" Y="" R="" B="" D="" N=""; fi
ok()   { echo "  ${G}✓${N} $*"; }
warn() { echo "  ${Y}!${N} $*"; }
die()  { echo "  ${R}✗${N} $*" >&2; exit 1; }
# questions go to the terminal even when the script itself comes from a pipe
ask() {
    local prompt="$1" default="$2" answer=""
    if [ "$yes" = 1 ] || [ ! -r /dev/tty ]; then echo "$default"; return; fi
    read -r -p "  $prompt " answer </dev/tty || true
    echo "${answer:-$default}"
}

echo "${B}minecraft-xdp-guard installer${N}"
[ "$(id -u)" = 0 ] || die "run as root: curl ... | sudo bash"

if [ "$uninstall" = 1 ]; then
    if [ -f "$UNIT" ]; then
        systemctl disable --now minecraft-xdp >/dev/null 2>&1 || true
        rm -f "$UNIT"; systemctl daemon-reload
        ok "service stopped and removed (the filter is detached)"
    fi
    rm -f "$BIN" && ok "removed $BIN"
    if [ "$purge" = 1 ]; then
        rm -rf "$CONF_DIR" "$LOG_DIR" /sys/fs/bpf/minecraft-xdp && ok "removed $CONF_DIR, $LOG_DIR and the pinned state"
    else
        echo "  config kept in $CONF_DIR (--purge removes it)"
    fi
    exit 0
fi

# the machine
[ "$(uname -s)" = Linux ] || die "Linux only"
arch=$(uname -m)
[ "$arch" = x86_64 ] || [ -n "$binary" ] || die "releases are built for x86_64 only (this is $arch): build from source, then --binary target/release/xdp-loader"
kernel=$(uname -r)
IFS=. read -r kmaj kmin _ <<<"$kernel"; kmin=${kmin%%[!0-9]*}
if [ "$kmaj" -lt 5 ] || { [ "$kmaj" -eq 5 ] && [ "$kmin" -lt 11 ]; }; then die "kernel $kernel: 5.11 or newer is needed"; fi
grep -qs ' /sys/fs/bpf bpf ' /proc/mounts || mount -t bpf bpf /sys/fs/bpf || die "can not mount /sys/fs/bpf"
command -v ss >/dev/null || die "ss (iproute2) is missing"
ok "Linux $kernel, $arch, root, /sys/fs/bpf mounted"

if [ -z "$interface" ]; then
    interface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
    [ -n "$interface" ] || interface=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
fi
[ -n "$interface" ] && [ -e "/sys/class/net/$interface" ] || die "no interface found: pass --interface"
driver=$(basename "$(readlink "/sys/class/net/$interface/device/driver" 2>/dev/null)" 2>/dev/null || true)
ok "interface: $interface${driver:+, driver $driver} (--interface to change)"

# the game ports: what listens here, besides loopback
sockets=$(ss -Hlntup 2>/dev/null || true)
listening() { # proto port -> "v4", "v6" (or dual stack), or nothing
    awk -v p="$1" -v port="$2" '
        $1 == p {
            n = split($5, a, ":"); if (a[n] != port) next
            addr = substr($5, 1, length($5) - length(port) - 1)
            if (addr ~ /^(127\.|\[::1\]|\[::ffff:127\.)/) next
            v6 = (addr ~ /^\[/ || addr == "*") ? 1 : v6
            found = 1
        }
        END { if (found) print (v6 ? "v6" : "v4") }' <<<"$sockets"
}
proxied() { # proto port -> true if docker-proxy holds it (DNAT into a container)
    awk -v p="$1" -v port="$2" '$1 == p && $5 ~ (":" port "$") && /docker-proxy/ { f = 1 } END { exit !f }' <<<"$sockets"
}
java=$(listening tcp 25565) bedrock=$(listening udp 19132) signal=$(listening tcp 19132) voice=$(listening udp 24454)
echo "  found listening:"
for line in "tcp 25565 java:$java" "udp 19132 bedrock:$bedrock" "tcp 19132 NetherNet signaling:$signal" "udp 24454 voice chat:$voice"; do
    state=${line##*:}
    [ -n "$state" ] && echo "    ${line%:*}${D}${state:+ ($state)}${N}"
done
[ -n "$java$bedrock$signal$voice" ] || warn "no game ports listen on this host: protecting tcp 25565 (Java) anyway"
blind=0
for p in "tcp 25565" "udp 19132" "tcp 19132" "udp 24454"; do proxied $p && blind=1; done

# the release
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if [ -n "$binary" ]; then
    cp "$binary" "$tmp/xdp-loader"
    ok "using $binary"
else
    if [ "$version" = latest ]; then base="https://github.com/$REPO/releases/latest/download"; else base="https://github.com/$REPO/releases/download/$version"; fi
    fetch() { if command -v curl >/dev/null; then curl -fsSL -o "$2" "$1"; else wget -qO "$2" "$1"; fi; }
    fetch "$base/xdp-loader" "$tmp/xdp-loader" || die "download failed: $base/xdp-loader"
    if fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null; then
        (cd "$tmp" && sha256sum --ignore-missing -c SHA256SUMS >/dev/null) || die "sha256 mismatch: refusing to install"
        ok "downloaded $("$tmp/xdp-loader" -V | awk '{print $2}'), sha256 ok"
    else
        warn "this release has no SHA256SUMS: installed without a checksum"
    fi
    # the checksums come from the same place as the binary; the attestation
    # proves GitHub Actions built it from this repository
    case "$version" in v1.0.[0-3]) attest=0 ;; *) attest=1 ;; esac # older releases have none
    if [ "$attest" = 1 ] && command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
        gh attestation verify "$tmp/xdp-loader" --repo "$REPO" >"$tmp/attest.log" 2>&1 \
            || { cat "$tmp/attest.log" >&2; die "the build attestation does not match: refusing to install"; }
        ok "build attestation verified (GitHub Actions, $REPO)"
    fi
fi
chmod 755 "$tmp/xdp-loader"

# the configuration: written once, an existing one is kept
install -d -m 755 "$CONF_DIR" "$LOG_DIR"
fresh=0
if [ ! -f "$CONF" ]; then
    fresh=1
    "$tmp/xdp-loader" --check -c "$CONF" >/dev/null 2>&1 || true # writes the documented defaults
    [ -f "$CONF" ] || die "could not write $CONF"
    set_key() { # section key value: replace `key = ...` within [section]
        awk -v s="[$1]" -v k="$2" -v v="$3" '
            /^\[/ { in_s = ($0 == s) }
            in_s && !done && $0 ~ ("^" k " *=") { print k " = " v; done = 1; next }
            { print }' "$CONF" >"$CONF.tmp" && mv "$CONF.tmp" "$CONF"
    }
    if [ -z "$hosts" ]; then hosts=$(ask "Host names players connect with, comma separated (empty: any):" ""); fi
    if [ -n "$hosts" ]; then
        list=$(tr ',' '\n' <<<"$hosts" | sed 's/^ *//; s/ *$//' | grep -v '^$' | sed 's/.*/"&"/' | paste -sd, - | sed 's/,/, /g')
        set_key java hosts "[$list]"
    fi
    if [ -n "$bedrock" ]; then
        set_key bedrock start_port 19132; set_key bedrock end_port 19132
        if [ "$kmaj" -gt 5 ] || [ "$kmin" -ge 18 ]; then set_key bedrock pong_from '"127.0.0.1:19132"'; fi
    fi
    if [ -n "$signal" ]; then set_key tcp_guard start_port 19132; set_key tcp_guard end_port 19132; fi
    if [ -n "$voice" ]; then set_key voice start_port 24454; set_key voice end_port 24454; fi
    if [ "$java" = v6 ] || [ "$bedrock" = v6 ] || [ "$signal" = v6 ] || [ "$voice" = v6 ]; then set_key xdp ipv6 '"inspect"'; fi
    [ "$blind" = 1 ] && set_key xdp adopt '"blind"'
    set_key metrics enabled true
    sed -i 's|^# addr = "127.0.0.1:1999"|addr = "127.0.0.1:1999"|' "$CONF"
    if [ -z "$telemetry" ]; then
        echo "  Telemetry: every 30 min an anonymous report (version, kernel, player and packet"
        echo "  counts; no addresses, host names or config) for the totals on https://stats.olune.me"
        case "$(ask "Send it? [Y/n]" y)" in [nN]*) telemetry=0 ;; *) telemetry=1 ;; esac
    fi
    [ "$telemetry" = 0 ] && set_key telemetry enabled false
    ok "$CONF written${hosts:+ (hosts: $hosts)}"
else
    ok "keeping $CONF"
fi
"$tmp/xdp-loader" --check -c "$CONF" >"$tmp/check.log" 2>&1 || { cat "$tmp/check.log" >&2; die "the kernel rejects the filter with this config"; }
ok "the kernel accepts the filter (--check)"

install -m 755 "$tmp/xdp-loader" "$BIN.new" && mv -f "$BIN.new" "$BIN"
ok "installed $BIN"

if [ "$service" = 1 ]; then
    command -v systemctl >/dev/null || die "no systemd: run $BIN -c $CONF $interface yourself, or use --no-service"
    cat >"$UNIT" <<EOF
# written by install.sh of $REPO
[Unit]
Description=Minecraft XDP filter
After=network-online.target sys-fs-bpf.mount
Wants=network-online.target

[Service]
WorkingDirectory=$LOG_DIR
ExecStart=$BIN --config $CONF $interface
# the loader exits and leaves the filter attached; Restart= starts the new one
ExecReload=/bin/kill -USR1 \$MAINPID
Restart=always
RestartSec=1
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    if systemctl is-active -q minecraft-xdp; then
        systemctl reload minecraft-xdp
        ok "minecraft-xdp.service reloaded: the new binary took over without a gap"
    else
        systemctl enable --now minecraft-xdp >/dev/null 2>&1
        ok "minecraft-xdp.service enabled and started"
    fi
    sleep 3
fi

echo
"$BIN" doctor -c "$CONF" || true
echo
if [ "$telemetry" != 0 ] && grep -q '^enabled = true' <(awk '/^\[telemetry\]/{f=1;next} /^\[/{f=0} f' "$CONF"); then
    echo "  Telemetry is on: anonymous counts, see https://github.com/$REPO#telemetry (off: [telemetry] enabled = false)"
fi
echo "  Config:  $CONF, then: systemctl reload minecraft-xdp"
echo "  Logs:    journalctl -u minecraft-xdp, $LOG_DIR/xdp-loader.log"
echo "  Check:   sudo xdp-loader doctor"
echo "  Undo:    curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo bash -s -- --uninstall"
[ "$fresh" = 1 ] && [ -z "$hosts" ] && echo "  ${Y}Tip:${N} set [java] hosts to the names players use: attacks on the bare IP stop at the filter."
exit 0
