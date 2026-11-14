#!/usr/bin/env python3
"""End-to-end test: the real loader with the real XDP program between a
client and stand-in servers.

Two network namespaces are joined by a veth pair; the loader attaches to the
server end in generic (skb) mode. A client process in the other namespace
then plays good and bad clients, and the loader is restarted in between to
check what happens to established connections.

Run as root on Linux (dev/run.sh dev/e2e-test.sh does it in a container).
"""
import os
import sys
import time

from harness import STATE_DIR, Client, Loader, check, setup, summary, teardown

CONFIG = """
[java]
start_port = 25565
end_port = 25565
hosts = ["mc.e2e.test", "10.99.0.1"]

[tcp_guard]
start_port = 19132
end_port = 19132

[bedrock]
start_port = 19132
end_port = 19132

[nethernet]
ice_start_port = 27020
ice_end_port = 27029

[limits]
window_secs = 2
syn_per_ip = {syn_per_ip}
status_per_ip = 3

[attack]
challenge = "{challenge}"
good_after_secs = 0

[lists]
allow = {allow}
deny = {deny}

[xdp]
mode = "skb"
drop_ipv6 = true
keep_state = true
state_dir = "{state_dir}"
adopt = "{adopt}"
adopt_secs = 20

[metrics]
enabled = true
addr = "127.0.0.1:1999"
poll_secs = 1

[logging]
level = "info"
"""


DEFAULTS = {"challenge": "auto", "adopt": "off", "syn_per_ip": 100, "allow": [], "deny": []}


def main():
    workdir, events, server = setup()
    client = Client()
    loader = Loader(os.path.abspath(sys.argv[1]), workdir, CONFIG)

    # ---- without the filter everything reaches the servers -----------------
    client.expect("tcp_raw 8080 00", "reply")
    client.expect("rak_stray", "ok")
    check("servers reachable before the filter is attached", len(events()) == 1)

    # ---- phase 1: fresh filter -------------------------------------------
    loader.start(**DEFAULTS)

    # Java
    client.expect("java_status mc.e2e.test", "ok")
    java = client.expect("java_login Steve mc.e2e.test", "ok")
    client.expect(f"echo {java}", "ok")
    java_split = client.expect("java_login Alex MC.E2E.Test. 1", "ok")
    client.expect(f"echo {java_split}", "ok")
    client.expect("java_login Bot evil.example.com", "timeout")       # host not allowed
    client.expect("java_status 203.0.113.9", "timeout")
    client.expect("java_login ThisNameIsWayTooLongForMojang mc.e2e.test", "timeout")
    client.expect("tcp_raw 25565 474554202f20485454502f312e310d0a0d0a", "timeout")  # "GET / HTTP/1.1"
    client.expect("tcp_raw 25565 fe01", "timeout")                     # legacy ping
    logins = [e for e in events() if e.startswith("java")]
    check("only valid Java clients reached the server",
          logins == ["java status mc.e2e.test", "java login mc.e2e.test Steve", "java login MC.E2E.Test. Alex"],
          str(logins))

    # status limit: 3 per ip within a window of 2s
    time.sleep(2.1)
    for _ in range(3):
        client.expect("java_status mc.e2e.test", "ok")
    client.expect("java_status mc.e2e.test", "timeout")

    # NetherNet signaling stand-in on the guard port
    client.expect("http 19132", "ok")
    client.expect("tcp_raw 19132 5353482d322e302d4f70656e5353480d0a", "timeout")   # "SSH-2.0-OpenSSH"
    check("only HTTP reached the guarded port", [e for e in events() if e.startswith("http")] == ["http GET"])

    # Bedrock
    client.expect("rak_ping", "ok")
    raknet = client.expect("rak_connect", "ok")
    client.expect(f"rak_data {raknet}", "ok")
    client.expect("rak_stray", "timeout")                              # game traffic without a session

    # NetherNet ICE
    ice = client.expect("ice_open", "ok")
    client.expect(f"ice_dtls {ice}", "ok")
    client.expect("ice_stray", "timeout")

    # unprotected ports are none of the filter's business
    client.expect("tcp_raw 8080 00", "reply")

    time.sleep(1.5)  # one metrics poll
    check("metrics: verified logins", loader.metric("minecraft_verified_connections") == 2)
    check("metrics: raknet sessions", loader.metric("minecraft_raknet_verified") == 1)
    check("metrics: ice sessions", loader.metric("minecraft_ice_verified") == 1)
    check("metrics: guard connections", loader.metric("minecraft_guard_verified") == 1)
    check("metrics: bad hosts", loader.metric("minecraft_bad_host") == 2)
    check("metrics: status throttled", loader.metric("minecraft_status_throttled") == 1)
    check("metrics: dropped packets", loader.metric("minecraft_dropped_packets") > 10)

    # ---- phase 2: restart, state is kept (adoption is off) ---------------
    loader.stop()
    client.expect(f"echo {java}", "ok")                                # no filter in between
    output = loader.start(**DEFAULTS)
    check("pinned maps are reused", output.count("Reusing pinned map") == 4, output)
    client.expect(f"echo {java}", "ok")
    client.expect(f"echo {java_split}", "ok")
    client.expect(f"rak_data {raknet}", "ok")
    client.expect(f"ice_dtls {ice}", "ok")
    client.expect("rak_stray", "timeout")
    time.sleep(1.5)
    check("nothing had to be adopted", loader.metric("minecraft_tcp_adopted") == 0)

    # ---- phase 3: state lost, existing connections are adopted -----------
    loader.stop()
    output = loader.start(reset=True, **{**DEFAULTS, "adopt": "socket"})
    # connections and known ips are forgotten, the deny list is not
    check("state was reset", output.count("Removed pinned map") == 3 and output.count("Reusing pinned map") == 1,
          output)
    client.expect(f"echo {java}", "ok")
    client.expect(f"rak_data {raknet}", "ok")
    client.expect(f"ice_dtls {ice}", "ok")
    # the kernel has no such connection: not adopted
    client.expect("tcp_raw 25565 fe01", "timeout")
    time.sleep(1.5)
    check("metrics: tcp adopted", loader.metric("minecraft_tcp_adopted") == 1)
    check("metrics: udp adopted", loader.metric("minecraft_udp_adopted") == 2)

    # ---- phase 4: state lost, no adoption, challenge always on -----------
    loader.stop()
    loader.start(reset=True, **{**DEFAULTS, "challenge": "always", "syn_per_ip": 6})
    client.expect(f"echo {java}", "timeout")
    client.expect(f"rak_data {raknet}", "timeout")
    client.expect(f"ice_dtls {ice}", "timeout")

    # an unknown ip gets in with its SYN retransmit (after 1s) ...
    answer = client.ask("connect_time 25565")
    check("first connect of an unknown ip is delayed by the challenge",
          answer.startswith("ok") and 0.9 <= float(answer.split()[1]) <= 2.5, answer)
    # ... and is known afterwards
    answer = client.ask("connect_time 25565")
    check("known ip connects immediately", answer.startswith("ok") and float(answer.split()[1]) < 0.2, answer)
    client.expect("java_login Steve mc.e2e.test", "ok")

    # per ip SYN limit: 6 per 2s window (the kernel retries dropped SYNs
    # only after 1s, longer than the client waits)
    time.sleep(2.1)
    answer = client.ask("syn_burst 25565 12")
    check("syn limit", answer == "ok 6", answer)
    time.sleep(1.5)
    check("metrics: syn throttled", loader.metric("minecraft_syn_throttled") >= 6)
    check("metrics: challenge", loader.metric("minecraft_challenge_passed") == 1)

    # ---- phase 5: deny and allow lists ------------------------------------
    loader.stop()
    loader.start(reset=True, **{**DEFAULTS, "deny": ["10.99.0.0/24", "203.0.113.7"]})
    client.expect("java_status mc.e2e.test", "timeout")
    client.expect("rak_ping", "timeout")
    client.expect("tcp_raw 8080 00", "reply")                          # only the protected ports
    time.sleep(1.5)
    check("metrics: deny list", loader.metric("minecraft_denylist_dropped") >= 2)

    loader.stop()
    loader.start(reset=True, **{**DEFAULTS, "deny": ["10.99.1.0/24"], "allow": ["10.99.0.2"]})
    client.expect("java_status mc.e2e.test", "ok")
    # allowed ips are not inspected: what was dropped in phase 1 gets through
    client.expect("tcp_raw 19132 5353482d322e302d4f70656e5353480d0a", "reply")
    client.expect("rak_stray", "ok")
    time.sleep(1.5)
    check("metrics: allow list", loader.metric("minecraft_allowlist_passed") > 5)
    check("metrics: nothing dropped", loader.metric("minecraft_dropped_packets") == 0)

    # ---- phase 6: bans while the filter runs -----------------------------
    loader.stop()
    loader.start(reset=True, **DEFAULTS)
    java = client.expect("java_login Steve mc.e2e.test", "ok")
    client.expect("rak_ping", "ok")
    check("deny list starts empty", loader.deny("list").strip() == "")

    output = loader.deny("add", "--ttl", "3", "10.99.0.2")
    check("the ban cut the open connection", "banned 1 (1 open connections cut)" in output, output)
    client.expect(f"echo {java}", "timeout")
    client.expect("rak_ping", "timeout")
    client.expect("tcp_raw 8080 00", "reply")                          # only the protected ports
    output = loader.deny("list")
    check("the ban is listed with its remaining time", "10.99.0.2/32" in output and "s left" in output, output)
    time.sleep(2.5)
    client.expect("rak_ping", "ok")                                    # the ban expired
    check("expired bans are removed", loader.deny("list").strip() == "")

    # a ban without an end survives restarts, with and without --reset-state
    loader.deny("add", "10.99.0.0/24", "203.0.113.7")
    client.expect("rak_ping", "timeout")
    loader.stop()
    output = loader.start(**DEFAULTS)
    check("bans are kept across a restart", "2 bans kept" in output, output)
    client.expect("rak_ping", "timeout")
    loader.stop()
    loader.start(reset=True, **DEFAULTS)
    client.expect("rak_ping", "timeout")
    check("del reports what it removed", "removed 1" in loader.deny("del", "10.99.0.0/24"))
    client.expect("rak_ping", "ok")
    check("the other ban is still there", loader.deny("list").split() == ["203.0.113.7/32", "until", "removed"])

    # bans from the config file follow the config file
    loader.stop()
    loader.start(**{**DEFAULTS, "deny": ["10.99.0.2"]})
    client.expect("rak_ping", "timeout")
    check("flush leaves the config entries alone", "removed 1" in loader.deny("flush"))
    check("config entries are listed", loader.deny("list").split() == ["10.99.0.2/32", "config", "file"])
    loader.stop()
    loader.start(**DEFAULTS)
    client.expect("rak_ping", "ok")

    loader.stop()
    check("state is kept after exit", sorted(os.listdir(os.path.join(STATE_DIR, "v1"))) ==
          ["deny_v4", "ip_table", "verified_tcp", "verified_udp"])

    client.close()
    server.kill()
    return summary()


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        teardown()
