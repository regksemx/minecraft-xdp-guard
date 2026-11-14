#!/usr/bin/env python3
"""Load test: floods with spoofed source addresses from several threads
(so several cpus run the filter at once) while real clients keep playing.

For every kind of flood it checks that
  - an established player loses nothing,
  - a proven player can still open new connections,
  - a newcomer nobody has seen before still gets in (with the delay of the
    retransmit challenge),
  - nearly everything of the flood is dropped and it leaves almost no state
    behind (no table churn).

Run as root on Linux: dev/run.sh dev/load-test.sh
"""
import os
import subprocess
import sys
import time

from harness import CLI, SERVER_IP, Client, Loader, check, in_ns, setup, sh, summary, teardown

FLOOD = os.path.abspath(sys.argv[2])
SECONDS = 5
# one flood thread per cpu: on a veth pair the receiving side runs on the cpu
# of the sender, so this is what spreads the flood over all cpus like the
# receive queues of a real NIC do
THREADS = os.cpu_count() or 4
# a 1 Gbit/s port carries at most 1.49 million minimum-size packets per second
GIGABIT_PPS = 1_490_000

CONFIG = """
[java]
start_port = 25565
end_port = 25565
hosts = ["mc.e2e.test"]

[tcp_guard]
start_port = 19132
end_port = 19132

[bedrock]
start_port = 19132
end_port = 19132

[nethernet]
ice_start_port = 27020
ice_end_port = 27029

[attack]
challenge = "auto"
challenge_new_ips_per_sec = 300
retry_table_slots = 16777216
syn_budget = 600
login_budget = 120
status_budget = 120
ping_budget = 600
udp_session_budget = 120
good_after_secs = 2

[xdp]
mode = "skb"
keep_state = false
state_dir = "{state_dir}"
adopt = "off"
max_tracked_ips = 65536

[metrics]
enabled = true
addr = "127.0.0.1:1999"
poll_secs = 1
"""

COUNTERS = ["minecraft_incoming_packets", "minecraft_dropped_packets", "minecraft_new_ips",
            "minecraft_challenge_dropped", "minecraft_challenge_passed", "minecraft_tcp_budget_dropped"]


def main():
    workdir, events, server = setup()
    loader = Loader(os.path.abspath(sys.argv[1]), workdir, CONFIG)
    loader.start()
    server_mac = sh("ip -n mcxdp-srv -br link show veth-srv").stdout.split()[2]

    # a player who has been online long enough to count as proven
    player = Client()
    java = player.expect("java_login Steve mc.e2e.test", "ok")
    raknet = player.expect("rak_connect", "ok")
    ice = player.expect("ice_open", "ok")
    for _ in range(3):
        time.sleep(1.1)
        player.expect(f"echo {java}", "ok")
        player.expect(f"rak_data {raknet}", "ok")
    time.sleep(1.2)
    check("the player's ip is marked as proven", loader.metric("minecraft_good_ips") >= 1)

    def snapshot():
        return {name: loader.metric(name) for name in COUNTERS}

    print(f"{'flood':<12} {'sent':>10} {'pps':>9} {'dropped':>8} {'new ips':>8}  newcomer", flush=True)
    # every kind at the rate of a saturated 1 Gbit/s port, then two as fast
    # as this machine can send, far beyond what the port could carry
    runs = [(kind, GIGABIT_PPS) for kind in ("syn", "ack", "handshake", "ping", "ocr1", "junk", "stun", "replay")]
    runs += [("syn", 0), ("ping", 0)]
    for index, (kind, pps) in enumerate(runs):
        label = kind if pps else kind + " max"
        newcomer_ip = f"10.99.0.{10 + index}"
        sh(f"ip -n {CLI} addr add {newcomer_ip}/24 dev veth-cli")
        newcomer = Client(newcomer_ip)
        before = snapshot()
        argv = [FLOOD, "veth-cli", server_mac, SERVER_IP, kind, str(SECONDS), str(THREADS)]
        flood = in_ns(CLI, argv + ([str(pps)] if pps else []), stdout=subprocess.PIPE)
        time.sleep(1.0)  # let the flood arm the challenge

        # the established player keeps playing ...
        lost = 0
        for _ in range(4):
            for command in (f"echo {java}", f"rak_data {raknet}", f"ice_dtls {ice}"):
                lost += player.ask(command) != "ok"
            time.sleep(0.2)
        check(f"{label}: established player lost nothing", lost == 0, f"({lost} exchanges failed)")
        # ... and can open new connections, challenge and budgets or not
        player.expect("java_login Steve mc.e2e.test", "ok")
        player.expect("java_status mc.e2e.test", "ok")
        player.expect("rak_connect", "ok")
        player.expect("rak_ping", "ok")

        # somebody new: in through the retransmit
        started = time.monotonic()
        if kind == "replay":
            # this flood passes the challenge and eats the budget for
            # unproven ips, which is exactly what the budget is for
            newcomer_result = "-"
        elif not pps:
            # at many times the rate of the port the challenge table turns
            # over faster than a client retransmits
            newcomer_result = "-"
        else:
            newcomer.expect("java_login Alex mc.e2e.test 0 5", "ok")
            newcomer.expect("rak_connect 6", "ok")
            newcomer.expect("ice_open 6", "ok")
            newcomer_result = f"in after {time.monotonic() - started:.1f}s"

        sent, rate = flood.communicate()[0].split()
        time.sleep(1.5)  # one metrics poll
        after = snapshot()
        delta = {name: after[name] - before[name] for name in COUNTERS}
        dropped = delta["minecraft_dropped_packets"] / max(1, int(sent))
        print(f"{label:<12} {int(sent):>10} {int(float(rate)):>9} {dropped:>8.1%} {delta['minecraft_new_ips']:>8}  "
              f"{newcomer_result}", flush=True)

        check(f"{label}: the filter saw the flood", delta["minecraft_incoming_packets"] >= 0.95 * int(sent), str(delta))
        if kind == "replay":
            # every SYN comes twice: the first is dropped by the challenge,
            # the second passes it and then runs into the SYN budget
            check("replay: retransmits pass the challenge", delta["minecraft_challenge_passed"] >= 0.3 * int(sent),
                  str(delta))
            check("replay: the budget drops what the challenge let through",
                  delta["minecraft_tcp_budget_dropped"] >= 0.3 * int(sent), str(delta))
            check("replay: new ips are bounded by the budget", delta["minecraft_new_ips"] <= 600 * (SECONDS + 2),
                  str(delta))
        else:
            check(f"{label}: the flood is dropped", dropped >= 0.99, f"({dropped:.2%})")
            check(f"{label}: the flood leaves no state behind", delta["minecraft_new_ips"] <= 1500, str(delta))
        newcomer.close()

    # nothing of the floods reached the servers
    seen = sorted(set(events()))
    check("only real clients reached the servers",
          seen == ["java login mc.e2e.test Alex", "java login mc.e2e.test Steve", "java status mc.e2e.test",
                   "raknet ping 10.99.0.2"], str(seen))
    # and the first connections are still alive
    player.expect(f"echo {java}", "ok")
    player.expect(f"rak_data {raknet}", "ok")
    player.expect(f"ice_dtls {ice}", "ok")
    check("the loader reported the flood", "Flood started" in loader.output())

    loader.stop()
    player.close()
    server.kill()
    return summary()


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        teardown()
