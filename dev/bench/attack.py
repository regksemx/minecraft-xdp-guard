#!/usr/bin/env python3
"""Attack scenarios for the charts in docs/charts: spoofed floods against the
test setup of dev/e2e, each scenario once with the filter and once without,
while a player keeps playing and logging in and newcomers join from addresses
never seen before.

Scenarios
  escalate  a SYN flood that steps up from 0.5 Mpps to as fast as this
            machine can send
  mix       every kind of flood the generator knows, one after another, at
            the rate of a saturated 1 Gbit/s port

Writes dev/bench/out/<scenario>-<with|without>-filter.json with
  - samples: what reached the server's network stack per interval, the
    filter's own counters and the cpu time of the machine,
  - rtt: round trips of the established player (Java and Bedrock),
  - logins: how long a login of the returning player and of a newcomer took,
  - phases: when each flood ran and how much it actually sent, and how much
    cpu the flood generator itself used.

Run as root on Linux: dev/run.sh dev/bench/attack.sh
"""
import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e"))
from harness import CLI, SERVER_IP, SRV, Client, Loader, in_ns, setup, sh, teardown  # noqa: E402

LOADER = os.path.abspath(sys.argv[1])
FLOOD = os.path.abspath(sys.argv[2])
OUT = os.path.abspath(sys.argv[3])
ONLY = sys.argv[4:]  # optional scenario names
HERE = os.path.dirname(os.path.abspath(__file__))

# a 1 Gbit/s port carries at most 1.49 million minimum-size packets per second
GIGABIT_PPS = 1_490_000
# leave cpus for the player and the measurement; on a veth pair the
# receiving side runs on the cpu of the sender
THREADS = max(1, (os.cpu_count() or 4) - 2)
SAMPLE_SECS = 0.5
HZ = os.sysconf("SC_CLK_TCK")

# name: (seconds per flood, gap, [(kind, pps or 0 for as fast as possible, label)])
SCENARIOS = {
    "escalate": (8, 4, [
        ("syn", 500_000, "0.5 Mpps"),
        ("syn", 1_500_000, "1.5 Mpps"),
        ("syn", 3_000_000, "3 Mpps"),
        ("syn", 0, "max"),
    ]),
    "mix": (6, 3, [
        ("syn", GIGABIT_PPS, "SYN"),
        ("ack", GIGABIT_PPS, "ACK"),
        ("handshake", GIGABIT_PPS, "Java handshake"),
        ("replay", GIGABIT_PPS, "SYN + retransmit"),
        ("ping", GIGABIT_PPS, "Bedrock ping"),
        ("ocr1", GIGABIT_PPS, "Bedrock connect"),
        ("stun", GIGABIT_PPS, "NetherNet STUN"),
        ("junk", GIGABIT_PPS, "UDP junk"),
    ]),
}
LEAD = 5  # seconds before the first and after the last flood

CONFIG = """
[java]
start_port = 25565
end_port = 25565
hosts = ["mc.e2e.test"]

[bedrock]
start_port = 19132
end_port = 19132

[nethernet]
ice_start_port = 27020
ice_end_port = 27020

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

[metrics]
enabled = true
addr = "127.0.0.1:1999"
poll_secs = 1
"""


def like_a_real_server():
    """In the bare test setup the server has no route back to the spoofed
    sources, so its kernel throws the flood away early and cheaply (reverse
    path filter, no route for the replies). A real server has a default
    route: it answers every spoofed SYN, ping and request. Give the server
    namespace one, into a dummy device standing in for the internet."""
    sh(f"ip -n {SRV} link add inet0 type dummy")
    sh(f"ip -n {SRV} link set inet0 up")
    sh(f"ip -n {SRV} route add default dev inet0")
    for conf in ("all", "default", "veth-srv"):
        sh(f"ip netns exec {SRV} sysctl -qw net.ipv4.conf.{conf}.rp_filter=0")


def process_cpu(pid):
    """utime + stime of a process and all its threads, in seconds."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / HZ
    except (OSError, IndexError, ValueError):
        return 0.0


def run(scenario, with_filter):
    flood_secs, gap, floods_plan = SCENARIOS[scenario]
    phases_plan, start = [], LEAD
    for kind, pps, label in floods_plan:
        phases_plan.append((start, kind, pps, label))
        start += flood_secs + gap
    duration = start - gap + LEAD

    workdir, _events, server = setup()
    like_a_real_server()
    loader = None
    if with_filter:
        loader = Loader(LOADER, workdir, CONFIG)
        loader.start()
    server_mac = sh(f"ip -n {SRV} -br link show veth-srv").stdout.split()[2]

    # the player: online before the attack, long enough to count as proven
    player = Client()
    java = player.ask("java_login Steve mc.e2e.test").split()[1]
    raknet = player.ask("rak_connect").split()[1]
    for _ in range(3):
        time.sleep(1.1)
        player.ask(f"echo {java}")
        player.ask(f"rak_data {raknet}")
    time.sleep(1.2)

    sampler = in_ns(SRV, [sys.executable, os.path.join(HERE, "sampler.py"), str(SAMPLE_SECS),
                          "1" if with_filter else "0"], stdout=subprocess.PIPE)
    t0 = time.time()
    stop = threading.Event()
    rtt, logins, phases = [], [], []

    def timed(client, command):
        started = time.time()
        answer = client.ask(command)
        return started - t0, (time.time() - started) * 1000 if answer.startswith("ok") else None

    def play():
        while not stop.is_set():
            t, ms = timed(player, f"echo {java}")
            rtt.append({"t": t, "kind": "java", "ms": ms})
            t, ms = timed(player, f"rak_data {raknet}")
            rtt.append({"t": t, "kind": "bedrock", "ms": ms})
            time.sleep(0.1)

    def returning():
        client = Client()
        while not stop.is_set():
            t, ms = timed(client, "java_login Steve mc.e2e.test 0 5")
            logins.append({"t": t, "who": "returning", "ms": ms})
            time.sleep(2)
        client.close()

    def newcomers():
        index = 0
        while not stop.is_set() and index < 140:
            address = f"10.99.0.{100 + index}"
            index += 1
            sh(f"ip -n {CLI} addr add {address}/24 dev veth-cli")
            client = Client(address)
            t, ms = timed(client, "java_login Alex mc.e2e.test 0 5")
            logins.append({"t": t, "who": "newcomer", "ms": ms})
            client.close()
            time.sleep(2)

    def floods():
        for begin, kind, pps, label in phases_plan:
            time.sleep(max(0.0, t0 + begin - time.time()))
            argv = [FLOOD, "veth-cli", server_mac, SERVER_IP, kind, str(flood_secs), str(THREADS)]
            begun = time.time() - t0
            # nsenter execs the generator, so this is its pid
            process = in_ns(CLI, argv + ([str(pps)] if pps else []), stdout=subprocess.PIPE)
            cpu = 0.0
            while process.poll() is None:
                cpu = max(cpu, process_cpu(process.pid))
                time.sleep(0.05)
            sent, rate = process.communicate()[0].split()
            ended = time.time() - t0
            phases.append({"start": begun, "end": ended, "kind": kind, "label": label, "target_pps": pps,
                           "sent": int(sent), "pps": int(float(rate)), "generator_cores": cpu / (ended - begun)})

    threads = [threading.Thread(target=f, daemon=True) for f in (play, returning, newcomers, floods)]
    for thread in threads:
        thread.start()
    time.sleep(max(0.0, t0 + duration - time.time()))
    stop.set()
    threads[3].join()
    sampler.terminate()
    samples = []
    for line in sampler.communicate()[0].splitlines():
        sample = json.loads(line)
        sample["t"] -= t0
        samples.append(sample)

    if loader:
        loader.stop()
    player.close()
    server.kill()
    teardown()
    return {"scenario": scenario, "filter": with_filter, "threads": THREADS, "cpus": os.cpu_count(),
            "kernel": os.uname().release, "duration": duration, "hz": HZ, "phases": phases,
            "samples": samples, "rtt": rtt, "logins": logins}


def main():
    os.makedirs(OUT, exist_ok=True)
    for scenario in SCENARIOS:
        if ONLY and scenario not in ONLY:
            continue
        for with_filter in (True, False):
            name = f"{scenario}-{'with' if with_filter else 'without'}-filter"
            print(f"== {name}", flush=True)
            result = run(scenario, with_filter)
            with open(os.path.join(OUT, f"{name}.json"), "w") as f:
                json.dump(result, f)
            for p in result["phases"]:
                print(f"   {p['label']:<18} sent {p['pps']:>9} pps, generator {p['generator_cores']:.2f} cores",
                      flush=True)
            answered = sum(1 for r in result["rtt"] if r["ms"] is not None)
            print(f"   player round trips answered: {answered}/{len(result['rtt'])}", flush=True)


if __name__ == "__main__":
    try:
        main()
    finally:
        teardown()
