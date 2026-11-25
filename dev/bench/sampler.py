#!/usr/bin/env python3
"""Runs inside the server namespace of dev/bench/attack.py and prints one
JSON line per interval: what reached the server's network stack (the kernel
counters of this namespace, which never see what XDP dropped), the cpu time
of the machine and, if the loader runs, the filter's own counters.

    sampler.py <interval seconds> <with metrics: 0|1>
"""
import json
import sys
import time
import urllib.request

INTERVAL = float(sys.argv[1])
METRICS = sys.argv[2] == "1"
FILTER_COUNTERS = ("minecraft_incoming_packets", "minecraft_dropped_packets")


def snmp():
    """IpInReceives, TcpPassiveOpens, UdpInDatagrams of this namespace."""
    values = {}
    with open("/proc/net/snmp") as f:
        lines = f.read().splitlines()
    for header, row in zip(lines[::2], lines[1::2]):
        names, numbers = header.split()[1:], row.split()[1:]
        proto = header.split(":")[0]
        for name, number in zip(names, numbers):
            values[f"{proto}.{name}"] = int(number)
    return {
        "ip_in": values["Ip.InReceives"],
        "tcp_opens": values["Tcp.PassiveOpens"],
        "udp_in": values["Udp.InDatagrams"],
    }


def cpu():
    """Cpu time of the whole machine in clock ticks: busy (everything but
    idle and iowait) and the softirq part of it, where packets are received
    and where XDP in generic mode runs."""
    fields = [int(x) for x in open("/proc/stat").readline().split()[1:]]
    user, nice, system, idle, iowait, irq, softirq, steal = fields[:8]
    return {"cpu_busy": user + nice + system + irq + softirq + steal, "cpu_softirq": softirq}


def filter_counters():
    try:
        text = urllib.request.urlopen("http://127.0.0.1:1999/metrics", timeout=0.3).read().decode()
    except OSError:
        return {}
    found = {}
    for line in text.splitlines():
        name, _, value = line.partition(" ")
        if name in FILTER_COUNTERS:
            found[name.removeprefix("minecraft_")] = int(float(value))
    return found


while True:
    sample = {"t": time.time(), **snmp(), **cpu()}
    if METRICS:
        sample.update(filter_counters())
    print(json.dumps(sample), flush=True)
    time.sleep(INTERVAL - time.time() % INTERVAL)
