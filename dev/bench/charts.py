#!/usr/bin/env python3
"""Draws the charts in docs/charts/ from the measurements of
dev/bench/attack.sh (dev/bench/out/). Plain SVG, no dependencies; every chart
comes in a light and a dark variant for GitHub's two themes.

    python3 dev/bench/charts.py [dev/bench/out] [docs/charts]
"""
import json
import math
import os
import re
import statistics
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "dev/bench/out"
DST = sys.argv[2] if len(sys.argv) > 2 else "docs/charts"

THEMES = {
    "light": {
        "surface": "#ffffff", "ink": "#191919", "ink2": "#666666", "grid": "#e7e7e7", "axis": "#c2c2c2",
        "band": "#f3f4f6", "border": "rgba(11,11,11,0.10)", "s1": "#257de0", "s2": "#f47230",
    },
    "dark": {
        "surface": "#0d1117", "ink": "#efefef", "ink2": "#9c9c9c", "grid": "#262c36", "axis": "#474747",
        "band": "#161b22", "border": "rgba(255,255,255,0.10)", "s1": "#338ced", "s2": "#e76624",
    },
}
FONT = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
W = 880
LEFT, RIGHT = 64, 28
WITH, WITHOUT = ("with the filter", "s1"), ("without the filter", "s2")
BAND = {"SYN + retransmit": "SYN+retry", "Java handshake": "Handshake", "Bedrock ping": "Ping",
        "Bedrock connect": "Connect", "NetherNet STUN": "STUN", "UDP junk": "Junk"}


def esc(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Svg:
    def __init__(self, theme, height, title, subtitle):
        self.c = THEMES[theme]
        self.h = height
        self.parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{height}" viewBox="0 0 {W} {height}" '
            f'font-family="{FONT}" role="img" aria-label="{esc(title)}">',
            f"<title>{esc(title)}</title>",
            f'<rect x="0.5" y="0.5" width="{W - 1}" height="{height - 1}" rx="8" fill="{self.c["surface"]}" '
            f'stroke="{self.c["border"]}"/>',
        ]
        self.grid_at = len(self.parts)  # gridlines go here, under everything else
        self.text(24, 34, title, size=17, weight=600)
        y = 56
        for line in subtitle:
            self.text(24, y, line, size=12.5, color="ink2")
            y += 18
        self.top = y + 6

    def text(self, x, y, s, size=12, color="ink", weight=400, anchor="start", tabular=False):
        extra = ' style="font-variant-numeric:tabular-nums"' if tabular else ""
        self.parts.append(f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" '
                          f'fill="{self.c[color]}" text-anchor="{anchor}"{extra}>{esc(s)}</text>')

    def line(self, x1, y1, x2, y2, color="grid", width=1, under=False):
        element = (f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                   f'stroke="{self.c[color]}" stroke-width="{width}"/>')
        if under:
            self.parts.insert(self.grid_at, element)
            self.grid_at += 1
        else:
            self.parts.append(element)

    def rect(self, x, y, w, h, color, rx=0):
        self.parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" '
                          f'fill="{self.c[color]}"/>')

    def path(self, d, color, width=2):
        self.parts.append(f'<path d="{d}" fill="none" stroke="{self.c[color]}" stroke-width="{width}" '
                          f'stroke-linejoin="round" stroke-linecap="round"/>')

    def hbar(self, x0, y, w, h, color):
        """A bar growing right from x0: square at the baseline, 4px rounded at the data end."""
        r = min(4, w / 2, h / 2)
        if w <= 0:
            return
        self.parts.append(
            f'<path d="M{x0:.1f},{y:.1f} H{x0 + w - r:.1f} Q{x0 + w:.1f},{y:.1f} {x0 + w:.1f},{y + r:.1f} '
            f'V{y + h - r:.1f} Q{x0 + w:.1f},{y + h:.1f} {x0 + w - r:.1f},{y + h:.1f} H{x0:.1f} Z" '
            f'fill="{self.c[color]}"/>')

    def dot(self, x, y, color):
        # 2px ring in the surface color keeps overlapping dots apart
        self.parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{self.c[color]}" '
                          f'stroke="{self.c["surface"]}" stroke-width="2"/>')

    def legend(self, items, y, key="line"):
        x = 24
        for label, color in items:
            if key == "line":
                self.line(x, y - 4, x + 16, y - 4, color, 2.5)
            else:
                self.rect(x, y - 10, 12, 12, color, rx=3)
            self.text(x + 22, y, label, size=12.5, color="ink2")
            x += 44 + 6.6 * len(label)

    def save(self, path):
        with open(path, "w") as f:
            f.write("\n".join(self.parts + ["</svg>"]) + "\n")


def load(scenario, with_filter):
    with open(os.path.join(SRC, f"{scenario}-{'with' if with_filter else 'without'}-filter.json")) as f:
        return json.load(f)


def rates(samples, key):
    """Per-second rate between consecutive samples, at the midpoint."""
    out = []
    for a, b in zip(samples, samples[1:]):
        if key in a and key in b and b["t"] > a["t"]:
            out.append(((a["t"] + b["t"]) / 2, (b[key] - a[key]) / (b["t"] - a["t"])))
    return out


def phase_rate(run, key, phase, divide=1.0):
    """Mean rate of a counter while a flood runs, without its ramp up and down."""
    xs = [s for s in run["samples"] if phase["start"] + 1 <= s["t"] <= phase["end"] - 0.3 and key in s]
    return (xs[-1][key] - xs[0][key]) / (xs[-1]["t"] - xs[0]["t"]) / divide


def cores(run, phase):
    return phase_rate(run, "cpu_busy", phase, run["hz"])


def answered(run, phase, kind):
    trips = [r for r in run["rtt"] if r["kind"] == kind and phase["start"] <= r["t"] < phase["end"]]
    return sum(1 for r in trips if r["ms"] is not None) / len(trips)


def compact(v):
    if v >= 1e6:
        return f"{v / 1e6:g}M"
    if v >= 1e3:
        return f"{v / 1e3:g}K"
    return f"{v:g}"


def time_axis(svg, x_of, y0, y1, duration, phases):
    """Phase bands with their names, the time ticks and the baseline."""
    for p in phases:
        svg.rect(x_of(p["start"]), y0, x_of(p["end"]) - x_of(p["start"]), y1 - y0, "band", rx=3)
        svg.text((x_of(p["start"]) + x_of(p["end"])) / 2, y0 + 15, BAND.get(p["label"], p["label"]), size=11,
                 color="ink2", anchor="middle")
    for s in range(0, int(duration) + 1, 10):
        svg.text(x_of(s), y1 + 18, f"{s} s", size=11, color="ink2", anchor="middle", tabular=True)
    svg.line(LEFT, y1, W - RIGHT, y1, "axis")


def grouped_bars(svg, rows, vmax, ticks, fmt, label_w=190, bar_h=10, unit=""):
    """Horizontal bars, one group per row: rows = [(label, [(value, color), ...])]."""
    x0, x1 = 24 + label_w, W - RIGHT - 56
    x_of = lambda v: x0 + (x1 - x0) * min(v, vmax) / vmax  # noqa: E731
    group_h = len(rows[0][1]) * (bar_h + 2) - 2
    row_h = group_h + 16
    y = svg.top + 22
    first = y
    for label, bars in rows:
        svg.text(24, y + group_h / 2 + 4, label, size=12.5)
        for i, (value, color) in enumerate(bars):
            by = y + i * (bar_h + 2)  # 2px surface gap between the bars of a group
            svg.hbar(x0, by, x_of(value) - x0, bar_h, color)
            svg.text(x_of(value) + 6, by + bar_h - 1, fmt(value), size=11, color="ink2", tabular=True)
        y += row_h
    for t in ticks:
        if t:
            svg.line(x_of(t), first - 6, x_of(t), y - 10, under=True)
        svg.text(x_of(t), y + 8, f"{fmt(t)}{unit}", size=11, color="ink2", anchor="middle", tabular=True)
    svg.line(x0, first - 6, x0, y - 10, "axis")
    return y


def chart_reach(theme, w, wo):
    floods = [p for p in w["phases"] if p["target_pps"] == max(q["target_pps"] for q in w["phases"])]
    reached_wo = statistics.median(phase_rate(wo, "ip_in", p) for p in wo["phases"] if p["kind"] != "replay")
    reached_w = statistics.median(phase_rate(w, "ip_in", p) for p in w["phases"])
    svg = Svg(theme, 400, "What reaches the server during a flood", [
        f"Packets per second arriving at the server's network stack during eight spoofed floods at "
        f"{floods[0]['target_pps'] / 1e6:.2f} Mpps, the rate of",
        "a saturated 1 Gbit/s port (the retransmitting SYN flood runs at 50K pps). Log scale.",
    ])
    svg.legend([(f"without the filter: {compact(round(reached_wo, -4))} pps reach the server", "s2"),
                (f"with the filter: ~{round(reached_w, -1):.0f} pps, only the players", "s1")], svg.top + 8)
    y0, y1 = svg.top + 26, svg.h - 40
    duration = w["duration"]
    x_of = lambda t: LEFT + (W - LEFT - RIGHT) * t / duration  # noqa: E731
    lo, hi = 1, 7  # 10 .. 10M
    y_of = lambda v: y1 - (y1 - y0) * (math.log10(max(v, 10)) - lo) / (hi - lo)  # noqa: E731
    time_axis(svg, x_of, y0, y1, duration, w["phases"])
    for e in range(lo, hi):
        if e > lo:
            svg.line(LEFT, y_of(10 ** e), W - RIGHT, y_of(10 ** e), under=True)
        svg.text(LEFT - 10, y_of(10 ** e) + 4, compact(10 ** e), size=11, color="ink2", anchor="end", tabular=True)
    for run, color in ((wo, "s2"), (w, "s1")):
        pts = [(t, v) for t, v in rates(run["samples"], "ip_in") if 0 <= t <= duration]
        svg.path(" ".join(f"{'M' if i == 0 else 'L'}{x_of(t):.1f},{y_of(v):.1f}" for i, (t, v) in enumerate(pts)),
                 color)
    return svg


def chart_cpu(theme, w, wo):
    rows = [(p["label"], [(cores(w, p), "s1"), (cores(wo, q), "s2")]) for p, q in zip(w["phases"], wo["phases"])]
    svg = Svg(theme, 112 + len(rows) * 40 + 30, "CPU the flood costs", [
        "Busy cores of the 6-core machine while each flood runs at 1.49 Mpps (the retransmitting SYN flood at",
        "50K pps), including the flood generator itself. Same rate, same machine: the gap is the network stack.",
    ])
    svg.legend([WITH, WITHOUT], svg.top + 8, key="box")
    svg.top += 16
    grouped_bars(svg, rows, 4, [0, 1, 2, 3, 4], lambda v: f"{v:.1f}" if v % 1 else f"{v:.0f}")
    svg.text(W - RIGHT, svg.h - 14, "cores", size=11, color="ink2", anchor="end")
    return svg


def chart_capacity(theme, w, wo):
    best_w = max(p["pps"] for p in w["phases"])
    best_wo = max(p["pps"] for p in wo["phases"])
    busy_w = max(cores(w, p) for p in w["phases"])
    busy_wo = max(cores(wo, p) for p in wo["phases"])
    svg = Svg(theme, 214, "The biggest SYN flood the machine takes in", [
        "A SYN flood stepping up from 0.5 Mpps to as fast as the generator can send. Without the filter the",
        f"kernel's TCP stack saturates the machine at {best_wo / 1e6:.1f} Mpps ({busy_wo:.0f} cores busy); "
        f"with it, {best_w / 1e6:.1f} Mpps take {busy_w:.0f} cores.",
    ])
    grouped_bars(svg, [("with the filter", [(best_w / 1e6, "s1")]), ("without the filter", [(best_wo / 1e6, "s2")])],
                 10, [0, 2, 4, 6, 8, 10], lambda v: f"{v:.1f}" if v % 1 else f"{v:.0f}", bar_h=14)
    svg.text(W - RIGHT, svg.h - 14, "million packets per second", size=11, color="ink2", anchor="end")
    return svg


def chart_bedrock(theme, w, wo):
    udp = [i for i, p in enumerate(w["phases"]) if p["kind"] in ("ping", "ocr1", "stun", "junk")]
    rows = [(w["phases"][i]["label"], [(100 * answered(w, w["phases"][i], "bedrock"), "s1"),
                                       (100 * answered(wo, wo["phases"][i], "bedrock"), "s2")]) for i in udp]
    svg = Svg(theme, 112 + len(rows) * 40 + 30, "A Bedrock player during UDP floods", [
        "Share of the player's round trips answered while each flood runs at 1.49 Mpps. Every lost one stalls the",
        "player for a 1 s timeout. The STUN flood aims at the NetherNet port, not at the game socket.",
    ])
    svg.legend([WITH, WITHOUT], svg.top + 8, key="box")
    svg.top += 16
    grouped_bars(svg, rows, 100, [0, 25, 50, 75, 100], lambda v: f"{v:.0f}%")
    return svg


def chart_newcomers(theme, w, wo):
    svg = Svg(theme, 372, "The price: newcomers wait for one retransmit", [
        "Login time of a player from an address the filter has never seen. While a flood of unknown addresses is",
        "on, and 30 s after it, the first SYN is dropped and the retransmit gets in. Returning players: 0-5 ms.",
    ])
    svg.legend([WITHOUT, WITH], svg.top + 8)
    y0, y1 = svg.top + 26, svg.h - 40
    duration = w["duration"]
    x_of = lambda t: LEFT + (W - LEFT - RIGHT) * t / duration  # noqa: E731
    top = 3500
    y_of = lambda ms: y1 - (y1 - y0) * min(ms, top) / top  # noqa: E731
    time_axis(svg, x_of, y0, y1, duration, w["phases"])
    for ms in (1000, 2000, 3000):
        svg.line(LEFT, y_of(ms), W - RIGHT, y_of(ms), under=True)
    for ms in (0, 1000, 2000, 3000):
        svg.text(LEFT - 10, y_of(ms) + 4, f"{ms // 1000} s" if ms else "0", size=11, color="ink2", anchor="end",
                 tabular=True)
    for run, color in ((wo, "s2"), (w, "s1")):
        pts = [(l["t"], l["ms"]) for l in run["logins"] if l["who"] == "newcomer" and l["ms"] is not None]
        svg.path(" ".join(f"{'M' if i == 0 else 'L'}{x_of(t):.1f},{y_of(v):.1f}" for i, (t, v) in enumerate(pts)),
                 color)
        for t, v in pts:
            svg.dot(x_of(t), y_of(v), color)
    return svg


def pretty(name):
    name = name.replace("tcp", "TCP").replace(" ip", " IP")
    return name[0].upper() + name[1:]


def bench_rows():
    rows = []
    with open(os.path.join(SRC, "bench.txt")) as f:
        for line in f:
            m = re.match(r"(.+?)\s+(\d+) ns\s+(pass|drop)", line)
            if m:
                rows.append((pretty(m.group(1).strip()), int(m.group(2)), m.group(3)))
    return rows


def chart_cost(theme, rows):
    groups = [("Legitimate traffic, passed", [r for r in rows if r[2] == "pass"]),
              ("Attack traffic, dropped", [r for r in rows if r[2] == "drop"])]
    row_h, bar_h = 24, 12
    height = 104 + sum(22 + len(g) * row_h for _, g in groups) + 34
    svg = Svg(theme, height, "Cost per packet", [
        "Time the filter spends on one packet, measured with BPF_PROG_TEST_RUN in the kernel (warm cache, one",
        "core of an Apple Silicon VM). At 1 Gbit/s line rate a packet arrives every 670 ns.",
    ])
    x0, x1 = LEFT + 320, W - RIGHT - 40
    vmax = 40
    x_of = lambda ns: x0 + (x1 - x0) * ns / vmax  # noqa: E731
    y = svg.top + 14
    first = y
    for heading, items in groups:
        svg.text(24, y + 12, heading, size=12, color="ink2", weight=600)
        y += 22
        for name, ns, _ in items:
            svg.text(24, y + bar_h / 2 + 4, name, size=12.5)
            svg.hbar(x0, y, x_of(ns) - x0, bar_h, "s1")
            svg.text(x_of(ns) + 8, y + bar_h / 2 + 4, f"{ns} ns", size=12, color="ink2", tabular=True)
            y += row_h
    for ns in range(0, vmax + 1, 10):
        if ns:
            svg.line(x_of(ns), first, x_of(ns), y, under=True)
        svg.text(x_of(ns), y + 18, f"{ns} ns", size=11, color="ink2", anchor="middle", tabular=True)
    svg.line(x0, first, x0, y, "axis")
    return svg


def main():
    os.makedirs(DST, exist_ok=True)
    mix_w, mix_wo = load("mix", True), load("mix", False)
    esc_w, esc_wo = load("escalate", True), load("escalate", False)
    rows = bench_rows()
    charts = {
        "flood-reach": lambda t: chart_reach(t, mix_w, mix_wo),
        "flood-cpu": lambda t: chart_cpu(t, mix_w, mix_wo),
        "flood-capacity": lambda t: chart_capacity(t, esc_w, esc_wo),
        "bedrock-player": lambda t: chart_bedrock(t, mix_w, mix_wo),
        "newcomer-login": lambda t: chart_newcomers(t, mix_w, mix_wo),
        "cost-per-packet": lambda t: chart_cost(t, rows),
    }
    for old in os.listdir(DST):
        if old.endswith(".svg"):
            os.remove(os.path.join(DST, old))
    for name, draw in charts.items():
        for theme in THEMES:
            draw(theme).save(os.path.join(DST, f"{name}-{theme}.svg"))
    print("written:", ", ".join(charts))


if __name__ == "__main__":
    main()
