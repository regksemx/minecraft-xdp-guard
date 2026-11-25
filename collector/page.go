package main

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
)

// The public statistics page, GET /: stat tiles, players and servers over
// time, and how the running installations are set up. Server-rendered HTML
// with inline SVG, no scripts; colors are CSS variables so that light and
// dark follow the viewer's system.

const pageCSS = `
:root{color-scheme:light;--surface:#ffffff;--page:#f6f8fa;--ink:#191919;--ink2:#666666;--grid:#e7e7e7;--axis:#c2c2c2;
--border:rgba(11,11,11,.10);--s1:#257de0;--s2:#f47230;--s3:#00b894;--wash:rgba(37,125,224,.10)}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--surface:#0d1117;--page:#010409;--ink:#efefef;--ink2:#9c9c9c;
--grid:#262c36;--axis:#474747;--border:rgba(255,255,255,.10);--s1:#338ced;--s2:#e76624;--s3:#00a888;--wash:rgba(51,140,237,.12)}}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 48px}
header{display:flex;justify-content:space-between;align-items:baseline;gap:16px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:22px;margin:0;font-weight:600}h2{font-size:15px;margin:0 0 2px;font-weight:600}
a{color:var(--s1);text-decoration:none}a:hover{text-decoration:underline}
.sub{color:var(--ink2);font-size:13px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px 20px 12px;margin-bottom:16px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.tile .label{color:var(--ink2);font-size:13px}.tile .value{font-size:32px;font-weight:600;line-height:1.2}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.legend{display:flex;gap:18px;flex-wrap:wrap;color:var(--ink2);font-size:13px;margin:6px 0 4px}
.legend i{display:inline-block;width:16px;height:3px;border-radius:2px;vertical-align:middle;margin-right:6px}
.range a{margin-left:10px;font-size:13px}.range b{margin-left:10px;font-size:13px}
svg{display:block;width:100%;height:auto}svg text{font-family:inherit}
footer{color:var(--ink2);font-size:13px;margin-top:24px}
.empty{color:var(--ink2);padding:24px 0;text-align:center}
`

type pageSeries struct {
	name, color string
	value       func(snapshot) uint64
}

// renderPage draws the statistics page for the last `days` days.
func renderPage(sum Summary, hist []snapshot, now time.Time, days int) []byte {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>minecraft-xdp-guard statistics</title>` +
		`<meta name="description" content="Live usage of minecraft-xdp-guard: servers protected, players connected, packets dropped.">` +
		`<style>` + pageCSS + `</style></head><body><main>`)

	b.WriteString(`<header><div><h1>minecraft-xdp-guard</h1><div class="sub">Live statistics of the ` +
		`<a href="https://github.com/regksemx/minecraft-xdp-guard">XDP DDoS filter for Minecraft</a>, ` +
		`from the anonymous reports of the running installations. Updated every hour.</div></div>`)
	b.WriteString(`<div class="range">`)
	for _, d := range []int{7, 30, 90} {
		if d == days {
			fmt.Fprintf(&b, `<b>%d days</b>`, d)
		} else {
			fmt.Fprintf(&b, `<a href="/?days=%d">%d days</a>`, d, d)
		}
	}
	b.WriteString(`</div></header>`)

	b.WriteString(`<section class="card tiles">`)
	for _, t := range []struct{ label, value string }{
		{"Servers protected", compactFull(uint64(sum.Servers))},
		{"Players connected", compactFull(sum.PlayersTotal)},
		{"Packets dropped today", compactFull(sum.DroppedToday)},
		{"Packets dropped in total", compactFull(sum.DroppedTotal)},
	} {
		fmt.Fprintf(&b, `<div class="tile"><div class="label">%s</div><div class="value">%s</div></div>`, t.label, t.value)
	}
	b.WriteString(`</section>`)

	editions := []pageSeries{
		{"Java", "var(--s1)", func(s snapshot) uint64 { return uint64(s.Java) }},
		{"Bedrock", "var(--s2)", func(s snapshot) uint64 { return uint64(s.Bedrock) }},
		{"NetherNet", "var(--s3)", func(s snapshot) uint64 { return uint64(s.NetherNet) }},
	}
	b.WriteString(`<section class="card"><h2>Players</h2><div class="sub">Verified game connections, by edition</div>`)
	b.WriteString(`<div class="legend">`)
	for _, s := range editions {
		fmt.Fprintf(&b, `<span><i style="background:%s"></i>%s</span>`, s.color, s.name)
	}
	b.WriteString(`</div>`)
	b.WriteString(lineChart(hist, editions, now, days, 260))
	b.WriteString(`</section>`)

	b.WriteString(`<section class="card"><h2>Servers</h2><div class="sub">Installations that reported within the hour</div>`)
	b.WriteString(lineChart(hist, []pageSeries{{"Servers", "var(--s1)", func(s snapshot) uint64 { return uint64(s.Servers) }}},
		now, days, 200))
	b.WriteString(`</section>`)

	b.WriteString(`<div class="grid2">`)
	for _, d := range []struct {
		title, sub string
		counts     map[string]int
		// a server has one version but many protections: those are not
		// parts of a whole and must not be summed into "other"
		fold bool
	}{
		{"Versions", "of the running installations", sum.Versions, true},
		{"Protections", "switched on, share of servers", sum.Features, false},
		{"XDP mode", "native driver or generic", sum.Modes, true},
		{"Kernels", "major.minor", sum.Kernels, true},
		{"Architectures", "", sum.Arches, true},
	} {
		fmt.Fprintf(&b, `<section class="card"><h2>%s</h2><div class="sub">%s</div>`, d.title, d.sub)
		b.WriteString(barChart(d.counts, sum.Servers, d.fold))
		b.WriteString(`</section>`)
	}
	b.WriteString(`</div>`)

	b.WriteString(`<footer>What a report holds, and how to turn it off: ` +
		`<a href="https://github.com/regksemx/minecraft-xdp-guard#telemetry">Telemetry</a>. ` +
		`No addresses are stored. Data: <a href="/v1/summary">/v1/summary</a> · ` +
		`chart for READMEs: <a href="/v1/chart.svg">/v1/chart.svg</a></footer>`)
	b.WriteString(`</main></body></html>`)
	return []byte(b.String())
}

// lineChart draws one line per series over the last `days` days.
func lineChart(hist []snapshot, series []pageSeries, now time.Time, days int, height float64) string {
	const w, left, right, top = 920.0, 56.0, 12.0, 12.0
	bottom := height - 28
	if len(hist) < 2 {
		return `<div class="empty">Collecting data: the chart fills in over the next hours.</div>`
	}
	var peak uint64
	for _, h := range hist {
		for _, s := range series {
			peak = max(peak, s.value(h))
		}
	}
	ceiling := niceCeiling(peak)
	step := tickStep(ceiling)
	from := now.Add(-time.Duration(days) * 24 * time.Hour)
	span := now.Sub(from).Seconds()
	xOf := func(t time.Time) float64 { return left + (w-left-right)*t.Sub(from).Seconds()/span }
	yOf := func(v uint64) float64 { return bottom - (bottom-top)*float64(v)/float64(ceiling) }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" role="img" aria-label="%s over the last %d days">`, w, height,
		html.EscapeString(series[0].name), days)
	for v := step; v <= ceiling; v += step {
		fmt.Fprintf(&b, `<line x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f" stroke="var(--grid)"/>`, left, w-right, yOf(v), yOf(v))
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" font-size="11" fill="var(--ink2)" text-anchor="end">%s</text>`,
			left-8, yOf(v)+4, compactFull(v))
	}
	fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" font-size="11" fill="var(--ink2)" text-anchor="end">0</text>`, left-8, bottom+4)
	fmt.Fprintf(&b, `<line x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f" stroke="var(--axis)"/>`, left, w-right, bottom, bottom)
	ticks := 4
	for i := 0; i <= ticks; i++ {
		t := from.Add(time.Duration(float64(i) / float64(ticks) * span * float64(time.Second)))
		anchor := "middle"
		if i == 0 {
			anchor = "start"
		} else if i == ticks {
			anchor = "end"
		}
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" font-size="11" fill="var(--ink2)" text-anchor="%s">%s</text>`,
			xOf(t), bottom+20, anchor, t.UTC().Format("Jan 2"))
	}
	for _, s := range series {
		var path strings.Builder
		for i, h := range hist {
			cmd := "L"
			if i == 0 {
				cmd = "M"
			}
			fmt.Fprintf(&path, "%s%.1f,%.1f", cmd, xOf(h.T), yOf(s.value(h)))
		}
		fmt.Fprintf(&b, `<path d="%s" fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`,
			path.String(), s.color)
		last := hist[len(hist)-1]
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="4" fill="%s" stroke="var(--surface)" stroke-width="2"><title>%s now: %s</title></circle>`,
			xOf(last.T), yOf(s.value(last)), s.color, html.EscapeString(s.name), compactFull(s.value(last)))
	}
	// hover: one invisible column per hour with the values of that hour
	colW := (w - left - right) / float64(len(hist))
	for _, h := range hist {
		parts := []string{h.T.UTC().Format("Jan 2, 15:00 UTC")}
		for _, s := range series {
			parts = append(parts, fmt.Sprintf("%s %s", s.name, compactFull(s.value(h))))
		}
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="transparent"><title>%s</title></rect>`,
			xOf(h.T)-colW/2, top, max(colW, 2), bottom-top, html.EscapeString(strings.Join(parts, "\n")))
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// barChart draws the counts as horizontal bars, largest first, the tail
// folded into "other".
func barChart(counts map[string]int, total int, fold bool) string {
	if len(counts) == 0 {
		return `<div class="empty">No installations reporting yet.</div>`
	}
	type item struct {
		label string
		n     int
	}
	var items []item
	for k, n := range counts {
		items = append(items, item{k, n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].label < items[j].label
	})
	if fold && len(items) > 6 {
		other := 0
		for _, it := range items[5:] {
			other += it.n
		}
		items = append(items[:5], item{"other", other})
	}
	const w, labelW, barH, rowH = 420.0, 110.0, 12.0, 26.0
	height := float64(len(items))*rowH + 8
	peak := items[0].n
	for _, it := range items {
		peak = max(peak, it.n)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" role="img">`, w, height)
	for i, it := range items {
		y := 8 + float64(i)*rowH
		bw := (w - labelW - 70) * float64(it.n) / float64(peak)
		share := ""
		if total > 0 {
			share = fmt.Sprintf(" (%.0f%%)", 100*float64(it.n)/float64(total))
		}
		fmt.Fprintf(&b, `<g><title>%s: %d%s</title>`, html.EscapeString(it.label), it.n, share)
		fmt.Fprintf(&b, `<text x="0" y="%.1f" font-size="12.5" fill="var(--ink)">%s</text>`, y+barH-1, html.EscapeString(it.label))
		// square at the baseline, 4px rounded at the data end
		r := min(4.0, bw/2)
		fmt.Fprintf(&b, `<path d="M%.1f,%.1f H%.1f Q%.1f,%.1f %.1f,%.1f V%.1f Q%.1f,%.1f %.1f,%.1f H%.1f Z" fill="var(--s1)"/>`,
			labelW, y, labelW+bw-r, labelW+bw, y, labelW+bw, y+r, y+barH-r, labelW+bw, y+barH, labelW+bw-r, y+barH, labelW)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" font-size="12" fill="var(--ink2)">%d%s</text></g>`,
			labelW+bw+6, y+barH-1, it.n, share)
	}
	b.WriteString(`</svg>`)
	return b.String()
}
