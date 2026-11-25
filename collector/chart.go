package main

import (
	"fmt"
	"html"
	"math"
	"strings"
	"time"
)

// theme holds the colors of one GitHub theme; the same tokens as the charts
// in docs/charts (dev/bench/charts.py).
type theme struct {
	surface, ink, ink2, grid, axis, border, line, wash string
}

var themes = map[string]theme{
	"light": {surface: "#ffffff", ink: "#191919", ink2: "#666666", grid: "#e7e7e7", axis: "#c2c2c2",
		border: "rgba(11,11,11,0.10)", line: "#257de0", wash: "rgba(37,125,224,0.10)"},
	"dark": {surface: "#0d1117", ink: "#efefef", ink2: "#9c9c9c", grid: "#262c36", axis: "#474747",
		border: "rgba(255,255,255,0.10)", line: "#338ced", wash: "rgba(51,140,237,0.12)"},
}

const (
	chartW    = 880
	chartH    = 300
	plotLeft  = 64
	plotRight = 28
	font      = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
)

type svgBuf struct {
	strings.Builder
	t theme
}

func (b *svgBuf) text(x, y float64, s string, size float64, color string, weight int, anchor string) {
	fmt.Fprintf(b, `<text x="%.1f" y="%.1f" font-size="%g" font-weight="%d" fill="%s" text-anchor="%s">%s</text>`+"\n",
		x, y, size, weight, color, anchor, html.EscapeString(s))
}

func (b *svgBuf) line(x1, y1, x2, y2 float64, color string) {
	fmt.Fprintf(b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>`+"\n", x1, y1, x2, y2, color)
}

// renderChart draws three stat tiles (servers, players, packets dropped
// today) above the players of the last 30 days.
func renderChart(t theme, sum Summary, hist []snapshot, now time.Time) []byte {
	b := &svgBuf{t: t}
	fmt.Fprintf(b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="%s" role="img" aria-label="minecraft-xdp-guard usage: %d servers, %d players">`+"\n",
		chartW, chartH, chartW, chartH, font, sum.Servers, sum.PlayersTotal)
	fmt.Fprintf(b, `<rect x="0.5" y="0.5" width="%d" height="%d" rx="8" fill="%s" stroke="%s"/>`+"\n",
		chartW-1, chartH-1, t.surface, t.border)

	// stat tiles: label, value; the value in the system sans, proportional figures
	tiles := []struct{ label, value string }{
		{"Servers protected", compactFull(uint64(sum.Servers))},
		{"Players connected", compactFull(sum.PlayersTotal)},
		{"Packets dropped today", compactFull(sum.DroppedToday)},
	}
	for i, tile := range tiles {
		x := 24 + float64(i)*200
		b.text(x, 34, tile.label, 12.5, t.ink2, 400, "start")
		b.text(x, 68, tile.value, 30, t.ink, 600, "start")
	}
	b.text(chartW-24, 34, "live, updated hourly", 11, t.ink2, 400, "end")
	b.text(chartW-24, 50, "stats.olune.me", 11, t.ink2, 400, "end")

	top, bottom := 112.0, float64(chartH-40)
	left, right := float64(plotLeft), float64(chartW-plotRight)
	b.text(24, 98, "Players over the last 30 days", 12.5, t.ink2, 600, "start")
	b.line(left, bottom, right, bottom, t.axis)

	from := now.Add(-30 * 24 * time.Hour)
	xOf := func(ts time.Time) float64 {
		return left + (right-left)*ts.Sub(from).Seconds()/(30*24*3600)
	}
	// a date every week
	for d := 0; d <= 30; d += 7 {
		ts := from.Add(time.Duration(d) * 24 * time.Hour)
		b.text(xOf(ts), bottom+18, ts.UTC().Format("Jan 2"), 11, t.ink2, 400, "middle")
	}

	if len(hist) < 2 {
		b.text((left+right)/2, (top+bottom)/2+4, "Collecting data: the line fills in over the next hours", 12.5, t.ink2, 400, "middle")
		b.WriteString("</svg>\n")
		return []byte(b.String())
	}

	var peak uint64
	for _, s := range hist {
		if s.Players > peak {
			peak = s.Players
		}
	}
	ceiling := niceCeiling(peak)
	step := tickStep(ceiling)
	yOf := func(v uint64) float64 { return bottom - (bottom-top)*float64(v)/float64(ceiling) }
	for v := step; v <= ceiling; v += step {
		b.line(left, yOf(v), right, yOf(v), t.grid)
		b.text(left-10, yOf(v)+4, compactFull(v), 11, t.ink2, 400, "end")
	}
	b.text(left-10, bottom+4, "0", 11, t.ink2, 400, "end")

	var path strings.Builder
	for i, s := range hist {
		cmd := "L"
		if i == 0 {
			cmd = "M"
		}
		fmt.Fprintf(&path, "%s%.1f,%.1f ", cmd, xOf(s.T), yOf(s.Players))
	}
	first, last := hist[0], hist[len(hist)-1]
	// the area wash, then the 2px line and an end dot with a surface ring
	fmt.Fprintf(b, `<path d="%sL%.1f,%.1f L%.1f,%.1f Z" fill="%s" stroke="none"/>`+"\n",
		path.String(), xOf(last.T), bottom, xOf(first.T), bottom, t.wash)
	fmt.Fprintf(b, `<path d="%s" fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`+"\n",
		strings.TrimSpace(path.String()), t.line)
	fmt.Fprintf(b, `<circle cx="%.1f" cy="%.1f" r="4.5" fill="%s" stroke="%s" stroke-width="2"/>`+"\n",
		xOf(last.T), yOf(last.Players), t.line, t.surface)
	b.WriteString("</svg>\n")
	return []byte(b.String())
}

// niceCeiling rounds up to 1, 2 or 5 times a power of ten, at least 10.
func niceCeiling(v uint64) uint64 {
	if v < 10 {
		return 10
	}
	p := math.Pow(10, math.Floor(math.Log10(float64(v))))
	for _, m := range []float64{1, 2, 5, 10} {
		if c := uint64(m * p); c >= v {
			return c
		}
	}
	return uint64(10 * p)
}

// tickStep splits a niceCeiling into 4 or 5 round steps: 10 -> 2,
// 20 -> 5, 50 -> 10.
func tickStep(ceiling uint64) uint64 {
	p := uint64(math.Pow(10, math.Floor(math.Log10(float64(ceiling)))))
	switch ceiling / p {
	case 2:
		return p / 2
	case 5:
		return p
	default:
		return max(1, p/5)
	}
}

// compactFull is compact() with thousands separators below 10K.
func compactFull(v uint64) string {
	if v >= 10_000 {
		return compact(v)
	}
	s := fmt.Sprint(v)
	if len(s) > 3 {
		s = s[:len(s)-3] + "," + s[len(s)-3:]
	}
	return s
}
