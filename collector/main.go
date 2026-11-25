// Command collector receives the anonymous usage reports of xdp-loader
// (loader/telemetry.rs) and publishes the totals.
//
//	POST /v1/report         one report, JSON, at most 4 KiB
//	GET  /v1/summary        servers and players right now, packets dropped
//	GET  /v1/chart.svg      players over the last 30 days (?theme=dark)
//	GET  /v1/badge/servers  shields.io endpoint badge
//	GET  /v1/badge/players  shields.io endpoint badge
//
// What it keeps is exactly what the reports hold, the latest report per
// installation id. It never stores or logs addresses. Standard library only.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxBody = 4 << 10
	// an installation reports every 30 minutes; one seen within this window
	// counts as running
	activeWindow = 65 * time.Minute
	// reports of one id closer together than this are ignored
	minGap = 60 * time.Second
	// installations not heard of for this long are forgotten
	forgetAfter = 30 * 24 * time.Hour
	maxIDs      = 200_000
)

var (
	hexID      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	versionRe  = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,32}$`)
	kernelRe   = regexp.MustCompile(`^[0-9A-Za-z._+~-]{0,64}$`)
	archRe     = regexp.MustCompile(`^[0-9a-z_]{1,16}$`)
	knownModes = map[string]bool{"driver": true, "skb": true, "auto": true}
	knownFeats = map[string]bool{
		"java": true, "hosts": true, "bedrock": true, "pong": true, "nethernet": true,
		"tcp_guard": true, "voice": true, "udp_guard": true, "ipv6": true, "metrics": true,
	}
)

// Players connected at the time of a report.
type Players struct {
	Java      uint32 `json:"java"`
	Bedrock   uint32 `json:"bedrock"`
	NetherNet uint32 `json:"nethernet"`
	Voice     uint32 `json:"voice"`
}

// Packets since the previous report of the same installation.
type Packets struct {
	Incoming uint64 `json:"incoming"`
	Dropped  uint64 `json:"dropped"`
}

// Report is what xdp-loader sends; see Report in loader/telemetry.rs.
type Report struct {
	V            int      `json:"v"`
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Kernel       string   `json:"kernel"`
	Arch         string   `json:"arch"`
	CPUs         int      `json:"cpus"`
	Mode         *string  `json:"mode"`
	Features     []string `json:"features"`
	Players      *Players `json:"players"`
	Packets      *Packets `json:"packets"`
	UptimeSecs   uint64   `json:"uptime_secs"`
	IntervalSecs uint64   `json:"interval_secs"`
}

func (r *Report) validate() error {
	switch {
	case r.V != 1:
		return errors.New("unknown report version")
	case !hexID.MatchString(r.ID):
		return errors.New("bad id")
	case !versionRe.MatchString(r.Version):
		return errors.New("bad version")
	case !kernelRe.MatchString(r.Kernel):
		return errors.New("bad kernel")
	case !archRe.MatchString(r.Arch):
		return errors.New("bad arch")
	case r.CPUs < 0 || r.CPUs > 4096:
		return errors.New("bad cpus")
	case r.Mode != nil && !knownModes[*r.Mode]:
		return errors.New("bad mode")
	case len(r.Features) > len(knownFeats):
		return errors.New("too many features")
	case r.IntervalSecs < 10 || r.IntervalSecs > 86400:
		return errors.New("bad interval")
	}
	for _, f := range r.Features {
		if !knownFeats[f] {
			return errors.New("unknown feature")
		}
	}
	if p := r.Players; p != nil && (p.Java > 1e6 || p.Bedrock > 1e6 || p.NetherNet > 1e6 || p.Voice > 1e6) {
		return errors.New("implausible player count")
	}
	// a 400 Gbit/s port at its smallest packets for a whole day
	if p := r.Packets; p != nil && (p.Incoming > 6e13 || p.Dropped > p.Incoming) {
		return errors.New("implausible packet count")
	}
	return nil
}

type entry struct {
	Report Report    `json:"report"`
	Seen   time.Time `json:"seen"`
}

type day struct {
	Incoming uint64 `json:"incoming"`
	Dropped  uint64 `json:"dropped"`
}

// snapshot is the summary at one hour, the history behind /v1/chart.svg.
type snapshot struct {
	T         time.Time `json:"t"`
	Servers   int       `json:"servers"`
	Players   uint64    `json:"players"`
	Java      uint32    `json:"java"`
	Bedrock   uint32    `json:"bedrock"`
	NetherNet uint32    `json:"nethernet"`
}

// a year of hourly snapshots
const maxSnapshots = 24 * 366

type state struct {
	Installs map[string]*entry `json:"installs"`
	// UTC date -> packets reported that day
	Days map[string]*day `json:"days"`
	// all time, never forgotten
	DroppedTotal uint64 `json:"dropped_total"`
	// hourly, oldest first
	Snapshots []snapshot `json:"snapshots"`
}

type store struct {
	mu   sync.Mutex
	path string
	s    state
	now  func() time.Time
}

func newStore(path string) (*store, error) {
	st := &store{path: path, now: time.Now, s: state{Installs: map[string]*entry{}, Days: map[string]*day{}}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &st.s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if st.s.Installs == nil {
		st.s.Installs = map[string]*entry{}
	}
	if st.s.Days == nil {
		st.s.Days = map[string]*day{}
	}
	return st, nil
}

var errTooSoon = errors.New("too soon")

func (st *store) add(r Report) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	if e, ok := st.s.Installs[r.ID]; ok {
		if now.Sub(e.Seen) < minGap {
			return errTooSoon
		}
	} else if len(st.s.Installs) >= maxIDs {
		return errors.New("full")
	}
	st.s.Installs[r.ID] = &entry{Report: r, Seen: now}
	if r.Packets != nil {
		key := now.UTC().Format("2006-01-02")
		d := st.s.Days[key]
		if d == nil {
			d = &day{}
			st.s.Days[key] = d
		}
		d.Incoming += r.Packets.Incoming
		d.Dropped += r.Packets.Dropped
		st.s.DroppedTotal += r.Packets.Dropped
	}
	return nil
}

// Summary is the public view, GET /v1/summary.
type Summary struct {
	Servers      int            `json:"servers"`
	Players      Players        `json:"players"`
	PlayersTotal uint64         `json:"players_total"`
	DroppedToday uint64         `json:"dropped_today"`
	DroppedTotal uint64         `json:"dropped_total"`
	Versions     map[string]int `json:"versions"`
	Features     map[string]int `json:"features"`
	Modes        map[string]int `json:"modes"`
	Arches       map[string]int `json:"arches"`
	Kernels      map[string]int `json:"kernels"`
	Updated      time.Time      `json:"updated"`
}

func (st *store) summary() Summary {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	sum := Summary{
		Versions: map[string]int{}, Features: map[string]int{}, Modes: map[string]int{},
		Arches: map[string]int{}, Kernels: map[string]int{}, Updated: now.UTC().Truncate(time.Second),
	}
	for _, e := range st.s.Installs {
		if now.Sub(e.Seen) > activeWindow {
			continue
		}
		r := e.Report
		sum.Servers++
		if p := r.Players; p != nil {
			sum.Players.Java += p.Java
			sum.Players.Bedrock += p.Bedrock
			sum.Players.NetherNet += p.NetherNet
			sum.Players.Voice += p.Voice
		}
		sum.Versions[r.Version]++
		for _, f := range r.Features {
			sum.Features[f]++
		}
		if r.Mode != nil {
			sum.Modes[*r.Mode]++
		}
		sum.Arches[r.Arch]++
		sum.Kernels[majorMinor(r.Kernel)]++
	}
	// voice runs next to a game connection, so it is not a player of its own
	sum.PlayersTotal = uint64(sum.Players.Java) + uint64(sum.Players.Bedrock) + uint64(sum.Players.NetherNet)
	if d := st.s.Days[now.UTC().Format("2006-01-02")]; d != nil {
		sum.DroppedToday = d.Dropped
	}
	sum.DroppedTotal = st.s.DroppedTotal
	return sum
}

func majorMinor(kernel string) string {
	parts := strings.SplitN(kernel, ".", 3)
	if len(parts) < 2 {
		return "other"
	}
	return parts[0] + "." + strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' })
}

// snap records the current summary once per hour (on the hour, UTC).
func (st *store) snap() {
	sum := st.summary()
	hour := st.now().UTC().Truncate(time.Hour)
	st.mu.Lock()
	defer st.mu.Unlock()
	if n := len(st.s.Snapshots); n > 0 && !st.s.Snapshots[n-1].T.Before(hour) {
		return
	}
	st.s.Snapshots = append(st.s.Snapshots, snapshot{
		T: hour, Servers: sum.Servers, Players: sum.PlayersTotal,
		Java: sum.Players.Java, Bedrock: sum.Players.Bedrock, NetherNet: sum.Players.NetherNet,
	})
	if extra := len(st.s.Snapshots) - maxSnapshots; extra > 0 {
		st.s.Snapshots = append([]snapshot(nil), st.s.Snapshots[extra:]...)
	}
}

// history returns the snapshots of the last `days` days.
func (st *store) history(days int) []snapshot {
	st.mu.Lock()
	defer st.mu.Unlock()
	from := st.now().Add(-time.Duration(days) * 24 * time.Hour)
	var out []snapshot
	for _, s := range st.s.Snapshots {
		if !s.T.Before(from) {
			out = append(out, s)
		}
	}
	return out
}

// forget drops installations not heard of for a month and days older than a
// year, so that the file can not grow without bound.
func (st *store) forget() {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	for id, e := range st.s.Installs {
		if now.Sub(e.Seen) > forgetAfter {
			delete(st.s.Installs, id)
		}
	}
	oldest := now.UTC().AddDate(-1, 0, 0).Format("2006-01-02")
	for key := range st.s.Days {
		if key < oldest {
			delete(st.s.Days, key)
		}
	}
}

func (st *store) save() error {
	st.mu.Lock()
	data, err := json.Marshal(st.s)
	st.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

func (st *store) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/report", func(w http.ResponseWriter, req *http.Request) {
		var r Report
		dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, maxBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			http.Error(w, "bad report", http.StatusBadRequest)
			return
		}
		if err := r.validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch err := st.add(r); {
		case errors.Is(err, errTooSoon):
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		case err != nil:
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	mux.HandleFunc("GET /v1/summary", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, st.summary())
	})
	mux.HandleFunc("GET /v1/chart.svg", func(w http.ResponseWriter, req *http.Request) {
		theme := themes["light"]
		if req.URL.Query().Get("theme") == "dark" {
			theme = themes["dark"]
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		// GitHub's image proxy keeps it no longer than this
		w.Header().Set("Cache-Control", "public, max-age=600")
		_, _ = w.Write(renderChart(theme, st.summary(), st.history(30), st.now()))
	})
	mux.HandleFunc("GET /v1/badge/{what}", func(w http.ResponseWriter, req *http.Request) {
		sum := st.summary()
		var label string
		var value uint64
		switch req.PathValue("what") {
		case "servers":
			label, value = "servers", uint64(sum.Servers)
		case "players":
			label, value = "players", sum.PlayersTotal
		default:
			http.NotFound(w, req)
			return
		}
		writeJSON(w, map[string]any{"schemaVersion": 1, "label": label, "message": compact(value), "color": "blue"})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(v)
}

func compact(v uint64) string {
	switch {
	case v >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(v)/1e9)
	case v >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(v)/1e6)
	case v >= 10_000:
		return fmt.Sprintf("%.0fK", float64(v)/1e3)
	default:
		return fmt.Sprint(v)
	}
}

func main() {
	addr := flag.String("listen", "127.0.0.1:8099", "address to listen on")
	path := flag.String("state", "collector.json", "file the state is kept in")
	flag.Parse()

	st, err := newStore(*path)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              *addr,
		Handler:           st.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(os.Stderr, "", 0),
	}
	go func() {
		for range time.Tick(time.Minute) {
			st.snap()
			st.forget()
			if err := st.save(); err != nil {
				log.Printf("save: %v", err)
			}
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		if err := st.save(); err != nil {
			log.Printf("save: %v", err)
		}
		os.Exit(0)
	}()
	log.Printf("collector listening on %s, %d installations known", *addr, len(st.s.Installs))
	log.Fatal(server.ListenAndServe())
}

// sorted keys, used by the tests
func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
