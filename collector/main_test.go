package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const good = `{"v":1,"id":"0123456789abcdef0123456789abcdef","version":"1.0.1","kernel":"6.12.38+deb13-amd64",
"arch":"x86_64","cpus":12,"mode":"driver","features":["java","bedrock"],
"players":{"java":40,"bedrock":7,"nethernet":3,"voice":10},"packets":{"incoming":1000,"dropped":900},
"uptime_secs":120,"interval_secs":1800}`

func newTestStore(t *testing.T) (*store, *time.Time) {
	t.Helper()
	st, err := newStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	return st, &now
}

func post(t *testing.T, h http.Handler, body string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/report", strings.NewReader(body)))
	return rec.Code
}

func TestReportAndSummary(t *testing.T) {
	st, now := newTestStore(t)
	h := st.handler()
	if code := post(t, h, good); code != http.StatusNoContent {
		t.Fatalf("good report: %d", code)
	}
	if code := post(t, h, good); code != http.StatusTooManyRequests {
		t.Fatalf("repeated report: %d", code)
	}
	sum := st.summary()
	if sum.Servers != 1 || sum.PlayersTotal != 50 || sum.DroppedToday != 900 || sum.DroppedTotal != 900 {
		t.Fatalf("summary: %+v", sum)
	}
	if got := keys(sum.Features); strings.Join(got, ",") != "bedrock,java" {
		t.Fatalf("features: %v", got)
	}
	if sum.Kernels["6.12"] != 1 {
		t.Fatalf("kernels: %v", sum.Kernels)
	}

	// silent for longer than the window: not running any more, packets stay
	*now = now.Add(2 * time.Hour)
	sum = st.summary()
	if sum.Servers != 0 || sum.PlayersTotal != 0 || sum.DroppedTotal != 900 {
		t.Fatalf("after the window: %+v", sum)
	}
	*now = now.Add(31 * 24 * time.Hour)
	st.forget()
	if len(st.s.Installs) != 0 {
		t.Fatal("old installation not forgotten")
	}
}

func TestRejects(t *testing.T) {
	st, _ := newTestStore(t)
	h := st.handler()
	bad := map[string]string{
		"unknown field":   strings.Replace(good, `"cpus":12`, `"cpus":12,"ip":"1.2.3.4"`, 1),
		"bad id":          strings.Replace(good, "0123456789abcdef0123456789abcdef", "nope", 1),
		"unknown feature": strings.Replace(good, `"bedrock"]`, `"bedrock","spam"]`, 1),
		"dropped > in":    strings.Replace(good, `"dropped":900`, `"dropped":9000`, 1),
		"player count":    strings.Replace(good, `"java":40`, `"java":40000000`, 1),
		"html in version": strings.Replace(good, `"version":"1.0.1"`, `"version":"<b>"`, 1),
		"too big":         strings.Replace(good, `"kernel":"6.12.38+deb13-amd64"`, `"kernel":"`+strings.Repeat("a", 5000)+`"`, 1),
		"not json":        "hello",
	}
	for name, body := range bad {
		if code := post(t, h, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	if len(st.s.Installs) != 0 {
		t.Fatal("a rejected report was stored")
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	st, _ := newTestStore(t)
	post(t, st.handler(), good)
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	again, err := newStore(st.path)
	if err != nil {
		t.Fatal(err)
	}
	again.now = st.now
	if sum := again.summary(); sum.Servers != 1 || sum.DroppedTotal != 900 {
		t.Fatalf("after restart: %+v", sum)
	}
}

func TestBadge(t *testing.T) {
	st, _ := newTestStore(t)
	h := st.handler()
	post(t, h, good)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/badge/players", nil))
	if !strings.Contains(rec.Body.String(), `"message":"50"`) {
		t.Fatalf("badge: %s", rec.Body.String())
	}
}
