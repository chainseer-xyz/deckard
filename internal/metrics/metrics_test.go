package metrics_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/metrics"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler(m.Registry()).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	return rec.Body.String()
}

func TestRecorderMetrics(t *testing.T) {
	m := metrics.New("v1.2.3", "abc123")
	m.ObserveScan("tls.cert", "passive", 1500*time.Millisecond, nil)
	m.ObserveScan("tls.cert", "passive", time.Second, errors.New("boom"))
	m.ObserveSync("prod-cf", 2*time.Second, true)
	m.InventoryChange("added", 3)
	m.InventoryChange("added", 2)
	m.InventoryChange("removed", 0) // ignored
	m.SetQueueDepth("active", 7)
	m.SetQueueDepth("active", 4)

	out := scrape(t, m)
	for _, want := range []string{
		`deckard_checks_run_total{check="tls.cert",tier="passive"} 2`,
		`deckard_scan_errors_total{check="tls.cert"} 1`,
		`deckard_scan_duration_seconds_count{check="tls.cert",tier="passive"} 2`,
		`deckard_scan_duration_seconds_sum{check="tls.cert",tier="passive"} 2.5`,
		`deckard_source_sync_duration_seconds_count{source="prod-cf"} 1`,
		`deckard_inventory_changes_total{type="added"} 5`,
		`deckard_queue_depth{queue="active"} 4`,
		`deckard_build_info{commit="abc123",go_version="go`,
		`version="v1.2.3"} 1`,
		"go_goroutines",
		"process_",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in scrape", want)
		}
	}
	if strings.Contains(out, `deckard_inventory_changes_total{type="removed"}`) {
		t.Error("zero-count change should not create a series")
	}
}

func TestStateCollector(t *testing.T) {
	fs := fakestore.New()
	fs.StatsVal = store.Stats{
		AssetsByKind:    map[string]int{"hostname": 4},
		AssetsBySource:  map[string]int{"prod-cf": 5},
		AssetsByScope:   map[string]int{"owned": 3},
		FindingsBySev:   map[string]int{"high": 2},
		FindingsByCheck: map[string]int{"tls.cert": 2},
	}
	fs.Syncs = []store.SyncStatus{
		{Source: "prod-cf", LastOK: time.Unix(1700000000, 0)},
		{Source: "never", Error: "x"}, // no success -> no series
	}
	m := metrics.New("dev", "none")
	m.RegisterState(fs, time.Hour)

	out := scrape(t, m)
	for _, want := range []string{
		`deckard_assets{kind="hostname",scope="all",source="all"} 4`,
		`deckard_assets{kind="all",scope="all",source="prod-cf"} 5`,
		`deckard_assets{kind="all",scope="owned",source="all"} 3`,
		`deckard_findings_open{check="all",severity="high"} 2`,
		`deckard_findings_open{check="tls.cert",severity="all"} 2`,
		`deckard_source_last_success_timestamp{source="prod-cf"} 1.7e+09`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in scrape:\n%s", want, out)
		}
	}
	if strings.Contains(out, `source="never"`) {
		t.Error("source without success must not emit last_success")
	}
	// Cached: a second scrape within ttl must not hit the store again.
	scrape(t, m)
	if n := fs.StatsCalls(); n != 1 {
		t.Errorf("Stats called %d times, want 1 (cache)", n)
	}
}

func TestCollectorErrorServesStaleThenCounts(t *testing.T) {
	fs := fakestore.New()
	fs.StatsVal = store.Stats{FindingsBySev: map[string]int{"low": 1}}
	m := metrics.New("dev", "none")
	m.RegisterState(fs, 0) // ttl 0 => refresh every scrape
	scrape(t, m)
	fs.Do(func(s *fakestore.Store) { s.StatsErr = errors.New("db down") })
	out := scrape(t, m)
	if !strings.Contains(out, `deckard_findings_open{check="all",severity="low"} 1`) {
		t.Error("stale snapshot should still be served on refresh failure")
	}
	// Registry.Gather runs collectors concurrently, so the error counter can be
	// read before the failing collector increments it within the same scrape.
	// It must be visible by the next scrape.
	out = scrape(t, m)
	if !regexp.MustCompile(`deckard_metrics_collect_errors_total [1-9]`).MatchString(out) {
		t.Errorf("collect error not counted:\n%s", out)
	}
}

func TestCollectorFirstLoadFailureEmitsNothing(t *testing.T) {
	fs := fakestore.New()
	fs.StatsErr = errors.New("down")
	c := metrics.NewCollector(fs, time.Minute, nil)
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Errorf("got %d metrics, want 0", n)
	}
}

func TestNopRecorder(t *testing.T) {
	var r metrics.Recorder = metrics.Nop{}
	r.ObserveScan("a", "b", 0, nil)
	r.ObserveSync("a", 0, true)
	r.InventoryChange("a", 1)
	r.SetQueueDepth("a", 1)
}

func TestServeListener(t *testing.T) {
	m := metrics.New("dev", "none")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- metrics.ServeListener(ctx, ln, m.Registry()) }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "deckard_build_info") {
		t.Fatalf("bad scrape: %d", resp.StatusCode)
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/other", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("/other = %d, want 404", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not shut down")
	}
}

func TestServeBadAddr(t *testing.T) {
	m := metrics.New("dev", "none")
	if err := metrics.Serve(context.Background(), "256.1.1.1:99999", m.Registry()); err == nil {
		t.Fatal("expected listen error")
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	m := metrics.New("dev", "none")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- metrics.Serve(ctx, "127.0.0.1:0", m.Registry()) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRefdataMetrics(t *testing.T) {
	m := metrics.New("dev", "none")
	m.ObserveRefdata("shared_ranges", "ok")
	m.ObserveRefdata("shared_ranges", "ok")
	m.ObserveRefdata("shared_ranges", "rejected")
	m.SetRefdataState("shared_ranges", 812, time.Now().Add(-90*time.Second))
	out := scrape(t, m)
	for _, want := range []string{
		`deckard_refdata_refresh_total{dataset="shared_ranges",result="ok"} 2`,
		`deckard_refdata_refresh_total{dataset="shared_ranges",result="rejected"} 1`,
		`deckard_refdata_entries{dataset="shared_ranges"} 812`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in scrape", want)
		}
	}
	re := regexp.MustCompile(`deckard_refdata_age_seconds\{dataset="shared_ranges"\} (\d+)`)
	if mm := re.FindStringSubmatch(out); mm == nil || len(mm[1]) != 2 {
		t.Errorf("age series missing or not ~90s: %v\n%s", mm, out)
	}
}
