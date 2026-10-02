package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/source/registry"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// ---- helpers -------------------------------------------------------------

// alertsFor returns the posted alerts for (check, asset) split into firing
// (endsAt in the future) and resolved (endsAt already past).
func (m *mockAlertmanager) alertsFor(checkName, asset string) (firing, resolved int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, a := range m.alerts {
		l, _ := a["labels"].(map[string]any)
		if l["deckard_check"] != checkName || l["asset"] != asset {
			continue
		}
		s, _ := a["endsAt"].(string)
		end, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			continue
		}
		if end.After(now) {
			firing++
		} else {
			resolved++
		}
	}
	return firing, resolved
}

func netPortsFindings(t *testing.T, ctx context.Context, st store.Store, statuses ...model.FindingStatus) []model.Finding {
	t.Helper()
	fs, _, err := st.ListFindings(ctx, store.FindingFilter{Check: "net.ports", Statuses: statuses})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func serviceAssets(t *testing.T, ctx context.Context, st store.Store) (live, removed int) {
	t.Helper()
	as, _, err := st.ListAssets(ctx, store.AssetFilter{Kind: model.KindService, IncludeRemoved: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.RemovedAt != nil {
			removed++
		} else {
			live++
		}
	}
	return live, removed
}

// httpSource is a test source type: {"ips":[...]} over HTTP, 500 on demand.
type httpSource struct {
	name, url string
}

func (s *httpSource) Name() string { return s.name }
func (s *httpSource) Type() string { return "e2e-http" }
func (s *httpSource) Discover(ctx context.Context) (*source.Discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("e2e-http source: status %d", resp.StatusCode)
	}
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	d := &source.Discovery{}
	for _, ip := range body.IPs {
		d.Assets = append(d.Assets, model.AssetInput{Kind: model.KindIP, Key: ip, Source: s.name, Attrs: map[string]any{"owned": true}})
	}
	return d, nil
}

var registerHTTPSource sync.Once

func useHTTPSource() {
	registerHTTPSource.Do(func() {
		registry.Register("e2e-http", func(c config.SourceConfig, _ config.ScopeConfig, _ func(string) string, _ *slog.Logger) (source.Source, error) {
			return &httpSource{name: c.Name, url: c.BaseURL}, nil
		})
	})
}

// ---- tests ---------------------------------------------------------------

// (a) Closing a port resolves the finding after findings.resolve_after clean
// runs, garbage-collects the derived service asset, and Alertmanager receives
// the resolved notice (endsAt in the past).
func TestE2EClosingPortResolvesFindingRemovesServiceAndNotifies(t *testing.T) {
	ln := newListener(t)
	am := newMockAlertmanager(t)
	cfg := testConfig(t, "", ln.Port)
	cfg.Notify.Alertmanager.URLs = []string{am.srv.URL}
	cfg.Profiles.Active.Interval = time.Millisecond // re-scan on every pass
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	a := newApp(t, ctx, cfg, appOptions())
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db := openDB(t, ctx, cfg.Database.URL)

	pass := func(n int) {
		t.Helper()
		time.Sleep(20 * time.Millisecond)
		if err := a.Engine().RunOnce(ctx); err != nil {
			t.Fatalf("RunOnce %d: %v", n, err)
		}
	}
	pass(1)
	if got := netPortsFindings(t, ctx, db, model.StatusOpen); len(got) != 1 {
		t.Fatalf("open net.ports findings = %d, want 1", len(got))
	}
	if live, _ := serviceAssets(t, ctx, db); live != 1 {
		t.Fatalf("derived service assets = %d, want 1", live)
	}
	if err := a.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if firing, resolved := am.alertsFor("net.ports", "127.0.0.1"); firing < 1 || resolved != 0 {
		t.Fatalf("after the first pass: firing=%d resolved=%d", firing, resolved)
	}

	ln.Close() // the port is shut

	pass(2) // clean run 1: the derived service is garbage-collected right away
	if live, removed := serviceAssets(t, ctx, db); live != 0 || removed != 1 {
		t.Fatalf("closed port: service assets live=%d removed=%d, want 0/1", live, removed)
	}
	if got := netPortsFindings(t, ctx, db, model.StatusOpen); len(got) != 1 {
		t.Fatalf("after 1 clean run (resolve_after=2) the finding must still be open, got %d", len(got))
	}
	pass(3) // clean run 2: resolved
	if got := netPortsFindings(t, ctx, db, model.StatusOpen); len(got) != 0 {
		t.Fatalf("finding still open after resolve_after clean runs: %+v", got)
	}
	if got := netPortsFindings(t, ctx, db, model.StatusResolved); len(got) != 1 {
		t.Fatalf("resolved findings = %d, want 1", len(got))
	}
	if err := a.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, resolved := am.alertsFor("net.ports", "127.0.0.1"); resolved < 1 {
		t.Fatalf("Alertmanager never received the resolved (endsAt in the past) notice: %v", am.alerts)
	}
}

// (b) Removing an asset from the static source resolves its findings (C1), and
// the dispatcher stops re-sending the alert.
func TestE2ERemovedAssetResolvesFindingsAndStopsAlerting(t *testing.T) {
	ln := newListener(t)
	am := newMockAlertmanager(t)
	cfg1 := testConfig(t, "", ln.Port)
	cfg1.Notify.Alertmanager.URLs = []string{am.srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	a1 := newApp(t, ctx, cfg1, appOptions())
	if err := a1.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a1.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	db := openDB(t, ctx, cfg1.Database.URL)
	if got := netPortsFindings(t, ctx, db, model.StatusOpen); len(got) != 1 {
		t.Fatalf("open findings = %d, want 1", len(got))
	}
	if err := a1.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if firing, _ := am.alertsFor("net.ports", "127.0.0.1"); firing < 1 {
		t.Fatal("expected a firing alert before the asset is removed")
	}

	// The operator drops 127.0.0.1 from the static source; a new process syncs.
	cfg2 := testConfig(t, cfg1.Database.URL, ln.Port)
	cfg2.Notify.Alertmanager.URLs = []string{am.srv.URL}
	cfg2.Sources[0].IPs = nil
	a2 := newApp(t, ctx, cfg2, appOptions())
	if err := a2.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a2.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce after removal: %v", err)
	}
	as, _, _ := db.ListAssets(ctx, store.AssetFilter{Kind: model.KindIP, IncludeRemoved: true})
	if len(as) != 1 || as[0].RemovedAt == nil {
		t.Fatalf("static IP must be marked removed: %+v", as)
	}
	if got := netPortsFindings(t, ctx, db, model.StatusOpen); len(got) != 0 {
		t.Fatalf("findings of a removed asset must resolve, still open: %+v", got)
	}
	if err := a2.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, resolved := am.alertsFor("net.ports", "127.0.0.1"); resolved < 1 {
		t.Fatalf("no resolved notice for the removed asset: %v", am.alerts)
	}
	firingBefore, _ := am.alertsFor("net.ports", "127.0.0.1")
	for i := 0; i < 2; i++ {
		if err := a2.Dispatcher().Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if firingAfter, _ := am.alertsFor("net.ports", "127.0.0.1"); firingAfter != firingBefore {
		t.Fatalf("dispatcher kept re-sending a removed asset: firing %d -> %d", firingBefore, firingAfter)
	}
}

// (c) A second pass right after the first scans nothing that is not due: the
// due logic (store.LastScans) sees the first pass's runs.
func TestE2ESecondRunOnceDoesNotRescan(t *testing.T) {
	ln := newListener(t)
	cfg := testConfig(t, "", ln.Port)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	a := newApp(t, ctx, cfg, appOptions())
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db := openDB(t, ctx, cfg.Database.URL)
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := db.ListScans(ctx, 0)
	if err != nil || len(first) == 0 {
		t.Fatalf("first pass recorded %d scans, err=%v", len(first), err)
	}
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := db.ListScans(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != len(first) {
		perKey := map[string]int{}
		for _, r := range second {
			perKey[fmt.Sprintf("%d|%s", r.AssetID, r.Check)]++
		}
		t.Fatalf("second RunOnce created %d new scan rows (per asset/check: %v)", len(second)-len(first), perKey)
	}
	// A fresh process on the same database agrees (state lives in the store).
	a2 := newApp(t, ctx, testConfig(t, cfg.Database.URL, ln.Port), appOptions())
	if err := a2.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a2.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	third, _ := db.ListScans(ctx, 0)
	if len(third) != len(first) {
		t.Fatalf("a restarted process re-scanned: %d -> %d rows", len(first), len(third))
	}
}

// (d) A failed source neither removes assets nor resolves findings.
func TestE2EFailedSourceKeepsAssetsAndFindings(t *testing.T) {
	useHTTPSource()
	ln := newListener(t)
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"ips":["127.0.0.1"]}`))
	}))
	t.Cleanup(srv.Close)

	cfg := testConfig(t, "", ln.Port)
	cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "e2e-http", BaseURL: srv.URL}}
	// Default intervals: nothing is rescanned in the second pass, so any change
	// in assets or findings could only come from the failed sync.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	a := newApp(t, ctx, cfg, appOptions())
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db := openDB(t, ctx, cfg.Database.URL)
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := netPortsFindings(t, ctx, db, model.StatusOpen); len(got) != 1 {
		t.Fatalf("open findings = %d, want 1", len(got))
	}

	down.Store(true)
	ln.Close() // even with the port now shut, a failed source must not remove or resolve anything
	if err := a.Engine().RunOnce(ctx); err == nil {
		t.Fatal("RunOnce must report the failed source")
	}
	ips, _, _ := db.ListAssets(ctx, store.AssetFilter{Kind: model.KindIP, IncludeRemoved: true})
	if len(ips) != 1 || ips[0].RemovedAt != nil {
		t.Fatalf("a failed source removed assets: %+v", ips)
	}
	if got := netPortsFindings(t, ctx, db, model.StatusOpen); len(got) != 1 {
		t.Fatalf("a failed source resolved findings: %d open", len(got))
	}
	if live, _ := serviceAssets(t, ctx, db); live != 1 {
		t.Fatalf("derived services after a failed sync = %d, want 1", live)
	}
	syncs, _ := db.ListSyncs(ctx)
	if len(syncs) != 1 || syncs[0].Error == "" {
		t.Fatalf("sync status must record the failure: %+v", syncs)
	}
}

// (e) The safety property survives a restart: a stored "owned" claim for an
// address the guard never lets us probe (loopback without scope.include) is not
// resurrected by classifier rehydration, so the listener is never contacted.
func TestE2ENonOwnedNeverConnectedAcrossRestart(t *testing.T) {
	ln := newListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cfg1 := testConfig(t, "", ln.Port)
	cfg1.Scope.Include = nil
	a1 := newApp(t, ctx, cfg1, appOptions())
	if err := a1.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a1.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	cfg2 := testConfig(t, cfg1.Database.URL, ln.Port)
	cfg2.Scope.Include = nil
	cfg2.Sources = nil // restart without syncing: only rehydration knows the assets
	a2 := newApp(t, ctx, cfg2, appOptions())
	if err := a2.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a2.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ln.Conns(); n != 0 {
		t.Fatalf("deckard connected to a non-owned address %d times", n)
	}
	db := openDB(t, ctx, cfg1.Database.URL)
	if got := netPortsFindings(t, ctx, db); len(got) != 0 {
		t.Fatalf("findings for a non-owned asset: %+v", got)
	}
}
