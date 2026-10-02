package app_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/app"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// mockAlertmanager records the alerts deckard posts.
type mockAlertmanager struct {
	mu     sync.Mutex
	alerts []map[string]any
	srv    *httptest.Server
}

func newMockAlertmanager(t *testing.T) *mockAlertmanager {
	t.Helper()
	m := &mockAlertmanager{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		m.alerts = append(m.alerts, batch...)
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockAlertmanager) labels(key string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, a := range m.alerts {
		if l, ok := a["labels"].(map[string]any); ok {
			if v, ok := l[key].(string); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestScanFindsExposedPortAndAlerts exercises the whole pipeline: static
// source -> inventory -> scope guard -> engine -> real net.ports check ->
// findings -> Alertmanager. A local listener plays the exposed service.
func TestScanFindsExposedPortAndAlerts(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	am := newMockAlertmanager(t)

	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false // hermetic: tests never reach the public dataset sources
	cfg.Database.URL = pgtest.NewURL(t)
	cfg.Scope.Include = []string{"127.0.0.1"} // explicit operator ownership of loopback for the test
	cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "static", IPs: []string{"127.0.0.1"}}}
	cfg.Checks = map[string]map[string]any{"net.ports": {"ports": strconv.Itoa(port)}}
	cfg.Nuclei.Enabled = false
	cfg.Notify.Alertmanager.URLs = []string{am.srv.URL}
	cfg.Server.Roles = []string{"scheduler", "worker"}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	a, err := app.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), app.Options{Version: "test"})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(a.Close)
	if err := a.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	st, err := a.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.AssetsBySource["lab"] < 1 {
		t.Fatalf("static source asset not in inventory: %+v", st.AssetsBySource)
	}
	if st.AssetsByScope["owned"] < 1 {
		t.Fatalf("loopback must be classified owned via scope.include: %+v", st.AssetsByScope)
	}
	if st.FindingsByCheck["net.ports"] < 1 {
		t.Fatalf("expected a net.ports finding for the open port %d, stats: %+v", port, st)
	}

	if err := a.Dispatcher().Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if !contains(am.labels("deckard_check"), "net.ports") {
		t.Fatalf("Alertmanager did not receive a net.ports alert; got checks %v", am.labels("deckard_check"))
	}
	if !contains(am.labels("asset"), "127.0.0.1") {
		t.Fatalf("alert missing asset label; got %v", am.labels("asset"))
	}
}

// TestUnownedAssetIsNeverScanned is the safety property end to end: an IP the
// operator did not declare as owned gets inventoried but no check runs on it,
// even though a listener is reachable there.
func TestUnownedAssetIsNeverScanned(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	connections := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections++
			mu.Unlock()
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false // hermetic: tests never reach the public dataset sources
	cfg.Database.URL = pgtest.NewURL(t)
	// No scope.include: loopback is NOT owned. The static source still lists it.
	cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "static", IPs: []string{"127.0.0.1"}}}
	cfg.Checks = map[string]map[string]any{"net.ports": {"ports": strconv.Itoa(port)}}
	cfg.Nuclei.Enabled = false
	cfg.Server.Roles = []string{"scheduler", "worker"}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, err := app.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), app.Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if connections != 0 {
		t.Fatalf("deckard connected to a non-owned address %d times; the scope guard must prevent any probe", connections)
	}
	st, _ := a.Stats(ctx)
	if st.FindingsByCheck["net.ports"] != 0 {
		t.Fatalf("no findings may exist for a non-owned asset: %+v", st)
	}
}
