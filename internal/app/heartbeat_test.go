package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// okCheck is a passive check that always completes cleanly, so the heartbeat
// has a recent completed check to vouch for.
type okCheck struct{}

func (okCheck) Name() string               { return "test.ok" }
func (okCheck) Tier() model.Tier           { return model.TierPassive }
func (okCheck) Applies(a model.Asset) bool { return a.Kind == model.KindIP }
func (okCheck) Run(context.Context, check.Target) (*check.Result, error) {
	return &check.Result{}, nil
}

type hbServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newHBServer(t *testing.T) *hbServer {
	t.Helper()
	s := &hbServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *hbServer) hits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

func heartbeatApp(t *testing.T, ctx context.Context, roles []string, hbURL string, interval time.Duration) *App {
	t.Helper()
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false
	cfg.Vulnintel.Enabled = false
	cfg.Nuclei.Enabled = false
	cfg.Expansion.CTLogs = false
	cfg.Database.URL = pgtest.NewURL(t)
	cfg.Scope.Include = []string{"127.0.0.1"}
	cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "static", IPs: []string{"127.0.0.1"}}}
	cfg.Checks = map[string]map[string]any{"net.ports": {"ports": "1"}}
	cfg.Server.Roles = roles
	cfg.Server.MetricsAddr = "127.0.0.1:0"
	cfg.Server.HTTPAddr = "127.0.0.1:0"
	cfg.Auth.Mode = "none"
	cfg.Notify.Heartbeat = config.HeartbeatConfig{URL: hbURL + "/ping/abc-uuid", Interval: interval, Method: "GET", Timeout: 5 * time.Second}
	a, err := New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Version: "test", ExtraChecks: []check.Check{okCheck{}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func heartbeatCount(t *testing.T, a *App) float64 {
	t.Helper()
	mfs, err := a.metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var n float64
	for _, mf := range mfs {
		if mf.GetName() == "deckard_heartbeat_total" {
			for _, m := range mf.GetMetric() {
				n += m.GetCounter().GetValue()
			}
		}
	}
	return n
}

func serveFor(t *testing.T, ctx context.Context, a *App) (stop func()) {
	t.Helper()
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- a.Serve(sctx) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(45 * time.Second):
			t.Error("Serve did not return")
		}
	}
}

// The scheduler pings once a check has completed.
func TestSchedulerSendsHeartbeat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	srv := newHBServer(t)
	// Interval 2s: the health window is 4s, so a scan that completed just
	// before a beat is comfortably inside it even on a slow machine.
	a := heartbeatApp(t, ctx, []string{"scheduler", "worker"}, srv.URL, 2*time.Second)
	if a.hb == nil {
		t.Fatal("heartbeat not built although notify.heartbeat.url is set")
	}
	stop := serveFor(t, ctx, a)
	deadline := time.Now().Add(60 * time.Second)
	for len(srv.hits()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	hits := srv.hits()
	if len(hits) == 0 {
		t.Fatal("the scheduler never sent a heartbeat")
	}
	if hits[0] != "GET /ping/abc-uuid" {
		t.Fatalf("heartbeat request = %q", hits[0])
	}
}

// Worker and API replicas never ping, whatever their health: the heartbeat
// beats immediately when started, so had it started the counter would move.
func TestNonSchedulerRolesNeverSendHeartbeat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	srv := newHBServer(t)
	a := heartbeatApp(t, ctx, []string{"worker", "api"}, srv.URL, time.Minute)
	stop := serveFor(t, ctx, a)
	time.Sleep(1500 * time.Millisecond)
	stop()
	if n := heartbeatCount(t, a); n != 0 || len(srv.hits()) != 0 {
		t.Fatalf("a non-scheduler replica ran the heartbeat: %v attempts, hits %v", n, srv.hits())
	}
}
