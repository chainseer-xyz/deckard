package app_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/app"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

// testConfig is a loopback lab: 127.0.0.1 is declared owned via scope.include
// and listed by a static source; net.ports probes only port. The database is a
// fresh clone unless dbURL is given (restart scenarios).
func testConfig(t *testing.T, dbURL string, port int) *config.Config {
	t.Helper()
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false // hermetic: tests never reach the public dataset sources
	if dbURL == "" {
		dbURL = pgtest.NewURL(t)
	}
	cfg.Database.URL = dbURL
	cfg.Scope.Include = []string{"127.0.0.1"}
	cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "static", IPs: []string{"127.0.0.1"}}}
	cfg.Checks = map[string]map[string]any{"net.ports": {"ports": strconv.Itoa(port)}}
	cfg.Nuclei.Enabled = false
	cfg.Expansion.CTLogs = false
	cfg.Vulnintel.Enabled = false // never reach cisa.gov or api.first.org from tests
	cfg.Server.Roles = []string{"scheduler", "worker"}
	cfg.Server.MetricsAddr = "127.0.0.1:0"
	cfg.Server.HTTPAddr = "127.0.0.1:0"
	cfg.Findings.ResolveAfter = 2
	cfg.Auth.Mode = "none"
	return cfg
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newApp(t *testing.T, ctx context.Context, cfg *config.Config, opts app.Options) *app.App {
	t.Helper()
	if opts.Version == "" {
		opts.Version = "test"
	}
	a, err := app.New(ctx, cfg, quietLog(), opts)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(a.Close)
	return a
}

// listener is a local TCP service playing the exposed port; it counts
// connections and can be closed to simulate the port being shut.
type listener struct {
	ln    net.Listener
	mu    sync.Mutex
	conns int
	Port  int
}

func newListener(t *testing.T) *listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{ln: ln, Port: ln.Addr().(*net.TCPAddr).Port}
	t.Cleanup(l.Close)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.mu.Lock()
			l.conns++
			l.mu.Unlock()
			_ = c.Close()
		}
	}()
	return l
}

func (l *listener) Close() { _ = l.ln.Close() }

func (l *listener) Conns() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns
}

// openDB opens a second, read-oriented store on the same database.
func openDB(t *testing.T, ctx context.Context, url string) store.Store {
	t.Helper()
	st, err := postgres.New(ctx, url, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

func appOptions() app.Options { return app.Options{Version: "test"} }
