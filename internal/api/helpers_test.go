package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const testToken = "tok-for-tests"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

type fakeActions struct {
	mu        sync.Mutex
	rescans   []int64
	syncs     []string
	rescanErr error
	syncErr   error
}

func (f *fakeActions) RescanAsset(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rescans = append(f.rescans, id)
	return f.rescanErr
}

func (f *fakeActions) TriggerSync(_ context.Context, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs = append(f.syncs, s)
	return f.syncErr
}

type env struct {
	t       *testing.T
	store   *fakestore.Store
	actions *fakeActions
	clock   *fakeClock
	logs    *syncBuf
	bc      *api.Broadcaster
	srv     *api.Server
	h       http.Handler
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// newEnv builds a server with token auth by default.
func newEnv(t *testing.T, mutate ...func(*api.Deps)) *env {
	t.Helper()
	e := &env{t: t, store: fakestore.New(), actions: &fakeActions{}, clock: &fakeClock{t: t0},
		logs: &syncBuf{}, bc: api.NewBroadcaster()}
	d := api.Deps{
		Store: e.store, Authenticator: auth.NewToken(testToken), BaseURL: "https://deckard.example.com",
		Actions: e.actions, Clock: e.clock, Logger: slog.New(slog.NewJSONHandler(e.logs, nil)),
		Broadcaster: e.bc, SSEPollInterval: 20 * time.Millisecond, SSEHeartbeat: 60 * time.Millisecond,
	}
	for _, m := range mutate {
		m(&d)
	}
	e.srv = api.New(d)
	e.h = e.srv.Handler()
	return e
}

type resp struct {
	*httptest.ResponseRecorder
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body.Bytes(), v); err != nil {
		t.Fatalf("bad json %q: %v", r.Body.String(), err)
	}
}

func (r resp) errCode(t *testing.T) string {
	t.Helper()
	var e struct {
		Error struct{ Code, Message string }
	}
	r.json(t, &e)
	return e.Error.Code
}

// do performs a request with the test bearer token.
func (e *env) do(method, target string, body string, hdr ...string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	req.Header.Set("Authorization", "Bearer "+testToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return resp{rec}
}

func (e *env) get(target string) resp { e.t.Helper(); return e.do("GET", target, "") }

func (e *env) seed() {
	e.store.Do(func(s *fakestore.Store) {
		mk := func(id int64, k model.AssetKind, key, src string, sc model.ScopeClass, zone string) model.Asset {
			a := model.Asset{ID: id, Kind: k, Key: key, Source: src, Scope: sc, Zone: zone, FirstSeen: t0, LastSeen: t0}
			s.Assets[id] = a
			return a
		}
		mk(1, model.KindHostname, "www.example.com", "cf", model.ScopeOwned, "example.com")
		mk(2, model.KindIP, "203.0.113.5", "cf", model.ScopeOwned, "")
		mk(3, model.KindService, "203.0.113.5:443", "scan", model.ScopeOwned, "")
		mk(4, model.KindHostname, "api.example.com", "aws", model.ScopeShared, "example.com")
		mk(5, model.KindCertificate, "sha256:abcd", "scan", model.ScopeExternal, "")
		gone := mk(6, model.KindHostname, "old.example.com", "cf", model.ScopeOwned, "example.com")
		rm := t0.Add(-time.Hour)
		gone.RemovedAt = &rm
		s.Assets[6] = gone
		s.Rels = []model.Relation{
			{FromID: 1, ToID: 2, Type: model.RelResolvesTo},
			{FromID: 2, ToID: 3, Type: model.RelExposes},
			{FromID: 3, ToID: 5, Type: model.RelHasCert},
			{FromID: 4, ToID: 2, Type: model.RelResolvesTo},
		}
		s.Obs[1] = []model.Observation{{AssetID: 1, Check: "tls.cert", Data: map[string]any{"days": 30}, ObservedAt: t0}}
		s.Bases[1] = []store.Baseline{{AssetID: 1, Check: "tls.cert", Data: map[string]any{"days": 90}, Stable: true, Consistent: 3, UpdatedAt: t0}}
		fi := func(id, asset int64, check string, sev model.Severity, st model.FindingStatus, zone, src, title string) {
			s.Findings[id] = model.Finding{ID: id, Check: check, AssetID: asset, AssetKey: s.Assets[asset].Key, Zone: zone,
				Source: src, Severity: sev, Title: title, Status: st, FirstSeen: t0, LastSeen: t0}
		}
		fi(1, 1, "tls.cert", model.SeverityHigh, model.StatusOpen, "example.com", "cf", "cert expiring")
		fi(2, 1, "http.headers", model.SeverityLow, model.StatusOpen, "example.com", "cf", "missing hsts")
		fi(3, 4, "tls.cert", model.SeverityCritical, model.StatusAcknowledged, "example.com", "aws", "expired cert")
		fi(4, 2, "net.ports", model.SeverityMedium, model.StatusResolved, "", "scan", "ssh open")
		fi(5, 1, "dns.caa", model.SeverityInfo, model.StatusSuppressed, "example.com", "cf", "no caa")
		s.Syncs = []store.SyncStatus{
			{Source: "cf", Type: "cloudflare", LastRun: t0, LastOK: t0, AssetCount: 3},
			{Source: "aws", Type: "route53", LastRun: t0, Error: "throttled"},
			{Source: "k8s", Type: "kubernetes", LastRun: t0, LastOK: t0},
		}
		for i := 1; i <= 5; i++ {
			s.Scans = append(s.Scans, store.ScanRun{ID: int64(i), AssetID: 1, Check: "tls.cert", Tier: "passive", StartedAt: t0})
		}
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second) // generous: loaded CI runners are slow
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func newReq(method, target string) *http.Request { return httptest.NewRequest(method, target, nil) }
func newRec() *httptest.ResponseRecorder         { return httptest.NewRecorder() }
