package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/oauth2"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func raw(e *env, method, target string, hdr map[string]string) resp {
	req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return resp{rec}
}

func TestTokenModeRequiresBearerEverywhereButProbes(t *testing.T) {
	e := newEnv(t)
	e.seed()
	for _, p := range [][2]string{
		{"GET", "/api/v1/stats"}, {"GET", "/api/v1/assets"}, {"GET", "/api/v1/assets/1"}, {"GET", "/api/v1/findings"},
		{"GET", "/api/v1/me"}, {"GET", "/api/v1/events"}, {"GET", "/api/v1/openapi.yaml"}, {"GET", "/api/v1/nope"},
		{"POST", "/api/v1/findings/1/acknowledge"}, {"POST", "/api/v1/assets/1/rescan"}, {"POST", "/api/v1/sources/cf/sync"},
	} {
		r := raw(e, p[0], p[1], nil)
		if r.Code != 401 || r.errCode(t) != "unauthenticated" {
			t.Errorf("%s %s without token = %d", p[0], p[1], r.Code)
		}
		if r.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s %s: missing WWW-Authenticate", p[0], p[1])
		}
	}
	for _, p := range []string{"/healthz", "/readyz"} {
		if r := raw(e, "GET", p, nil); r.Code != 200 {
			t.Errorf("%s = %d without token", p, r.Code)
		}
	}
	// Query-string tokens are never accepted.
	if r := raw(e, "GET", "/api/v1/stats?token="+testToken, nil); r.Code != 401 {
		t.Errorf("query token = %d", r.Code)
	}
	if r := raw(e, "GET", "/api/v1/stats", map[string]string{"Authorization": "Bearer wrong"}); r.Code != 401 {
		t.Errorf("wrong token = %d", r.Code)
	}
	// Writes with token are not subject to CSRF.
	if r := e.do("POST", "/api/v1/findings/1/acknowledge", ""); r.Code != 200 {
		t.Errorf("token write = %d", r.Code)
	}
	var me struct {
		Subject, Method string
		AuthMode        string `json:"auth_mode"`
		CanWrite        bool   `json:"can_write"`
		CSRFToken       string `json:"csrf_token"`
	}
	e.get("/api/v1/me").json(t, &me)
	if me.AuthMode != "token" || me.Method != "token" || !me.CanWrite || me.CSRFToken != "" {
		t.Errorf("me = %+v", me)
	}
}

func TestNoneModeIsOpenAndWarns(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Authenticator = nil
		d.Auth = config.AuthConfig{Mode: "none"}
	})
	e.seed()
	if err := e.srv.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.logs.String(), "OPEN") {
		t.Errorf("none mode must log a loud warning: %s", e.logs.String())
	}
	if r := raw(e, "GET", "/api/v1/stats", nil); r.Code != 200 {
		t.Errorf("read = %d", r.Code)
	}
	r := raw(e, "POST", "/api/v1/findings/1/acknowledge", nil)
	if r.Code != 200 {
		t.Errorf("write = %d", r.Code)
	}
	if c := e.store.Changes; len(c) != 1 || c[0].Actor != "anonymous" {
		t.Errorf("changes = %+v", c)
	}
	var me struct {
		AuthMode string `json:"auth_mode"`
		CanWrite bool   `json:"can_write"`
	}
	raw(e, "GET", "/api/v1/me", nil).json(t, &me)
	if me.AuthMode != "none" || !me.CanWrite {
		t.Errorf("me = %+v", me)
	}
}

func TestTokenModeFromConfig(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Authenticator = nil
		d.Auth = config.AuthConfig{Mode: "token", TokenEnv: "BT"}
		d.AuthOptions = auth.Options{Getenv: func(k string) string {
			if k == "BT" {
				return "from-env-from-env-from-env-from-env-0123"
			}
			return ""
		}}
	})
	if e.srv.Err() != nil {
		t.Fatal(e.srv.Err())
	}
	if r := raw(e, "GET", "/api/v1/stats", map[string]string{"Authorization": "Bearer from-env-from-env-from-env-from-env-0123"}); r.Code != 200 {
		t.Errorf("= %d", r.Code)
	}
}

func TestMisconfiguredAuthFailsClosed(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Authenticator = nil
		d.Auth = config.AuthConfig{Mode: "token", TokenEnv: "UNSET"}
		d.AuthOptions = auth.Options{Getenv: func(string) string { return "" }}
	})
	if e.srv.Err() == nil {
		t.Fatal("Err() must report misconfiguration")
	}
	for _, hdr := range []map[string]string{nil, {"Authorization": "Bearer "}} {
		if r := raw(e, "GET", "/api/v1/stats", hdr); r.Code != 503 || r.errCode(t) != "auth_misconfigured" {
			t.Errorf("= %d %s", r.Code, r.Body)
		}
	}
	if r := raw(e, "GET", "/healthz", nil); r.Code != 200 {
		t.Error("probes must still work")
	}
}

// cookieAuth stands in for the OIDC session authenticator.
type cookieAuth struct{ csrf string }

func (cookieAuth) Mode() string { return "oidc" }
func (c cookieAuth) Authenticate(r *http.Request) (*auth.Identity, error) {
	if ck, err := r.Cookie("s"); err != nil || ck.Value != "ok" {
		return nil, auth.ErrUnauthenticated
	}
	return &auth.Identity{Subject: "u1", Email: "ada@example.com", EmailVerified: true, Method: auth.MethodCookie, CSRFToken: c.csrf}, nil
}

func TestCSRFOnCookieSessions(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.Authenticator = cookieAuth{csrf: "csrf-123"} })
	e.seed()
	do := func(method, target string, hdr map[string]string) resp {
		req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
		req.AddCookie(&http.Cookie{Name: "s", Value: "ok"})
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return resp{rec}
	}
	tests := []struct {
		name   string
		method string
		path   string
		hdr    map[string]string
		want   int
	}{
		{"read needs no csrf", "GET", "/api/v1/stats", nil, 200},
		{"write without csrf", "POST", "/api/v1/findings/1/acknowledge", nil, 403},
		{"write wrong csrf", "POST", "/api/v1/findings/1/acknowledge", map[string]string{"X-CSRF-Token": "nope"}, 403},
		{"write right csrf", "POST", "/api/v1/findings/1/acknowledge", map[string]string{"X-CSRF-Token": "csrf-123"}, 200},
		{"rescan without csrf", "POST", "/api/v1/assets/1/rescan", nil, 403},
		{"sync without csrf", "POST", "/api/v1/sources/cf/sync", nil, 403},
	}
	for _, tt := range tests {
		if r := do(tt.method, tt.path, tt.hdr); r.Code != tt.want {
			t.Errorf("%s: %d want %d", tt.name, r.Code, tt.want)
		}
	}
	if r := do("POST", "/api/v1/findings/1/acknowledge", nil); r.errCode(t) != "csrf" {
		t.Error("csrf error code")
	}
	if c := e.store.Changes; len(c) != 1 || c[0].Actor != "ada@example.com" {
		t.Errorf("actor = %+v", c)
	}
	var me struct {
		CSRFToken string `json:"csrf_token"`
		Method    string
	}
	do("GET", "/api/v1/me", nil).json(t, &me)
	if me.CSRFToken != "csrf-123" || me.Method != "cookie" {
		t.Errorf("me = %+v", me)
	}
	// No session cookie at all.
	r := raw(e, "GET", "/api/v1/stats", nil)
	if r.Code != 401 || !strings.Contains(r.Body.String(), "/auth/login") {
		t.Errorf("unauthenticated oidc = %d %s", r.Code, r.Body)
	}
	if r.Header().Get("WWW-Authenticate") != "" {
		t.Error("no Bearer challenge in oidc mode")
	}
}

func TestRequestIDAndAccessLog(t *testing.T) {
	e := newEnv(t)
	e.seed()
	r := e.do("GET", "/api/v1/assets?q=secret-search-term", "", "X-Request-ID", "abc-123")
	if r.Header().Get("X-Request-ID") != "abc-123" {
		t.Errorf("request id not honoured: %q", r.Header().Get("X-Request-ID"))
	}
	for _, bad := range []string{"has space", "x\ny", strings.Repeat("a", 65), "<script>"} {
		r := e.do("GET", "/api/v1/stats", "", "X-Request-ID", bad)
		if id := r.Header().Get("X-Request-ID"); id == bad || len(id) != 16 {
			t.Errorf("bad id %q -> %q", bad, id)
		}
	}
	if id := e.get("/api/v1/stats").Header().Get("X-Request-ID"); len(id) != 16 {
		t.Errorf("generated id = %q", id)
	}

	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["request_id"] == "abc-123" {
			line = m
		}
	}
	if line == nil {
		t.Fatalf("no access log for request: %s", e.logs.String())
	}
	if line["method"] != "GET" || line["path"] != "/api/v1/assets" || line["status"] != float64(200) ||
		line["route"] != "/api/v1/assets" || line["actor"] != "token" || line["msg"] != "http request" {
		t.Errorf("log line = %v", line)
	}
	if _, ok := line["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms missing: %v", line)
	}
	all := e.logs.String()
	if strings.Contains(all, "secret-search-term") || strings.Contains(all, testToken) {
		t.Error("access log leaked query string or token")
	}
}

type panicStore struct{ api.Actions }

func TestPanicRecovery(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.Actions = panicStore{} }) // nil embedded interface -> nil deref panic
	e.seed()
	r := e.do("POST", "/api/v1/sources/cf/sync", "")
	if r.Code != 500 || r.errCode(t) != "internal" {
		t.Fatalf("panic = %d %s", r.Code, r.Body)
	}
	if strings.Contains(r.Body.String(), "nil pointer") || strings.Contains(r.Body.String(), "goroutine") {
		t.Error("panic details leaked")
	}
	if !strings.Contains(e.logs.String(), "panic in handler") || !strings.Contains(e.logs.String(), `"level":"ERROR"`) {
		t.Errorf("panic not logged: %s", e.logs.String())
	}
	// server keeps serving
	if r := e.get("/api/v1/stats"); r.Code != 200 {
		t.Errorf("after panic = %d", r.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	r := e.get("/api/v1/stats")
	h := r.Header()
	for k, want := range map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Cache-Control":             "no-store",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	} {
		if h.Get(k) != want {
			t.Errorf("%s = %q want %q", k, h.Get(k), want)
		}
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("CSP = %q", h.Get("Content-Security-Policy"))
	}
	// no HSTS over plain http base URL
	e2 := newEnv(t, func(d *api.Deps) { d.BaseURL = "http://localhost:8080" })
	if e2.get("/api/v1/stats").Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be sent for http base URL")
	}
}

func TestCORS(t *testing.T) {
	// Off by default: no CORS headers even when an Origin is sent.
	e := newEnv(t)
	r := e.do("GET", "/api/v1/stats", "", "Origin", "https://evil.example")
	if r.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS must be off by default")
	}
	// Opt-in: exact-match origins only.
	e = newEnv(t, func(d *api.Deps) { d.CORSOrigins = []string{"https://ui.example.com"} })
	r = e.do("GET", "/api/v1/stats", "", "Origin", "https://ui.example.com")
	if r.Header().Get("Access-Control-Allow-Origin") != "https://ui.example.com" || r.Header().Get("Vary") == "" {
		t.Errorf("allowed origin headers: %v", r.Header())
	}
	r = e.do("GET", "/api/v1/stats", "", "Origin", "https://ui.example.com.evil.io")
	if r.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("non-listed origin allowed")
	}
	req := httptest.NewRequestWithContext(context.Background(), "OPTIONS", "/api/v1/findings/1/suppress", nil)
	req.Header.Set("Origin", "https://ui.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 204 || !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "X-CSRF-Token") {
		t.Errorf("preflight = %d %v", rec.Code, rec.Header())
	}
}

func TestGzip(t *testing.T) {
	e := newEnv(t)
	e.seed()
	r := e.do("GET", "/api/v1/assets", "", "Accept-Encoding", "gzip")
	if r.Header().Get("Content-Encoding") != "gzip" || r.Header().Get("Vary") == "" {
		t.Fatalf("not compressed: %v", r.Header())
	}
	zr, err := gzip.NewReader(bytes.NewReader(r.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(zr)
	var l listOut
	if err := json.Unmarshal(body, &l); err != nil || l.Total != 5 {
		t.Fatalf("decoded body: %v %s", err, body)
	}
	if r := e.get("/api/v1/assets"); r.Header().Get("Content-Encoding") != "" {
		t.Error("compressed without Accept-Encoding")
	}
	// errors compress too, 404 UI html too
	if r := e.do("GET", "/x/y", "", "Accept-Encoding", "gzip"); r.Header().Get("Content-Encoding") != "gzip" {
		t.Error("html not compressed")
	}
	// HEAD untouched
	req := httptest.NewRequestWithContext(context.Background(), "HEAD", "/healthz", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("HEAD compressed")
	}
}

func TestRequestBodyLimit(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.MaxBodyBytes = 32 })
	e.seed()
	r := e.do("POST", "/api/v1/findings/1/acknowledge", `{"note":"`+strings.Repeat("a", 100)+`"}`)
	if r.Code != 413 {
		t.Errorf("= %d", r.Code)
	}
}

type blockingStore struct{ *fakestore.Store }

func (b blockingStore) ListSyncs(ctx context.Context) ([]store.SyncStatus, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRequestTimeoutPropagatesToStore(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Store = blockingStore{fakestore.New()}
		d.RequestTimeout = 20 * time.Millisecond
	})
	r := e.get("/api/v1/sources")
	if r.Code != 504 || r.errCode(t) != "timeout" {
		t.Errorf("= %d %s", r.Code, r.Body)
	}
}

func TestHTTPMetricsRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	e := newEnv(t, func(d *api.Deps) { d.Registry = reg })
	e.seed()
	e.get("/api/v1/assets/1")
	e.get("/api/v1/assets/2")
	e.get("/api/v1/assets/999")
	raw(e, "GET", "/api/v1/stats", nil)
	if n := testutil.CollectAndCount(reg, "deckard_http_requests_total"); n != 3 {
		t.Errorf("series = %d, want 3 (2xx, 4xx on /assets/{id}; 4xx on stats)", n)
	}
	if got := counterValue(t, reg, "deckard_http_requests_total", map[string]string{"method": "GET", "route": "/api/v1/assets/{id}", "code": "2xx"}); got != 2 {
		t.Errorf("assets/{id} 2xx = %v", got)
	}
	// double registration (two servers, one registry) must not crash
	api.New(api.Deps{Store: e.store, Authenticator: auth.None{}, Registry: reg})
}

func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			n := 0
			for _, lp := range m.GetLabel() {
				if labels[lp.GetName()] == lp.GetValue() {
					n++
				}
			}
			if n == len(labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("series %v not found", labels)
	return 0
}

// stubProvider is enough for route registration; it is never exercised.
type stubProvider struct{}

func (stubProvider) Endpoint() oauth2.Endpoint                   { return oauth2.Endpoint{} }
func (stubProvider) Verifier(*oidc.Config) *oidc.IDTokenVerifier { return nil }

func oidcDeps(d *api.Deps) {
	d.Authenticator = nil
	d.Auth = config.AuthConfig{Mode: "oidc", OIDC: config.OIDCConfig{Issuer: "https://idp.example", ClientID: "c"}}
	d.AuthOptions = auth.Options{
		Getenv:   func(string) string { return strings.Repeat("s", 40) },
		Discover: func(context.Context, string) (auth.Provider, error) { return stubProvider{}, nil },
	}
}

func TestOIDCRoutesMountedAndNoStore(t *testing.T) {
	e := newEnv(t, oidcDeps)
	if e.srv.Err() != nil {
		t.Fatal(e.srv.Err())
	}
	r := raw(e, "GET", "/auth/login", nil)
	if r.Code != 302 || r.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("login = %d %v", r.Code, r.Header())
	}
	if r := raw(e, "GET", "/auth/unknown", nil); r.Code != 404 || r.errCode(t) != "not_found" {
		t.Errorf("unknown auth path = %d", r.Code)
	}
	// token mode has no /auth routes
	e2 := newEnv(t)
	if r := raw(e2, "GET", "/auth/login", nil); r.Code != 404 {
		t.Errorf("token mode /auth/login = %d", r.Code)
	}
}
