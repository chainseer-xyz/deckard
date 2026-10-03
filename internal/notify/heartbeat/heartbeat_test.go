package heartbeat

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type fakeHealth struct {
	mu      sync.Mutex
	pingErr error
	last    time.Time
	lastErr error
}

func (h *fakeHealth) Ping(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pingErr
}

func (h *fakeHealth) LastCleanScan(context.Context) (time.Time, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last, h.lastErr
}

type hit struct{ method, path, query, ua string }

type server struct {
	*httptest.Server
	mu     sync.Mutex
	hits   []hit
	status int
}

func newServer(t *testing.T, status int) *server {
	t.Helper()
	s := &server{status: status}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, hit{r.Method, r.URL.Path, r.URL.RawQuery, r.UserAgent()})
		st := s.status
		s.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hits)
}

// secretURL puts a token in every part a heartbeat service might use.
func secretURL(base string) string {
	u, _ := url.Parse(base)
	u.User = url.UserPassword("hbuser", "PASSWORD-SECRET")
	u.Path = "/ping/PATH-SECRET-uuid"
	u.RawQuery = "token=QUERY-SECRET"
	return u.String()
}

var secrets = []string{"PASSWORD-SECRET", "hbuser", "PATH-SECRET", "QUERY-SECRET"}

func newPinger(t *testing.T, cfg config.HeartbeatConfig, h Health) (*Pinger, *bytes.Buffer, *[]string) {
	t.Helper()
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	var logs bytes.Buffer
	var mu sync.Mutex
	results := &[]string{}
	p, err := New(cfg, h, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		WithClock(func() time.Time { return t0 }), WithUserAgent("deckard/test"),
		WithRecorder(func(r string) { mu.Lock(); *results = append(*results, r); mu.Unlock() }))
	if err != nil {
		t.Fatal(err)
	}
	return p, &logs, results
}

func noLeak(t *testing.T, what, s string) {
	t.Helper()
	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			t.Errorf("%s leaks %q: %s", what, sec, s)
		}
	}
}

func TestHealthyBeatPings(t *testing.T) {
	for _, method := range []string{"GET", "post"} {
		srv := newServer(t, http.StatusOK)
		h := &fakeHealth{last: t0.Add(-time.Minute)}
		p, logs, results := newPinger(t, config.HeartbeatConfig{URL: secretURL(srv.URL), Method: method}, h)
		if got := p.Beat(context.Background()); got != ResultOK {
			t.Fatalf("%s: result %q", method, got)
		}
		if srv.count() != 1 {
			t.Fatalf("%s: hits = %d", method, srv.count())
		}
		got := srv.hits[0]
		if got.method != strings.ToUpper(method) || got.path != "/ping/PATH-SECRET-uuid" || got.query != "token=QUERY-SECRET" || got.ua != "deckard/test" {
			t.Errorf("%s: request = %+v", method, got)
		}
		if strings.Join(*results, ",") != ResultOK {
			t.Errorf("%s: recorded %v", method, *results)
		}
		noLeak(t, "logs", logs.String())
	}
}

func TestUnhealthyIsNotPinged(t *testing.T) {
	cases := []struct {
		name string
		h    *fakeHealth
		why  string
	}{
		{"database down", &fakeHealth{pingErr: errors.New("connection refused"), last: t0}, "database unreachable"},
		{"query fails", &fakeHealth{lastErr: errors.New("relation missing")}, "database query failed"},
		{"never scanned", &fakeHealth{}, "no check has completed yet"},
		{"wedged: last check too old", &fakeHealth{last: t0.Add(-11 * time.Minute)}, "no check completed in the last 10m0s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, http.StatusOK)
			p, logs, results := newPinger(t, config.HeartbeatConfig{URL: secretURL(srv.URL), Interval: 5 * time.Minute}, tc.h)
			if got := p.Beat(context.Background()); got != ResultUnhealthy {
				t.Fatalf("result %q, want unhealthy", got)
			}
			if srv.count() != 0 {
				t.Fatal("an unhealthy deckard pinged the dead-man's switch")
			}
			if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), tc.why) {
				t.Errorf("log = %s, want a WARN with %q", logs.String(), tc.why)
			}
			if strings.Join(*results, ",") != ResultUnhealthy {
				t.Errorf("recorded %v", *results)
			}
			noLeak(t, "logs", logs.String())
		})
	}
	// Exactly at the edge of the window still counts as healthy.
	srv := newServer(t, http.StatusOK)
	p, _, _ := newPinger(t, config.HeartbeatConfig{URL: srv.URL, Interval: 5 * time.Minute}, &fakeHealth{last: t0.Add(-10 * time.Minute)})
	if got := p.Beat(context.Background()); got != ResultOK {
		t.Fatalf("a check exactly two intervals ago: %q, want ok", got)
	}
}

func TestPingFailuresAreWarnedCountedAndRedacted(t *testing.T) {
	srv := newServer(t, http.StatusInternalServerError)
	p, logs, results := newPinger(t, config.HeartbeatConfig{URL: secretURL(srv.URL)}, &fakeHealth{last: t0})
	if got := p.Beat(context.Background()); got != ResultError {
		t.Fatalf("5xx: %q", got)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "status 500") {
		t.Errorf("log = %s", logs.String())
	}
	if !strings.Contains(logs.String(), "url="+srv.URL+" ") {
		t.Errorf("log should name scheme://host %s: %s", srv.URL, logs.String())
	}
	noLeak(t, "logs", logs.String())

	// Connection refused: the transport error embeds the URL; it must not leak.
	srv.Close()
	logs.Reset()
	if got := p.Beat(context.Background()); got != ResultError {
		t.Fatalf("refused: %q", got)
	}
	if !strings.Contains(logs.String(), "heartbeat ping failed") {
		t.Errorf("log = %s", logs.String())
	}
	noLeak(t, "logs", logs.String())
	if strings.Join(*results, ",") != "error,error" {
		t.Errorf("recorded %v", *results)
	}
}

func TestTimeoutIsAFailure(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	t.Cleanup(func() { close(block); srv.Close() })
	p, logs, _ := newPinger(t, config.HeartbeatConfig{URL: secretURL(srv.URL), Timeout: 50 * time.Millisecond}, &fakeHealth{last: t0})
	if got := p.Beat(context.Background()); got != ResultError {
		t.Fatalf("result %q, want error", got)
	}
	noLeak(t, "logs", logs.String())
}

func TestRedact(t *testing.T) {
	u, _ := url.Parse(secretURL("https://hc-ping.example:8443"))
	if got := Redact(u); got != "https://hc-ping.example:8443" {
		t.Fatalf("Redact = %q", got)
	}
}

func TestNewValidationNeverEchoesTheURL(t *testing.T) {
	h := &fakeHealth{}
	for _, cfg := range []config.HeartbeatConfig{
		{URL: "ftp://hbuser:PASSWORD-SECRET@x/PATH-SECRET?token=QUERY-SECRET", Interval: time.Minute, Timeout: time.Second},
		{URL: "https://hbuser:PASSWORD-SECRET@x/PATH-SECRET?token=QUERY-SECRET", Method: "PUT", Interval: time.Minute, Timeout: time.Second},
		{URL: "https://hbuser:PASSWORD-SECRET@x/PATH-SECRET?token=QUERY-SECRET", Interval: 0, Timeout: time.Second},
	} {
		_, err := New(cfg, h, nil)
		if err == nil {
			t.Fatalf("accepted %+v", cfg.Method)
		}
		noLeak(t, "error", err.Error())
	}
	if _, err := New(config.HeartbeatConfig{URL: "https://x/", Interval: time.Minute, Timeout: time.Second}, nil, nil); err == nil {
		t.Fatal("nil health accepted")
	}
}

// Run beats right away and then every interval until cancelled.
func TestRunBeatsUntilCancelled(t *testing.T) {
	srv := newServer(t, http.StatusOK)
	h := &fakeHealth{last: t0}
	p, _, _ := newPinger(t, config.HeartbeatConfig{URL: srv.URL, Interval: 20 * time.Millisecond}, h)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for srv.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if srv.count() < 3 {
		t.Fatalf("hits = %d, want at least 3", srv.count())
	}
	n := srv.count()
	time.Sleep(60 * time.Millisecond)
	if srv.count() != n {
		t.Fatal("pinged after Run returned")
	}
}
