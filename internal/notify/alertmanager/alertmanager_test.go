package alertmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

type recorded struct {
	method, path, auth, ctype string
	alerts                    []postableAlert
}

type mock struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []recorded
	hits atomic.Int32
}

func newMock(t *testing.T, handler func(n int, w http.ResponseWriter)) *mock {
	t.Helper()
	m := &mock{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var alerts []postableAlert
		_ = json.NewDecoder(r.Body).Decode(&alerts)
		m.mu.Lock()
		m.reqs = append(m.reqs, recorded{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), alerts})
		m.mu.Unlock()
		n := int(m.hits.Add(1))
		if handler != nil {
			handler(n, w)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func openFindings(n int) []model.Finding {
	out := make([]model.Finding, n)
	for i := range out {
		out[i] = finding(func(f *model.Finding) { f.ID = int64(i + 1); f.Fingerprint = fmt.Sprintf("fp%d", i) })
	}
	return out
}

func newNotifier(t *testing.T, cfg config.AlertmanagerConfig, env map[string]string, opts ...Option) (*Notifier, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	opts = append([]Option{WithClock(func() time.Time { return t0 }), WithRetry(4, time.Millisecond)}, opts...)
	n, err := New(cfg, func(k string) string { return env[k] }, log, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return n, &logs
}

func TestNotifyRequestShapeAndAuth(t *testing.T) {
	m := newMock(t, nil)
	n, logs := newNotifier(t,
		config.AlertmanagerConfig{URLs: []string{m.URL + "/"}, Resend: 5 * time.Minute, Username: "deckard", PasswordEnv: "AM_PW"},
		map[string]string{"AM_PW": "s3cr3t-pw"}, WithBaseURL("https://b.example"))
	if n.Name() != "alertmanager" {
		t.Error("name")
	}
	if err := n.Notify(context.Background(), openFindings(2), nil); err != nil {
		t.Fatal(err)
	}
	if len(m.reqs) != 1 {
		t.Fatalf("reqs=%d", len(m.reqs))
	}
	r := m.reqs[0]
	if r.method != http.MethodPost || r.path != "/api/v2/alerts" || r.ctype != "application/json" {
		t.Errorf("req = %+v", r)
	}
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://x", nil)
	req.SetBasicAuth("deckard", "s3cr3t-pw")
	if r.auth != req.Header.Get("Authorization") {
		t.Errorf("auth = %q", r.auth)
	}
	if len(r.alerts) != 2 || r.alerts[0].Labels["alertname"] != "DeckardDnsDangling" {
		t.Errorf("alerts = %+v", r.alerts)
	}
	if !r.alerts[0].EndsAt.Equal(t0.Add(10 * time.Minute)) {
		t.Errorf("endsAt = %v", r.alerts[0].EndsAt)
	}
	if strings.Contains(logs.String(), "s3cr3t-pw") {
		t.Error("password leaked into logs")
	}
}

func TestNoAuthHeaderWhenUnconfigured(t *testing.T) {
	m := newMock(t, nil)
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil)
	if err := n.Notify(context.Background(), openFindings(1), nil); err != nil {
		t.Fatal(err)
	}
	if m.reqs[0].auth != "" {
		t.Errorf("auth = %q", m.reqs[0].auth)
	}
}

func TestNewValidation(t *testing.T) {
	env := func(string) string { return "" }
	if _, err := New(config.AlertmanagerConfig{}, env, nil); err == nil {
		t.Error("no urls should error")
	}
	if _, err := New(config.AlertmanagerConfig{URLs: []string{"ftp://x"}}, env, nil); err == nil {
		t.Error("bad scheme should error")
	}
	_, err := New(config.AlertmanagerConfig{URLs: []string{"http://u:hunter2@x"}, PasswordEnv: "MISSING"}, env, nil)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v", err)
	}
	_, err = New(config.AlertmanagerConfig{URLs: []string{"://u:hunter2@x"}}, env, nil)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v", err)
	}
}

func TestResolvedSentWithEndsAt(t *testing.T) {
	m := newMock(t, nil)
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil)
	acked := finding(func(f *model.Finding) { f.Status = model.StatusAcknowledged; f.Fingerprint = "acked" })
	res := finding(func(f *model.Finding) { f.Fingerprint = "gone" })
	if err := n.Notify(context.Background(), []model.Finding{acked}, []model.Finding{res}); err != nil {
		t.Fatal(err)
	}
	a := m.reqs[0].alerts
	if len(a) != 1 || a[0].Labels["fingerprint"] != "gone" || !a[0].EndsAt.Equal(t0) {
		t.Errorf("alerts = %+v", a)
	}
}

func TestNothingToSendMakesNoRequest(t *testing.T) {
	m := newMock(t, nil)
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil)
	acked := finding(func(f *model.Finding) { f.Status = model.StatusSuppressed })
	if err := n.Notify(context.Background(), []model.Finding{acked}, nil); err != nil {
		t.Fatal(err)
	}
	if m.hits.Load() != 0 {
		t.Errorf("hits = %d", m.hits.Load())
	}
}

func TestIdempotentReassert(t *testing.T) {
	m := newMock(t, nil)
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil)
	open := openFindings(3)
	for i := 0; i < 2; i++ {
		if err := n.Notify(context.Background(), open, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.reqs) != 2 || len(m.reqs[0].alerts) != 3 || len(m.reqs[1].alerts) != 3 {
		t.Errorf("each call must fully re-assert: %d reqs", len(m.reqs))
	}
}

func TestMultiURL(t *testing.T) {
	up := newMock(t, nil)
	down := newMock(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(500) })
	n, logs := newNotifier(t, config.AlertmanagerConfig{URLs: []string{down.URL, up.URL}}, nil, WithRetry(2, time.Millisecond))
	if err := n.Notify(context.Background(), openFindings(1), nil); err != nil {
		t.Fatalf("one up should succeed: %v", err)
	}
	if up.hits.Load() != 1 {
		t.Errorf("up hits = %d", up.hits.Load())
	}
	if down.hits.Load() != 2 {
		t.Errorf("down hits = %d (retries)", down.hits.Load())
	}
	if !strings.Contains(logs.String(), "push failed") {
		t.Error("per-URL error not logged")
	}

	down2 := newMock(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(503) })
	n, _ = newNotifier(t, config.AlertmanagerConfig{URLs: []string{down.URL, down2.URL}}, nil, WithRetry(2, time.Millisecond))
	if err := n.Notify(context.Background(), openFindings(1), nil); err == nil {
		t.Fatal("all down should error")
	}
}

func TestConnectionRefusedIsError(t *testing.T) {
	s := httptest.NewServer(nil)
	url := s.URL
	s.Close()
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{url}}, nil, WithRetry(2, time.Millisecond))
	if err := n.Notify(context.Background(), openFindings(1), nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestRetry429Then200(t *testing.T) {
	m := newMock(t, func(n int, w http.ResponseWriter) {
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
		}
	})
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil)
	if err := n.Notify(context.Background(), openFindings(1), nil); err != nil {
		t.Fatal(err)
	}
	if m.hits.Load() != 2 {
		t.Errorf("hits = %d", m.hits.Load())
	}
}

func TestRetry5xxExhausts(t *testing.T) {
	m := newMock(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(502) })
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil, WithRetry(3, time.Millisecond))
	if err := n.Notify(context.Background(), openFindings(1), nil); err == nil {
		t.Fatal("expected error")
	}
	if m.hits.Load() != 3 {
		t.Errorf("hits = %d", m.hits.Load())
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	for _, code := range []int{400, 401, 404} {
		m := newMock(t, func(_ int, w http.ResponseWriter) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte("bad things"))
		})
		n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil)
		err := n.Notify(context.Background(), openFindings(1), nil)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(code)) {
			t.Errorf("code %d: err = %v", code, err)
		}
		if m.hits.Load() != 1 {
			t.Errorf("code %d: hits = %d, want 1", code, m.hits.Load())
		}
	}
}

func TestContextCancelMidRetry(t *testing.T) {
	m := newMock(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(500) })
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil, WithRetry(10, 10*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for m.hits.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	start := time.Now()
	err := n.Notify(ctx, openFindings(1), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("did not abort backoff promptly")
	}
	if m.hits.Load() != 1 {
		t.Errorf("hits = %d", m.hits.Load())
	}
}

func TestPerRequestTimeout(t *testing.T) {
	m := newMock(t, func(_ int, w http.ResponseWriter) { time.Sleep(300 * time.Millisecond) })
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}, Timeout: 20 * time.Millisecond}, nil, WithRetry(1, time.Millisecond))
	start := time.Now()
	if err := n.Notify(context.Background(), openFindings(1), nil); err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Error("timeout not enforced")
	}
}

func TestBatching250Alerts(t *testing.T) {
	m := newMock(t, nil)
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil)
	if err := n.Notify(context.Background(), openFindings(250), nil); err != nil {
		t.Fatal(err)
	}
	if len(m.reqs) != 3 {
		t.Fatalf("reqs = %d", len(m.reqs))
	}
	sizes := []int{len(m.reqs[0].alerts), len(m.reqs[1].alerts), len(m.reqs[2].alerts)}
	if sizes[0] != 100 || sizes[1] != 100 || sizes[2] != 50 {
		t.Errorf("sizes = %v", sizes)
	}
}

func TestBatchFailureReported(t *testing.T) {
	m := newMock(t, func(n int, w http.ResponseWriter) {
		if n == 2 {
			w.WriteHeader(400)
		}
	})
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}}, nil)
	if err := n.Notify(context.Background(), openFindings(250), nil); err == nil {
		t.Fatal("a failed batch must surface as an error")
	}
	if m.hits.Load() != 3 {
		t.Errorf("remaining batches should still be attempted, hits = %d", m.hits.Load())
	}
}
