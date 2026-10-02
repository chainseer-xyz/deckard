package api_test

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// sseClient reads an event stream line by line from a live test server.
type sseClient struct {
	t      *testing.T
	cancel context.CancelFunc
	resp   *http.Response
	lines  chan string
	done   chan struct{}
}

func (e *env) stream(t *testing.T, ts *httptest.Server, path string, hdr ...string) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Accept-Encoding", "gzip") // must not be compressed
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // closed in t.Cleanup below; bodyclose doesn't trace into go func(){}() or t.Cleanup closures
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	c := &sseClient{t: t, cancel: cancel, resp: resp, lines: make(chan string, 256), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		defer close(c.lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
	}()
	t.Cleanup(func() { cancel(); _ = resp.Body.Close() })
	return c
}

// until returns lines up to and including the first line containing substr.
func (c *sseClient) until(substr string, d time.Duration) []string {
	c.t.Helper()
	var got []string
	timer := time.After(d)
	for {
		select {
		case l, ok := <-c.lines:
			if !ok {
				c.t.Fatalf("stream closed before %q; got %q", substr, got)
			}
			got = append(got, l)
			if strings.Contains(l, substr) {
				return got
			}
		case <-timer:
			c.t.Fatalf("timeout waiting for %q; got %q", substr, got)
		}
	}
}

func (c *sseClient) expectNo(substr string, d time.Duration) {
	c.t.Helper()
	timer := time.After(d)
	for {
		select {
		case l, ok := <-c.lines:
			if !ok {
				return
			}
			if strings.Contains(l, substr) {
				c.t.Fatalf("unexpected %q", l)
			}
		case <-timer:
			return
		}
	}
}

// sseServer registers Close as a cleanup so it runs after the streams' own
// cleanups (LIFO) cancel their requests; a plain defer would deadlock.
func (e *env) sseServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(e.h)
	t.Cleanup(ts.Close)
	return ts
}

func evAt(id int64, typ string, at time.Time) store.Event {
	return store.Event{ID: id, Type: typ, Subject: "s" + typ, At: at}
}

func TestSSEHeadersAndLiveDelivery(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.SSEPollInterval = time.Hour }) // only Broadcaster wakes it
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events")
	c.until(": connected", 2*time.Second)

	h := c.resp.Header
	if h.Get("Content-Type") != "text/event-stream" || !strings.Contains(h.Get("Cache-Control"), "no-cache") ||
		h.Get("Content-Encoding") != "" || h.Get("X-Accel-Buffering") != "no" {
		t.Errorf("headers = %v", h)
	}

	// Event recorded after connect; the publish wakes the stream immediately.
	e.store.Do(func(s *fakestore.Store) {
		s.Events = append(s.Events, evAt(7, "finding_opened", e.clock.Now().Add(time.Second)))
	})
	e.bc.Publish(store.Event{})
	got := c.until("data:", 2*time.Second)
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "id: 7") || !strings.Contains(joined, "event: change") || !strings.Contains(joined, `"type":"finding_opened"`) {
		t.Errorf("frame = %q", got)
	}
}

func TestSSEPollingDeliversWithoutBroadcaster(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.Broadcaster = nil })
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events")
	c.until(": connected", 2*time.Second)
	e.store.Do(func(s *fakestore.Store) {
		s.Events = append(s.Events, evAt(1, "asset_added", e.clock.Now().Add(time.Second)))
	})
	c.until("event: change", 2*time.Second)
}

func TestSSEReplaySinceAndLastEventID(t *testing.T) {
	e := newEnv(t)
	e.store.Do(func(s *fakestore.Store) {
		s.Events = []store.Event{
			evAt(1, "asset_added", t0.Add(-48*time.Hour)),
			evAt(2, "asset_added", t0.Add(-2*time.Hour)),
			evAt(3, "asset_removed", t0.Add(-time.Hour)),
			evAt(4, "finding_opened", t0.Add(-time.Minute)),
		}
	})
	ts := e.sseServer(t)

	t.Run("no cursor means live only", func(t *testing.T) {
		c := e.stream(t, ts, "/api/v1/events")
		c.until(": connected", 2*time.Second)
		c.expectNo("event: change", 150*time.Millisecond)
	})
	t.Run("since replays newer", func(t *testing.T) {
		since := t0.Add(-90 * time.Minute).Format(time.RFC3339)
		c := e.stream(t, ts, "/api/v1/events?since="+since)
		lines := strings.Join(c.until("id: 4", 2*time.Second), "\n")
		if strings.Contains(lines, "id: 2") || !strings.Contains(lines, "id: 3") {
			t.Errorf("replay = %q", lines)
		}
	})
	t.Run("Last-Event-ID resumes after id", func(t *testing.T) {
		c := e.stream(t, ts, "/api/v1/events", "Last-Event-ID", "2")
		lines := strings.Join(c.until("id: 4", 2*time.Second), "\n")
		if strings.Contains(lines, "id: 2\n") || strings.Contains(lines, "id: 1\n") || !strings.Contains(lines, "id: 3") {
			t.Errorf("replay = %q", lines)
		}
		// exactly once: nothing repeats on later polls
		c.expectNo("id: 3", 150*time.Millisecond)
	})
	t.Run("events older than replay window are not replayed", func(t *testing.T) {
		c := e.stream(t, ts, "/api/v1/events", "Last-Event-ID", "0")
		lines := strings.Join(c.until("id: 4", 2*time.Second), "\n")
		if strings.Contains(lines, "id: 1\n") {
			t.Errorf("48h-old event replayed: %q", lines)
		}
	})
}

func TestSSEBadResumeParams(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"abc", "-5"} {
		r := e.do("GET", "/api/v1/events", "", "Last-Event-ID", v)
		if r.Code != 400 {
			t.Errorf("Last-Event-ID %q = %d", v, r.Code)
		}
	}
}

func TestSSEHeartbeat(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.SSEHeartbeat = 30 * time.Millisecond })
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events")
	c.until(": connected", 2*time.Second)
	c.until(": heartbeat", 2*time.Second)
	c.until(": heartbeat", 2*time.Second)
}

func TestSSEDeliversInOrderAndBatches(t *testing.T) {
	e := newEnv(t)
	e.store.Do(func(s *fakestore.Store) {
		for i := int64(1); i <= 1200; i++ { // spans multiple 500-row batches
			s.Events = append(s.Events, evAt(i, "asset_added", t0.Add(time.Duration(i)*time.Millisecond)))
		}
	})
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events?since="+t0.Add(-time.Hour).Format(time.RFC3339))
	prev := 0
	count := 0
	deadline := time.After(5 * time.Second)
	for count < 1200 {
		select {
		case l := <-c.lines:
			if strings.HasPrefix(l, "id: ") {
				var n int
				_, _ = fmt.Sscan(l[4:], &n)
				if n != prev+1 {
					t.Fatalf("out of order or gap: %d after %d", n, prev)
				}
				prev = n
				count++
			}
		case <-deadline:
			t.Fatalf("only %d events", count)
		}
	}
}

func TestSSEKeepsStreamOnTransientStoreError(t *testing.T) {
	e := newEnv(t)
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events")
	c.until(": connected", 2*time.Second)
	e.store.Do(func(s *fakestore.Store) { s.EventsErr = context.DeadlineExceeded })
	time.Sleep(80 * time.Millisecond)
	e.store.Do(func(s *fakestore.Store) {
		s.EventsErr = nil
		s.Events = append(s.Events, evAt(9, "asset_added", e.clock.Now().Add(time.Second)))
	})
	c.until("id: 9", 2*time.Second)
}

func TestSSEEndsWhenClientDisconnects(t *testing.T) {
	e := newEnv(t)
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events")
	c.until(": connected", 2*time.Second)
	waitFor(t, func() bool { return e.bc.Subscribers() == 1 })
	c.cancel()
	waitFor(t, func() bool { return e.bc.Subscribers() == 0 })
}

func TestServeShutsDownSSEOnContextCancel(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.ShutdownTimeout = 3 * time.Second })
	ctx, cancel := context.WithCancel(context.Background())
	ln := listen(t)
	done := make(chan error, 1)
	go func() { done <- e.srv.Serve(ctx, ln) }()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+ln.Addr().String()+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	br := bufio.NewReader(resp.Body)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.bc.Subscribers() == 1 })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down with an open SSE stream")
	}
	if e.bc.Subscribers() != 0 {
		t.Error("subscriber leaked")
	}
}

func TestListenAndServe(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.srv.ListenAndServe(ctx, "127.0.0.1:0") }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := e.srv.ListenAndServe(context.Background(), "256.0.0.1:1"); err == nil {
		t.Error("expected listen error")
	}
}
