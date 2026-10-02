package api_test

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// headerAuth identifies the caller by the X-User header (tests only).
type headerAuth struct{}

func (headerAuth) Mode() string { return "token" }
func (headerAuth) Authenticate(r *http.Request) (*auth.Identity, error) {
	u := r.Header.Get("X-User")
	if u == "" {
		return nil, auth.ErrUnauthenticated
	}
	return &auth.Identity{Subject: u, Method: auth.MethodToken}, nil
}

func TestSSEGlobalStreamCap(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.MaxSSEStreams = 3; d.MaxSSEStreamsPerIdentity = 10 })
	ts := e.sseServer(t)
	var open []*sseClient
	for i := 0; i < 3; i++ {
		c := e.stream(t, ts, "/api/v1/events")
		if c.resp.StatusCode != 200 {
			t.Fatalf("stream %d = %d", i, c.resp.StatusCode)
		}
		c.until(": connected", 2*time.Second)
		open = append(open, c)
	}
	over := e.stream(t, ts, "/api/v1/events")
	if over.resp.StatusCode != 429 {
		t.Fatalf("N+1th stream = %d, want 429", over.resp.StatusCode)
	}
	if over.resp.Header.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	var rd io.Reader = over.resp.Body
	if over.resp.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(over.resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		rd = zr
	}
	b, _ := io.ReadAll(rd)
	if err := json.Unmarshal(b, &body); err != nil || body.Error.Code != "too_many_streams" {
		t.Errorf("body = %q (%v)", b, err)
	}

	// Closing one frees a slot.
	open[0].cancel()
	waitFor(t, func() bool { return e.bc.Subscribers() == 2 })
	var again *sseClient
	waitFor(t, func() bool {
		again = e.stream(t, ts, "/api/v1/events")
		return again.resp.StatusCode == 200
	})
	again.until(": connected", 2*time.Second)
}

func TestSSEPerIdentityCap(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Authenticator = headerAuth{}
		d.MaxSSEStreams = 100
		d.MaxSSEStreamsPerIdentity = 2
	})
	ts := e.sseServer(t)
	open := func(user string) *sseClient { return e.stream(t, ts, "/api/v1/events", "X-User", user) }
	a1, a2 := open("alice"), open("alice")
	if a1.resp.StatusCode != 200 || a2.resp.StatusCode != 200 {
		t.Fatal("first two streams must be admitted")
	}
	if a3 := open("alice"); a3.resp.StatusCode != 429 {
		t.Fatalf("third stream for alice = %d, want 429", a3.resp.StatusCode)
	}
	if b1 := open("bob"); b1.resp.StatusCode != 200 {
		t.Fatalf("bob blocked by alice's streams: %d", b1.resp.StatusCode)
	}
	a1.until(": connected", 2*time.Second)
	a1.cancel()
	waitFor(t, func() bool { return open("alice").resp.StatusCode == 200 })
}

func TestSSERejectedRequestsDoNotLeakSlots(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.MaxSSEStreams = 1 })
	for i := 0; i < 5; i++ { // bad Last-Event-ID is rejected before a slot is taken
		if r := e.do("GET", "/api/v1/events", "", "Last-Event-ID", "abc"); r.Code != 400 {
			t.Fatalf("= %d", r.Code)
		}
	}
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events")
	if c.resp.StatusCode != 200 {
		t.Fatalf("slot leaked: %d", c.resp.StatusCode)
	}
}

func TestSSENoGoroutineLeakAfterManyStreams(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.MaxSSEStreams = 5 })
	ts := e.sseServer(t)
	http.DefaultClient.CloseIdleConnections()
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		c := e.stream(t, ts, "/api/v1/events")
		if c.resp.StatusCode == 200 {
			c.until(": connected", 2*time.Second)
		}
		c.cancel()
		<-c.done
	}
	waitFor(t, func() bool { return e.bc.Subscribers() == 0 })
	http.DefaultClient.CloseIdleConnections()
	waitFor(t, func() bool { return runtime.NumGoroutine() <= before+3 })
}

func TestSSEReplaySinceIsClampedToReplayWindow(t *testing.T) {
	e := newEnv(t)
	e.store.Do(func(s *fakestore.Store) {
		s.Events = []store.Event{
			evAt(1, "asset_added", t0.Add(-48*time.Hour)),
			evAt(2, "asset_added", t0.Add(-time.Hour)),
		}
	})
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events?since=2000-01-01T00:00:00Z")
	lines := strings.Join(c.until("id: 2", 2*time.Second), "\n")
	if strings.Contains(lines, "id: 1\n") {
		t.Errorf("since older than the replay window was honoured: %q", lines)
	}
}

func TestSSEWakeFloodIsCoalesced(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.SSEPollInterval = time.Hour })
	ts := e.sseServer(t)
	c := e.stream(t, ts, "/api/v1/events")
	c.until(": connected", 2*time.Second)
	time.Sleep(300 * time.Millisecond)
	before := e.store.EventsCalls()
	for i := 0; i < 200; i++ {
		e.bc.Publish(store.Event{})
	}
	time.Sleep(100 * time.Millisecond)
	if n := e.store.EventsCalls() - before; n > 3 {
		t.Errorf("200 wake-ups caused %d store queries", n)
	}
}
