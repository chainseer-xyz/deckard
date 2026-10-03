package scope

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

type refusalCount struct {
	mu sync.Mutex
	n  map[string]int // tier|class|reason
}

func (c *refusalCount) observe(tier, class, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n[tier+"|"+class+"|"+reason]++
}

func (c *refusalCount) get(k string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[k]
}

// levels returns the level of every "scope refusal" line, in order.
func levels(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r logRec
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if r.Msg == "scope refusal" {
			out = append(out, r.Level)
		}
	}
	return out
}

func throttleGuard(t *testing.T, buf *bytes.Buffer, res *fakeResolver, cnt *refusalCount, now *time.Time) *Guard {
	t.Helper()
	lg := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g, err := NewGuard(config.ScopeConfig{Exclude: []string{"secret.example.com"}},
		WithResolver(res), WithDialer(&recordingDialer{}), WithLogger(lg), WithRefusalObserver(cnt.observe))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	g.throttle.now = func() time.Time { return *now }
	return g
}

// Expected refusals (an owned name on a CDN edge, refused for the active
// tier) log WARN once per (target, reason) per hour and DEBUG in between;
// every one of them is counted.
func TestExpectedRefusalsWarnHourlyAndAreCounted(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cnt := &refusalCount{n: map[string]int{}}
	res := newFakeResolver(map[string][][]string{
		"app.example.com":   {{"104.16.1.1"}},
		"other.example.com": {{"104.16.1.1"}},
		"int.example.com":   {{"10.1.2.3"}}, // split-horizon private answer: routine
	})
	g := throttleGuard(t, &buf, res, cnt, &now)
	d := g.Dialer(model.TierActive, model.ScopeOwned, nil)
	dial := func(addr string) {
		t.Helper()
		if _, err := d.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrOutOfScope) {
			t.Fatalf("%s: %v", addr, err)
		}
	}

	for i := 0; i < 5; i++ {
		dial("app.example.com:443")
		now = now.Add(time.Minute)
	}
	dial("other.example.com:443") // a different target warns on its own
	now = now.Add(time.Hour)
	dial("app.example.com:443") // an hour later it warns again

	want := []string{"WARN", "DEBUG", "DEBUG", "DEBUG", "DEBUG", "WARN", "WARN"}
	if got := levels(t, &buf); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("levels = %v, want %v", got, want)
	}
	if n := cnt.get("active|shared|tier requires an owned destination IP"); n != 7 {
		t.Fatalf("counted %d refusals, want 7 (DEBUG ones included): %v", n, cnt.n)
	}

	buf.Reset()
	for i := 0; i < 3; i++ {
		dial("int.example.com:443")
	}
	if got := levels(t, &buf); strings.Join(got, ",") != "WARN,DEBUG,DEBUG" {
		t.Fatalf("private destination levels = %v, want throttled like any routine refusal", got)
	}
	if n := cnt.get("active|external|private destination is not owned"); n != 3 {
		t.Fatalf("private refusals counted %d: %v", n, cnt.n)
	}
}

// Refusals that indicate a genuine anomaly log WARN every single time.
func TestAnomalousRefusalsAlwaysWarn(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver(map[string][][]string{
		"loop.example.com": {{"127.0.0.1"}},
		"meta.example.com": {{"169.254.169.254"}},
		"junk.example.com": {{"not-an-ip"}},
	})
	cases := []struct {
		name string
		do   func(g *Guard) error
	}{
		{"owned name resolving to loopback", func(g *Guard) error {
			_, err := g.Dialer(model.TierActive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "loop.example.com:443")
			return err
		}},
		{"owned name resolving to metadata", func(g *Guard) error {
			_, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "meta.example.com:80")
			return err
		}},
		{"metadata IP literal", func(g *Guard) error {
			_, err := g.Dialer(model.TierActive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "169.254.169.254:80")
			return err
		}},
		{"excluded name", func(g *Guard) error {
			_, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "secret.example.com:443")
			return err
		}},
		{"excluded name lookup", func(g *Guard) error {
			_, err := g.Resolver(model.TierPassive, model.ScopeOwned, nil).LookupHost(context.Background(), "secret.example.com")
			return err
		}},
		{"unparseable resolver answer", func(g *Guard) error {
			_, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "junk.example.com:443")
			return err
		}},
		{"unsupported network", func(g *Guard) error {
			_, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "unix", "app.example.com:443")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			cnt := &refusalCount{n: map[string]int{}}
			g := throttleGuard(t, &buf, res, cnt, &now)
			for i := 0; i < 4; i++ {
				if err := tc.do(g); !errors.Is(err, ErrOutOfScope) {
					t.Fatalf("attempt %d: want a refusal, got %v", i, err)
				}
			}
			got := levels(t, &buf)
			if len(got) != 4 || strings.Join(got, ",") != "WARN,WARN,WARN,WARN" {
				t.Fatalf("levels = %v, want WARN every time", got)
			}
			total := 0
			for _, n := range cnt.n {
				total += n
			}
			if total != 4 {
				t.Fatalf("counted %d, want 4: %v", total, cnt.n)
			}
		})
	}
}

// Metric reasons are fixed strings: nothing from the target or the resolver
// answer leaks into the label.
func TestRefusalReasonsAreBounded(t *testing.T) {
	var buf bytes.Buffer
	now := time.Now()
	cnt := &refusalCount{n: map[string]int{}}
	res := newFakeResolver(map[string][][]string{"junk.example.com": {{"not-an-ip-1234"}}})
	g := throttleGuard(t, &buf, res, cnt, &now)
	_, _ = g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "junk.example.com:443")
	_, _ = g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "udp9", "junk.example.com:443")
	for k := range cnt.n {
		if strings.Contains(k, "1234") || strings.Contains(k, "udp9") || strings.Contains(k, "junk") {
			t.Errorf("label %q carries request data", k)
		}
	}
}

func TestRefusalThrottleIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	th := refusalThrottle{now: func() time.Time { return now }}
	for i := 0; i < maxThrottled+50; i++ {
		if !th.warn(fmt.Sprintf("t%d", i), "r") {
			t.Fatalf("first refusal of target %d must warn", i)
		}
	}
	if len(th.last) > maxThrottled {
		t.Fatalf("throttle holds %d entries, bound is %d", len(th.last), maxThrottled)
	}
}
