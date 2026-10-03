package netcheck

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// A port queued behind the per-host rate limiter is not an unresponsive port:
// time spent waiting for a token must not count against the per-dial timeout.
// Otherwise every dial past the first timeout's worth of tokens fails inside
// the limiter without ever being attempted, is reported closed, and the open
// port findings on those ports resolve.
func TestPortsRateLimitedScanProbesEveryPort(t *testing.T) {
	base := &plainDialer{}
	g, err := scope.NewGuard(config.ScopeConfig{Include: []string{"127.0.0.1"}},
		scope.WithDialer(base), scope.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	// 300 ports at 100/s with a 200ms dial timeout and every dial in flight at
	// once: all but the first ~120 must wait longer than the timeout for a token.
	d := g.Dialer(model.TierActive, model.ScopeOwned, scope.NewHostLimiter(100, 100))
	cfg := map[string]any{"ports": "1-300", "concurrency": 300, "timeout": "200ms"}

	_, err = (&portsCheck{}).Run(context.Background(), check.Target{Asset: ipAsset(), Dialer: d, Config: cfg})

	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := base.calls.Load(); n != 300 {
		t.Fatalf("only %d of 300 ports were actually dialled; the rest were reported closed unprobed", n)
	}
}
