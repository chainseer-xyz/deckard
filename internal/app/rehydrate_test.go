package app_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/app"
	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// recCheck is a passive check on IP assets that records what it ran on. It
// never touches the network.
type recCheck struct {
	name string
	mu   sync.Mutex
	keys []string
}

func (c *recCheck) Name() string               { return c.name }
func (c *recCheck) Tier() model.Tier           { return model.TierPassive }
func (c *recCheck) Applies(a model.Asset) bool { return a.Kind == model.KindIP }
func (c *recCheck) Run(_ context.Context, t check.Target) (*check.Result, error) {
	c.mu.Lock()
	c.keys = append(c.keys, t.Asset.Key)
	c.mu.Unlock()
	return &check.Result{}, nil
}
func (c *recCheck) ran() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.keys, ",")
}

// TestRestartRehydratesClassifier (C11): ownership declared by a source (a
// static IP) lives in the database. A new process that did not sync yet must
// still scan that asset, and must still never scan one that is not owned.
func TestRestartRehydratesClassifier(t *testing.T) {
	const ownedIP, strangerIP = "192.0.2.10", "198.51.100.7"
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Process 1: sync the static source and scan once.
	cfg1 := testConfig(t, "", 1)
	cfg1.Scope.Include = nil
	cfg1.Sources = cfg1.Sources[:1]
	cfg1.Sources[0].IPs = []string{ownedIP}
	rec1 := &recCheck{name: "test.rec1"}
	a1 := newApp(t, ctx, cfg1, app.Options{ExtraChecks: []check.Check{rec1}})
	if err := a1.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a1.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce 1: %v", err)
	}
	if rec1.ran() != ownedIP {
		t.Fatalf("process 1 scanned %q, want only %s", rec1.ran(), ownedIP)
	}

	// A non-owned asset sitting in the inventory (e.g. a shared edge IP some
	// record points at).
	db := openDB(t, ctx, cfg1.Database.URL)
	if _, err := db.ApplySnapshot(ctx, "other", []store.AssetUpsert{{
		AssetInput: model.AssetInput{Kind: model.KindIP, Key: strangerIP, Source: "other"},
		Scope:      model.ScopeExternal,
	}}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Process 2: same database, NO sources configured, so nothing syncs. A
	// fresh check name makes every asset due.
	cfg2 := testConfig(t, cfg1.Database.URL, 1)
	cfg2.Scope.Include = nil
	cfg2.Sources = nil
	rec2 := &recCheck{name: "test.rec2"}
	a2 := newApp(t, ctx, cfg2, app.Options{ExtraChecks: []check.Check{rec2}})
	if err := a2.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a2.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce 2: %v", err)
	}
	if got := rec2.ran(); got != ownedIP {
		t.Fatalf("after restart (no sync) the owned asset must still be scanned and the stranger never: ran on %q", got)
	}
}
