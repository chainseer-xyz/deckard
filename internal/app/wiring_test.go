package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/engine"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

func wiringApp(t *testing.T) (*App, context.Context) {
	t.Helper()
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false // hermetic: tests never reach the public dataset sources
	cfg.Database.URL = pgtest.NewURL(t)
	cfg.Scope.Include = []string{"127.0.0.1"}
	cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "static", IPs: []string{"127.0.0.1"}}}
	cfg.Nuclei.Enabled = false
	cfg.Checks = map[string]map[string]any{"net.ports": {"ports": "1"}}
	cfg.Expansion.CTLogs = false
	cfg.Server.Roles = []string{"scheduler", "worker"}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	a, err := New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return a, ctx
}

// C10c: one pool, owned by the store, shared with the job queue.
func TestAppUsesASinglePool(t *testing.T) {
	a, _ := wiringApp(t)
	if a.pool == nil || a.pool != a.st.Pool() {
		t.Fatal("engine must use the store's pool, not a second one")
	}
}

// C10b: the engine reports inventory changes; the inventory service must not
// also report them.
func TestInventoryChangesAreCountedOnce(t *testing.T) {
	a, ctx := wiringApp(t)
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := a.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range st.AssetsByKind {
		total += n
	}
	if added := inventoryChanges(t, a, "added"); total < 1 || added != float64(total) {
		t.Fatalf("inventory_changes_total{type=added} = %v for %d assets in the inventory (double counted?)", added, total)
	}
}

// C10a: scheduling.queue_workers reaches the engine.
func TestQueueWorkersFromConfig(t *testing.T) {
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false // hermetic: tests never reach the public dataset sources
	cfg.Scheduling.QueueWorkers["active"] = 9
	got := queueWorkers(cfg)
	if got[engine.QueueActive] != 9 || got[engine.QueuePassive] != 10 || got[engine.QueueExpand] != 1 ||
		got[engine.QueueSync] != 2 || got[engine.QueueIntrusive] != 1 || got[engine.QueueDefault] != 2 ||
		got[engine.QueueIntel] != 8 {
		t.Fatalf("queue workers: %v", got)
	}
}

func inventoryChanges(t *testing.T, a *App, kind string) float64 {
	t.Helper()
	fams, err := a.metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != "deckard_inventory_changes_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "type" && l.GetValue() == kind {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// Every scope refusal is counted in deckard_scope_refusals_total, whatever
// level it was logged at.
func TestScopeRefusalsAreCounted(t *testing.T) {
	a, ctx := wiringApp(t)
	d := a.guard.Dialer(model.TierActive, model.ScopeOwned, nil)
	for i := 0; i < 3; i++ {
		if _, err := d.DialContext(ctx, "tcp", "169.254.169.254:80"); !errors.Is(err, scope.ErrOutOfScope) {
			t.Fatalf("metadata dial not refused: %v", err)
		}
	}
	mfs, err := a.metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, mf := range mfs {
		if mf.GetName() == "deckard_scope_refusals_total" {
			for _, m := range mf.GetMetric() {
				total += m.GetCounter().GetValue()
			}
		}
	}
	if total != 3 {
		t.Fatalf("deckard_scope_refusals_total = %v, want 3", total)
	}
}
