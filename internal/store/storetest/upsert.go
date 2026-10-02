package storetest

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// testUpsertSnapshot pins UpsertSnapshot: ApplySnapshot semantics without the
// removal step, for partial or suspect syncs (review item C4).
func testUpsertSnapshot(t *testing.T, f Factory) {
	t.Run("adds, changes and revives but never removes", func(t *testing.T) {
		e := newEnv(t, f)
		mk := func(k, v string) store.AssetUpsert {
			return au(model.KindHostname, k, "cf", model.ScopeOwned, map[string]any{"v": v})
		}
		e.snapshot("cf", []store.AssetUpsert{mk("a.x.io", "1"), mk("b.x.io", "1"), mk("gone.x.io", "1")}, nil, at(0))
		e.snapshot("cf", []store.AssetUpsert{mk("a.x.io", "1"), mk("b.x.io", "1")}, nil, at(1)) // gone removed

		d, err := e.s.UpsertSnapshot(e.ctx, "cf", []store.AssetUpsert{mk("a.x.io", "2"), mk("gone.x.io", "1"), mk("c.x.io", "1")}, nil, at(2))
		if err != nil {
			t.Fatal(err)
		}
		if !equalStrings(keysOf(d.Added), []string{"c.x.io"}) || !equalStrings(keysOf(d.Changed), []string{"a.x.io"}) ||
			!equalStrings(keysOf(d.Revived), []string{"gone.x.io"}) || len(d.Removed) != 0 {
			t.Fatalf("diff = %+v", d)
		}
		// b.x.io was not in the partial snapshot but stays live.
		if a := e.asset(model.KindHostname, "b.x.io"); a.RemovedAt != nil {
			t.Errorf("unseen asset removed: %+v", a)
		}
		// A later complete snapshot removes it as usual: the reporter set was
		// left intact.
		d = e.snapshot("cf", []store.AssetUpsert{mk("a.x.io", "2")}, nil, at(3))
		if !equalStrings(keysOf(d.Removed), sorted("b.x.io", "c.x.io", "gone.x.io")) {
			t.Errorf("removed = %v", keysOf(d.Removed))
		}
	})
}

func testSyncWarning(t *testing.T, f Factory) {
	e := newEnv(t, f)
	if err := e.s.RecordSync(e.ctx, store.SyncStatus{Source: "cf", Type: "cloudflare", LastRun: at(1), LastOK: at(1), Warning: "tunnels skipped"}); err != nil {
		t.Fatal(err)
	}
	got, _ := e.s.ListSyncs(e.ctx)
	if len(got) != 1 || got[0].Warning != "tunnels skipped" || got[0].Error != "" {
		t.Fatalf("syncs = %+v", got)
	}
	if err := e.s.RecordSync(e.ctx, store.SyncStatus{Source: "cf", Type: "cloudflare", LastRun: at(2), LastOK: at(2)}); err != nil {
		t.Fatal(err)
	}
	got, _ = e.s.ListSyncs(e.ctx)
	if got[0].Warning != "" {
		t.Errorf("warning not cleared by a clean run: %+v", got[0])
	}
}
