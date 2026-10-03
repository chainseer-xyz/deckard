package storetest

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// testDerivedGCOnRemoval pins that derivation registrations die with a
// removed asset. A removed parent is never scanned again, so ReplaceDerived
// can never drop or confirm its registrations: without cleanup its derived
// children stay live (and keep being scheduled) forever, and the stale rows
// veto the orphan GC when another parent later drops the same child.
func testDerivedGCOnRemoval(t *testing.T, f Factory) {
	const check = "net.ports"

	t.Run("removing the parent removes its now-unobserved derived children", func(t *testing.T) {
		e := newEnv(t, f)
		h := e.seedHost("h.x.io", "cf", at(0))
		e.replace(h.ID, check, []store.AssetUpsert{svc("h.x.io:443", check, nil)},
			[]model.RelationInput{exposes("h.x.io", "h.x.io:443")}, at(1))

		// cf stops reporting the parent: both it and the service must go.
		d := e.snapshot("cf", nil, nil, at(2))
		if got := keysOf(d.Removed); !equalStrings(got, sorted("h.x.io", "h.x.io:443")) {
			t.Fatalf("removed = %v, want parent and derived child", got)
		}
		if a := e.asset(model.KindService, "h.x.io:443"); a.RemovedAt == nil {
			t.Fatalf("derived child still live after its only parent was removed")
		}
	})

	t.Run("a child registered by another live parent survives, and its stale row does not veto later GC", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("h1.x.io", "cf"), host("h2.x.io", "cf")}, nil, at(0))
		h1 := e.asset(model.KindHostname, "h1.x.io")
		h2 := e.asset(model.KindHostname, "h2.x.io")
		shared := []store.AssetUpsert{svc("10.0.0.9:443", check, nil)}
		e.replace(h1.ID, check, shared, nil, at(1))
		e.replace(h2.ID, check, shared, nil, at(1))

		// h1 goes away: the child is still observed by h2 and must survive.
		if d := e.snapshot("cf", []store.AssetUpsert{host("h2.x.io", "cf")}, nil, at(2)); !equalStrings(keysOf(d.Removed), []string{"h1.x.io"}) {
			t.Fatalf("removed = %v, want only h1.x.io", keysOf(d.Removed))
		}
		if a := e.asset(model.KindService, "10.0.0.9:443"); a.RemovedAt != nil {
			t.Fatalf("child removed although h2 still observes it")
		}

		// h2 stops observing it: h1's long-dead registration must not keep it alive.
		d := e.replace(h2.ID, check, nil, nil, at(3))
		if !equalStrings(keysOf(d.Removed), []string{"10.0.0.9:443"}) {
			t.Fatalf("removed = %v, want the orphaned child", keysOf(d.Removed))
		}
	})

	t.Run("a scan finishing after its parent was removed does not revive its children", func(t *testing.T) {
		e := newEnv(t, f)
		h := e.seedHost("h.x.io", "cf", at(0))
		children := []store.AssetUpsert{svc("h.x.io:443", check, nil)}
		e.replace(h.ID, check, children, []model.RelationInput{exposes("h.x.io", "h.x.io:443")}, at(1))
		e.snapshot("cf", nil, nil, at(2)) // removes the parent and its child

		// A scan of the parent that started before the removal lands now.
		d := e.replace(h.ID, check, children, []model.RelationInput{exposes("h.x.io", "h.x.io:443")}, at(3))
		if len(d.Added)+len(d.Revived)+len(d.Changed) != 0 {
			t.Fatalf("stale scan of a removed parent changed inventory: %+v", d)
		}
		if a := e.asset(model.KindService, "h.x.io:443"); a.RemovedAt == nil {
			t.Fatalf("derived child revived by a stale scan of its removed parent; nothing will ever remove it again")
		}
	})

	t.Run("removal cascades down derivation chains", func(t *testing.T) {
		e := newEnv(t, f)
		h := e.seedHost("h.x.io", "cf", at(0))
		e.replace(h.ID, check, []store.AssetUpsert{svc("h.x.io:443", check, nil)}, nil, at(1))
		s := e.asset(model.KindService, "h.x.io:443")
		e.replace(s.ID, "net.services", []store.AssetUpsert{
			au(model.KindHostname, "alt.x.io", "net.services", model.ScopeOwned, nil),
		}, nil, at(2))

		d := e.snapshot("cf", nil, nil, at(3))
		if got := keysOf(d.Removed); !equalStrings(got, sorted("alt.x.io", "h.x.io", "h.x.io:443")) {
			t.Fatalf("removed = %v, want the whole chain", got)
		}
	})
}
