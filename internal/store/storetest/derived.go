package storetest

import (
	"reflect"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func svc(key, origin string, attrs map[string]any) store.AssetUpsert {
	return au(model.KindService, key, origin, model.ScopeOwned, attrs)
}

// testOwnershipRules pins who may own, update, revive and remove an asset
// (review items C2 and C5).
func testOwnershipRules(t *testing.T, f Factory) {
	t.Run("IsDerivedSource", func(t *testing.T) {
		for src, want := range map[string]bool{
			"check:dns": true, "net.ports": true, "expansion:ct": true, "discovered": true, "": true,
			"cf": false, "route53": false, "kubernetes": false, "static": false, "aws": false,
		} {
			if got := store.IsDerivedSource(src); got != want {
				t.Errorf("IsDerivedSource(%q) = %v, want %v", src, got, want)
			}
		}
	})

	t.Run("a source snapshot claims a derived asset", func(t *testing.T) {
		e := newEnv(t, f)
		e.discover([]store.AssetUpsert{host("x.x.io", "check:dns")}, nil, at(0))
		cf := au(model.KindHostname, "x.x.io", "cf", model.ScopeOwned, map[string]any{"proxied": true})
		d := e.snapshot("cf", []store.AssetUpsert{cf}, nil, at(1))
		if len(d.Changed) != 1 || len(d.Added) != 0 {
			t.Fatalf("claim diff = %+v", d)
		}
		a := e.asset(model.KindHostname, "x.x.io")
		if a.Source != "cf" || a.Attrs["proxied"] != true {
			t.Fatalf("after claim: %+v", a)
		}
		// From then on cf's snapshot may remove it.
		if d := e.snapshot("cf", nil, nil, at(2)); len(d.Removed) != 1 {
			t.Errorf("claimed asset not removed by owner snapshot: %+v", d)
		}
	})

	t.Run("a derived origin never takes ownership of a source-owned asset", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{au(model.KindHostname, "x.x.io", "cf", model.ScopeOwned, map[string]any{"a": "1"})}, nil, at(0))
		d := e.discover([]store.AssetUpsert{au(model.KindHostname, "x.x.io", "check:dns", model.ScopeOwned, map[string]any{"z": "9", "a": "2"})}, nil, at(1))
		if !d.Empty() {
			t.Errorf("diff = %+v", d)
		}
		a := e.asset(model.KindHostname, "x.x.io")
		if a.Source != "cf" || !reflect.DeepEqual(a.Attrs, map[string]any{"a": "1"}) || !a.LastSeen.Equal(at(1)) {
			t.Errorf("asset = %+v", a)
		}
	})

	t.Run("AddDiscovered never revives a source-removed asset", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("x.x.io", "cf")}, nil, at(0))
		e.snapshot("cf", nil, nil, at(1))
		d := e.discover([]store.AssetUpsert{host("x.x.io", "check:dns")}, nil, at(2))
		if len(d.Revived) != 0 || len(d.Added) != 0 || d.Ignored != 1 {
			t.Errorf("diff = %+v, want one ignored", d)
		}
		a := e.asset(model.KindHostname, "x.x.io")
		if a.RemovedAt == nil || a.Source != "cf" {
			t.Errorf("asset = %+v", a)
		}
		// Only the owning source's snapshot revives it, and it stays cf's.
		if d := e.snapshot("cf", []store.AssetUpsert{host("x.x.io", "cf")}, nil, at(3)); len(d.Revived) != 1 {
			t.Errorf("snapshot revive = %+v", d)
		}
		if a := e.asset(model.KindHostname, "x.x.io"); a.RemovedAt != nil || a.Source != "cf" {
			t.Errorf("after revive = %+v", a)
		}
	})

	t.Run("two sources reporting one asset", func(t *testing.T) {
		e := newEnv(t, f)
		cf := au(model.KindHostname, "x.x.io", "cf", model.ScopeOwned, map[string]any{"from": "cf"})
		r53 := au(model.KindHostname, "x.x.io", "r53", model.ScopeOwned, map[string]any{"from": "r53"})
		e.snapshot("cf", []store.AssetUpsert{cf}, nil, at(0))
		// The first owner keeps canonical metadata; provenance gains a reporter.
		if d := e.snapshot("r53", []store.AssetUpsert{r53}, nil, at(1)); len(d.Changed) != 1 {
			t.Errorf("second source diff = %+v", d)
		}
		if d := e.snapshot("cf", []store.AssetUpsert{cf}, nil, at(2)); !d.Empty() {
			t.Errorf("owner resync diff = %+v", d)
		}
		a := e.asset(model.KindHostname, "x.x.io")
		if a.Source != "cf" || a.Attrs["from"] != "cf" {
			t.Fatalf("asset = %+v", a)
		}
		// cf stops reporting; r53 still does: the asset stays and r53 takes over.
		if d := e.snapshot("cf", nil, nil, at(3)); len(d.Removed) != 0 {
			t.Fatalf("removed while another source still reports it: %+v", d)
		}
		if a := e.asset(model.KindHostname, "x.x.io"); a.RemovedAt != nil || a.Source != "r53" {
			t.Fatalf("after cf stops: %+v", a)
		}
		// r53 resyncs (now owner: attrs refresh), then stops reporting: removed.
		e.snapshot("r53", []store.AssetUpsert{r53}, nil, at(4))
		if a := e.asset(model.KindHostname, "x.x.io"); a.Attrs["from"] != "r53" {
			t.Errorf("new owner attrs = %v", a.Attrs)
		}
		if d := e.snapshot("r53", nil, nil, at(5)); !equalStrings(keysOf(d.Removed), []string{"x.x.io"}) {
			t.Errorf("last reporter gone: %+v", d)
		}
	})

	t.Run("non-owner source stops reporting, owner keeps the asset", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("x.x.io", "cf")}, nil, at(0))
		e.snapshot("r53", []store.AssetUpsert{host("x.x.io", "r53")}, nil, at(1))
		if d := e.snapshot("r53", nil, nil, at(2)); len(d.Removed) != 0 {
			t.Errorf("removed: %+v", d)
		}
		if d := e.snapshot("cf", []store.AssetUpsert{host("x.x.io", "cf")}, nil, at(3)); !d.Empty() {
			t.Errorf("diff = %+v", d)
		}
		if d := e.snapshot("cf", nil, nil, at(4)); len(d.Removed) != 1 {
			t.Errorf("owner removal: %+v", d)
		}
	})
}

// testDerivedAttrs pins per-key attr merging for derived assets and
// owner-only replacement for source-owned assets (review item C5).
func testDerivedAttrs(t *testing.T, f Factory) {
	t.Run("derived origins merge attrs per key", func(t *testing.T) {
		e := newEnv(t, f)
		e.discover([]store.AssetUpsert{svc("h:443", "net.ports", map[string]any{"port": "443", "state": "open"})}, nil, at(0))
		d := e.discover([]store.AssetUpsert{svc("h:443", "net.services", map[string]any{"tls": true, "product": "nginx"})}, nil, at(1))
		if len(d.Changed) != 1 {
			t.Fatalf("services diff = %+v", d)
		}
		want := map[string]any{"port": "443", "state": "open", "tls": true, "product": "nginx"}
		if a := e.asset(model.KindService, "h:443"); !reflect.DeepEqual(a.Attrs, want) || a.Source != "net.ports" {
			t.Fatalf("after services: %+v", a)
		}
		// net.ports re-runs with new values for its own keys: tls/product survive.
		d = e.discover([]store.AssetUpsert{svc("h:443", "net.ports", map[string]any{"port": "443", "state": "filtered"})}, nil, at(2))
		if len(d.Changed) != 1 {
			t.Errorf("ports rerun diff = %+v", d)
		}
		want["state"] = "filtered"
		if a := e.asset(model.KindService, "h:443"); !reflect.DeepEqual(a.Attrs, want) {
			t.Errorf("after ports rerun: %+v", a.Attrs)
		}
		// An identical rerun is a no-op.
		if d := e.discover([]store.AssetUpsert{svc("h:443", "net.ports", map[string]any{"port": "443", "state": "filtered"})}, nil, at(3)); !d.Empty() {
			t.Errorf("identical rerun diff = %+v", d)
		}
		// Nil attrs from a writer erase nothing.
		if d := e.discover([]store.AssetUpsert{svc("h:443", "net.ports", nil)}, nil, at(4)); !d.Empty() {
			t.Errorf("nil attrs diff = %+v", d)
		}
		if a := e.asset(model.KindService, "h:443"); !reflect.DeepEqual(a.Attrs, want) {
			t.Errorf("after nil attrs: %+v", a.Attrs)
		}
	})

	t.Run("source-owned assets keep owner-only replace semantics", func(t *testing.T) {
		e := newEnv(t, f)
		mk := func(attrs map[string]any) store.AssetUpsert {
			return au(model.KindHostname, "x.x.io", "cf", model.ScopeOwned, attrs)
		}
		e.snapshot("cf", []store.AssetUpsert{mk(map[string]any{"a": "1", "b": "2"})}, nil, at(0))
		e.discover([]store.AssetUpsert{au(model.KindHostname, "x.x.io", "net.services", model.ScopeOwned, map[string]any{"tls": true})}, nil, at(1))
		if a := e.asset(model.KindHostname, "x.x.io"); !reflect.DeepEqual(a.Attrs, map[string]any{"a": "1", "b": "2"}) {
			t.Errorf("derived write leaked into source asset: %v", a.Attrs)
		}
		e.snapshot("cf", []store.AssetUpsert{mk(map[string]any{"a": "1"})}, nil, at(2))
		if a := e.asset(model.KindHostname, "x.x.io"); !reflect.DeepEqual(a.Attrs, map[string]any{"a": "1"}) {
			t.Errorf("owner replace: %v", a.Attrs)
		}
	})
}
