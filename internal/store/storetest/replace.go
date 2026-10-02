package storetest

import (
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func (e *env) replace(parent int64, origin string, assets []store.AssetUpsert, rels []model.RelationInput, now time.Time) store.InventoryDiff {
	e.t.Helper()
	d, err := e.s.ReplaceDerived(e.ctx, parent, origin, assets, rels, now)
	if err != nil {
		e.t.Fatalf("ReplaceDerived(%s): %v", origin, err)
	}
	return d
}

func exposes(host, service string) model.RelationInput {
	return model.RelationInput{FromKind: model.KindHostname, FromKey: host, ToKind: model.KindService, ToKey: service, Type: model.RelExposes}
}

func edgeKeys(e *env, id int64) []string {
	e.t.Helper()
	es, err := e.s.Edges(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, ed := range es {
		out = append(out, ed.Other.Key)
	}
	sort.Strings(out)
	return out
}

// testReplaceDerived pins garbage collection of derived assets and their
// relations (review item C3).
func testReplaceDerived(t *testing.T, f Factory) {
	const check = "net.ports"
	setup := func() (*env, *model.Asset) {
		e := newEnv(t, f)
		return e, e.seedHost("h.x.io", "cf", at(0))
	}
	two := []store.AssetUpsert{svc("h.x.io:80", check, nil), svc("h.x.io:443", check, nil)}
	twoRels := []model.RelationInput{exposes("h.x.io", "h.x.io:80"), exposes("h.x.io", "h.x.io:443")}

	t.Run("unobserved children are removed with their relations, then revive", func(t *testing.T) {
		e, h := setup()
		d := e.replace(h.ID, check, two, twoRels, at(1))
		if len(d.Added) != 2 || len(d.Removed) != 0 {
			t.Fatalf("first diff = %+v", d)
		}
		if got := edgeKeys(e, h.ID); !equalStrings(got, sorted("h.x.io:80", "h.x.io:443")) {
			t.Fatalf("edges = %v", got)
		}
		// Identical rerun: nothing changes.
		if d := e.replace(h.ID, check, two, twoRels, at(2)); !d.Empty() {
			t.Errorf("rerun diff = %+v", d)
		}
		// Port 80 closed.
		d = e.replace(h.ID, check, two[1:], twoRels[1:], at(3))
		if !equalStrings(keysOf(d.Removed), []string{"h.x.io:80"}) {
			t.Fatalf("removed = %v", keysOf(d.Removed))
		}
		gone := e.asset(model.KindService, "h.x.io:80")
		if gone.RemovedAt == nil {
			t.Errorf("closed port not removed: %+v", gone)
		}
		if got := edgeKeys(e, h.ID); !equalStrings(got, []string{"h.x.io:443"}) {
			t.Errorf("edges after GC = %v", got)
		}
		if got := edgeKeys(e, gone.ID); len(got) != 0 {
			t.Errorf("removed child keeps edges %v", got)
		}
		// Reopened: revived, relation restored.
		d = e.replace(h.ID, check, two, twoRels, at(4))
		if !equalStrings(keysOf(d.Revived), []string{"h.x.io:80"}) {
			t.Errorf("revived = %v", keysOf(d.Revived))
		}
		if got := edgeKeys(e, h.ID); len(got) != 2 {
			t.Errorf("edges after revive = %v", got)
		}
		// Empty observation removes everything from this (parent, origin).
		if d := e.replace(h.ID, check, nil, nil, at(5)); len(d.Removed) != 2 {
			t.Errorf("empty replace removed = %v", keysOf(d.Removed))
		}
	})

	t.Run("removal resolves findings of the removed child", func(t *testing.T) {
		e, h := setup()
		e.replace(h.ID, check, two, twoRels, at(1))
		c := e.asset(model.KindService, "h.x.io:80")
		e.reconcile(c.ID, "tls.cert", []model.FindingInput{fi("tls.cert", "k", model.SeverityHigh)}, 1, at(2))
		e.replace(h.ID, check, two[1:], twoRels[1:], at(3))
		if fs, _, _ := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: c.ID}); len(fs) != 1 || fs[0].Status != model.StatusResolved {
			t.Errorf("findings = %+v", fs)
		}
	})

	t.Run("other origins and other parents keep a child alive", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("h1.x.io", "cf"), host("h2.x.io", "cf")}, nil, at(0))
		h1, h2 := e.asset(model.KindHostname, "h1.x.io"), e.asset(model.KindHostname, "h2.x.io")
		e.replace(h1.ID, "net.ports", []store.AssetUpsert{svc("shared:80", "net.ports", map[string]any{"port": "80"})}, nil, at(1))
		e.replace(h2.ID, "net.ports", []store.AssetUpsert{svc("shared:80", "net.ports", nil)}, nil, at(1))
		e.replace(h1.ID, "net.services", []store.AssetUpsert{svc("shared:80", "net.services", map[string]any{"tls": false})}, nil, at(2))
		if d := e.replace(h1.ID, "net.ports", nil, nil, at(3)); len(d.Removed) != 0 {
			t.Fatalf("removed while other parent/origin observes it: %v", keysOf(d.Removed))
		}
		if d := e.replace(h2.ID, "net.ports", nil, nil, at(4)); len(d.Removed) != 0 {
			t.Fatalf("removed while net.services observes it: %v", keysOf(d.Removed))
		}
		a := e.asset(model.KindService, "shared:80")
		if a.Attrs["port"] != "80" || a.Attrs["tls"] != false {
			t.Errorf("attrs = %v", a.Attrs)
		}
		if d := e.replace(h1.ID, "net.services", nil, nil, at(5)); len(d.Removed) != 1 {
			t.Errorf("last observer gone: removed = %v", keysOf(d.Removed))
		}
		// Revival starts from fresh attrs.
		e.replace(h1.ID, "net.ports", []store.AssetUpsert{svc("shared:80", "net.ports", map[string]any{"port": "80"})}, nil, at(6))
		if a := e.asset(model.KindService, "shared:80"); a.RemovedAt != nil || !reflect.DeepEqual(a.Attrs, map[string]any{"port": "80"}) {
			t.Errorf("revived = %+v", a)
		}
	})

	t.Run("a source-claimed child is never garbage-collected", func(t *testing.T) {
		e, h := setup()
		e.replace(h.ID, check, two, twoRels, at(1))
		e.snapshot("k8s", []store.AssetUpsert{au(model.KindService, "h.x.io:80", "k8s", model.ScopeOwned, nil)}, nil, at(2))
		if d := e.replace(h.ID, check, two[1:], twoRels[1:], at(3)); len(d.Removed) != 0 {
			t.Errorf("removed claimed asset: %v", keysOf(d.Removed))
		}
		if a := e.asset(model.KindService, "h.x.io:80"); a.RemovedAt != nil || a.Source != "k8s" {
			t.Errorf("claimed asset = %+v", a)
		}
	})

	t.Run("source-removed assets are ignored and counted", func(t *testing.T) {
		e, h := setup()
		e.snapshot("k8s", []store.AssetUpsert{au(model.KindService, "h.x.io:80", "k8s", model.ScopeOwned, nil)}, nil, at(1))
		e.snapshot("k8s", nil, nil, at(2))
		d := e.replace(h.ID, check, two[:1], nil, at(3))
		if d.Ignored != 1 || len(d.Revived) != 0 {
			t.Errorf("diff = %+v", d)
		}
	})

	t.Run("unknown parent is not found", func(t *testing.T) {
		e := newEnv(t, f)
		if _, err := e.s.ReplaceDerived(e.ctx, 9999, check, nil, nil, at(0)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("PruneRelations drops edges of long-removed assets", func(t *testing.T) {
		e := newEnv(t, f)
		ipa := func(k string) store.AssetUpsert { return au(model.KindIP, k, "cf", model.ScopeOwned, nil) }
		rel := func(to string) model.RelationInput {
			return model.RelationInput{FromKind: model.KindHostname, FromKey: "a.x.io", ToKind: model.KindIP, ToKey: to, Type: model.RelResolvesTo}
		}
		e.snapshot("cf", []store.AssetUpsert{host("a.x.io", "cf"), ipa("1.1.1.1"), ipa("2.2.2.2")},
			[]model.RelationInput{rel("1.1.1.1"), rel("2.2.2.2")}, at(0))
		e.snapshot("cf", []store.AssetUpsert{host("a.x.io", "cf"), ipa("2.2.2.2")}, nil, at(5))
		a := e.asset(model.KindHostname, "a.x.io")
		if n, err := e.s.PruneRelations(e.ctx, at(4)); err != nil || n != 0 {
			t.Fatalf("early prune = %d, %v", n, err)
		}
		if got := edgeKeys(e, a.ID); len(got) != 2 {
			t.Fatalf("edges = %v", got)
		}
		if n, err := e.s.PruneRelations(e.ctx, at(6)); err != nil || n != 1 {
			t.Fatalf("prune = %d, %v", n, err)
		}
		if got := edgeKeys(e, a.ID); !equalStrings(got, []string{"2.2.2.2"}) {
			t.Errorf("edges after prune = %v", got)
		}
	})
}
