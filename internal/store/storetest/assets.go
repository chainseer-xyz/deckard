package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func testLifecycle(t *testing.T, f Factory) {
	e := newEnv(t, f)
	if err := e.s.Ping(e.ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := e.s.Migrate(e.ctx); err != nil {
			t.Fatalf("Migrate #%d on migrated store: %v", i, err)
		}
	}
	if err := e.s.Ping(e.ctx); err != nil {
		t.Fatalf("Ping after migrate: %v", err)
	}
}

type diffWant struct{ added, changed, removed, revived []string }

type snapStep struct {
	source string
	assets []store.AssetUpsert
	now    time.Time
	want   diffWant
}

func testAssets(t *testing.T, f Factory) {
	own, shared := model.ScopeOwned, model.ScopeShared
	cf := func(key string, scope model.ScopeClass, attrs map[string]any) store.AssetUpsert {
		return au(model.KindHostname, key, "cf", scope, attrs)
	}
	cases := []struct {
		name  string
		steps []snapStep
	}{
		{"first snapshot adds everything", []snapStep{
			{"cf", []store.AssetUpsert{host("a.x.io", "cf"), host("b.x.io", "cf")}, at(0),
				diffWant{added: sorted("a.x.io", "b.x.io")}},
		}},
		{"identical resnapshot is empty", []snapStep{
			{"cf", []store.AssetUpsert{host("a.x.io", "cf")}, at(0), diffWant{added: sorted("a.x.io")}},
			{"cf", []store.AssetUpsert{host("a.x.io", "cf")}, at(1), diffWant{}},
		}},
		{"attrs change is changed", []snapStep{
			{"cf", []store.AssetUpsert{cf("a.x.io", own, map[string]any{"ip": "1.1.1.1"})}, at(0), diffWant{added: sorted("a.x.io")}},
			{"cf", []store.AssetUpsert{cf("a.x.io", own, map[string]any{"ip": "2.2.2.2"})}, at(1), diffWant{changed: sorted("a.x.io")}},
			{"cf", []store.AssetUpsert{cf("a.x.io", own, map[string]any{"ip": "2.2.2.2"})}, at(2), diffWant{}},
		}},
		{"nil and empty attrs are equal", []snapStep{
			{"cf", []store.AssetUpsert{cf("a.x.io", own, nil)}, at(0), diffWant{added: sorted("a.x.io")}},
			{"cf", []store.AssetUpsert{cf("a.x.io", own, map[string]any{})}, at(1), diffWant{}},
		}},
		{"scope change is changed", []snapStep{
			{"cf", []store.AssetUpsert{cf("a.x.io", own, nil)}, at(0), diffWant{added: sorted("a.x.io")}},
			{"cf", []store.AssetUpsert{cf("a.x.io", shared, nil)}, at(1), diffWant{changed: sorted("a.x.io")}},
		}},
		{"unseen asset is removed once", []snapStep{
			{"cf", []store.AssetUpsert{host("a.x.io", "cf"), host("b.x.io", "cf")}, at(0), diffWant{added: sorted("a.x.io", "b.x.io")}},
			{"cf", []store.AssetUpsert{host("a.x.io", "cf")}, at(1), diffWant{removed: sorted("b.x.io")}},
			{"cf", []store.AssetUpsert{host("a.x.io", "cf")}, at(2), diffWant{}},
		}},
		{"removed asset seen again is revived", []snapStep{
			{"cf", []store.AssetUpsert{host("a.x.io", "cf")}, at(0), diffWant{added: sorted("a.x.io")}},
			{"cf", nil, at(1), diffWant{removed: sorted("a.x.io")}},
			{"cf", []store.AssetUpsert{host("a.x.io", "cf")}, at(2), diffWant{revived: sorted("a.x.io")}},
			{"cf", []store.AssetUpsert{host("a.x.io", "cf")}, at(3), diffWant{}},
		}},
		{"mixed diff in one snapshot", []snapStep{
			{"cf", []store.AssetUpsert{cf("keep", own, nil), cf("chg", own, map[string]any{"v": "1"}), cf("gone", own, nil), cf("back", own, nil)}, at(0),
				diffWant{added: sorted("keep", "chg", "gone", "back")}},
			{"cf", []store.AssetUpsert{cf("keep", own, nil), cf("chg", own, map[string]any{"v": "1"}), cf("back", own, nil)}, at(1),
				diffWant{removed: sorted("gone")}},
			{"cf", []store.AssetUpsert{cf("keep", own, nil), cf("chg", own, map[string]any{"v": "2"}), cf("gone", own, nil), cf("new", own, nil)}, at(2),
				diffWant{added: sorted("new"), changed: sorted("chg"), revived: sorted("gone"), removed: sorted("back")}},
		}},
		{"duplicate inputs collapse to one asset", []snapStep{
			{"cf", []store.AssetUpsert{host("a.x.io", "cf"), host("a.x.io", "cf")}, at(0), diffWant{added: sorted("a.x.io")}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, f)
			for i, st := range tc.steps {
				d := e.snapshot(st.source, st.assets, nil, st.now)
				for _, c := range []struct {
					name      string
					got       []model.Asset
					want      []string
					removedAt bool
				}{
					{"added", d.Added, st.want.added, false},
					{"changed", d.Changed, st.want.changed, false},
					{"removed", d.Removed, st.want.removed, true},
					{"revived", d.Revived, st.want.revived, false},
				} {
					if !equalStrings(keysOf(c.got), c.want) {
						t.Errorf("step %d %s = %v, want %v", i, c.name, keysOf(c.got), c.want)
					}
					for _, a := range c.got {
						if (a.RemovedAt != nil) != c.removedAt {
							t.Errorf("step %d %s %s RemovedAt = %v", i, c.name, a.Key, a.RemovedAt)
						}
					}
				}
				if got, want := d.Empty(), len(st.want.added)+len(st.want.changed)+len(st.want.removed)+len(st.want.revived) == 0; got != want {
					t.Errorf("step %d Empty() = %v, want %v", i, got, want)
				}
			}
		})
	}

	t.Run("timestamps and persisted fields", func(t *testing.T) {
		e := newEnv(t, f)
		in := au(model.KindIP, "203.0.113.9", "cf", model.ScopeShared, map[string]any{"proxied": true, "name": "x"})
		in.Zone = "x.io"
		e.snapshot("cf", []store.AssetUpsert{in}, nil, at(0))
		e.snapshot("cf", []store.AssetUpsert{in}, nil, at(5))
		a := e.asset(model.KindIP, "203.0.113.9")
		if !a.FirstSeen.Equal(at(0)) || !a.LastSeen.Equal(at(5)) {
			t.Errorf("first/last seen = %v/%v, want %v/%v", a.FirstSeen, a.LastSeen, at(0), at(5))
		}
		if a.Source != "cf" || a.Scope != model.ScopeShared || a.Zone != "x.io" || a.RemovedAt != nil {
			t.Errorf("asset = %+v", a)
		}
		if a.Attrs["proxied"] != true || a.Attrs["name"] != "x" {
			t.Errorf("attrs = %v", a.Attrs)
		}
		e.snapshot("cf", nil, nil, at(10))
		a = e.asset(model.KindIP, "203.0.113.9")
		if a.RemovedAt == nil || !a.RemovedAt.Equal(at(10)) {
			t.Errorf("RemovedAt = %v, want %v", a.RemovedAt, at(10))
		}
		e.snapshot("cf", []store.AssetUpsert{in}, nil, at(20))
		a = e.asset(model.KindIP, "203.0.113.9")
		if a.RemovedAt != nil || !a.FirstSeen.Equal(at(0)) || !a.LastSeen.Equal(at(20)) {
			t.Errorf("after revive: %+v", a)
		}
		byID, err := e.s.GetAsset(e.ctx, a.ID)
		if err != nil || byID.Key != a.Key {
			t.Errorf("GetAsset = %v, %v", byID, err)
		}
	})

	t.Run("same key different kind are distinct", func(t *testing.T) {
		e := newEnv(t, f)
		d := e.snapshot("cf", []store.AssetUpsert{
			au(model.KindHostname, "x", "cf", model.ScopeOwned, nil),
			au(model.KindURL, "x", "cf", model.ScopeOwned, nil),
		}, nil, at(0))
		if len(d.Added) != 2 {
			t.Errorf("added = %d, want 2", len(d.Added))
		}
	})
}

func testOwnership(t *testing.T, f Factory) {
	t.Run("snapshot only removes its own source's assets", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("cf1.x.io", "cf"), host("cf2.x.io", "cf")}, nil, at(0))
		e.snapshot("r53", []store.AssetUpsert{host("r1.x.io", "r53")}, nil, at(1))
		// r53 resyncs with nothing: only r1 may go.
		d := e.snapshot("r53", nil, nil, at(2))
		if got := keysOf(d.Removed); !equalStrings(got, []string{"r1.x.io"}) {
			t.Fatalf("removed = %v, want [r1.x.io]", got)
		}
		for _, k := range []string{"cf1.x.io", "cf2.x.io"} {
			if a := e.asset(model.KindHostname, k); a.RemovedAt != nil {
				t.Errorf("%s removed by foreign snapshot", k)
			}
		}
	})

	t.Run("snapshot of one source leaves others untouched", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("cf1.x.io", "cf")}, nil, at(0))
		d := e.snapshot("r53", []store.AssetUpsert{host("r1.x.io", "r53")}, nil, at(1))
		if len(d.Removed) != 0 {
			t.Errorf("removed = %v, want none", keysOf(d.Removed))
		}
		if a := e.asset(model.KindHostname, "cf1.x.io"); a.RemovedAt != nil {
			t.Errorf("cf asset removed")
		}
	})

	t.Run("AddDiscovered never removes", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("cf1.x.io", "cf")}, nil, at(0))
		d := e.discover([]store.AssetUpsert{host("found.x.io", "discovery")}, nil, at(1))
		if got := keysOf(d.Added); !equalStrings(got, []string{"found.x.io"}) || len(d.Removed) != 0 {
			t.Fatalf("diff = %+v", d)
		}
		d = e.discover(nil, nil, at(2))
		if !d.Empty() {
			t.Errorf("empty discovery diff = %+v", d)
		}
		for _, k := range []string{"cf1.x.io", "found.x.io"} {
			if a := e.asset(model.KindHostname, k); a.RemovedAt != nil {
				t.Errorf("%s removed", k)
			}
		}
	})

	t.Run("discovered assets are not removed by another source's snapshot", func(t *testing.T) {
		e := newEnv(t, f)
		e.discover([]store.AssetUpsert{host("found.x.io", "discovery")}, nil, at(0))
		d := e.snapshot("cf", nil, nil, at(1))
		if len(d.Removed) != 0 {
			t.Errorf("removed = %v", keysOf(d.Removed))
		}
	})

	t.Run("AddDiscovered reports changed and revived", func(t *testing.T) {
		e := newEnv(t, f)
		mk := func(v string) store.AssetUpsert {
			return au(model.KindHostname, "d.x.io", "discovery", model.ScopeOwned, map[string]any{"v": v})
		}
		e.discover([]store.AssetUpsert{mk("1")}, nil, at(0))
		if d := e.discover([]store.AssetUpsert{mk("2")}, nil, at(1)); len(d.Changed) != 1 {
			t.Errorf("changed = %v", keysOf(d.Changed))
		}
		if d := e.discover([]store.AssetUpsert{mk("2")}, nil, at(2)); !d.Empty() {
			t.Errorf("unchanged rediscovery diff = %+v", d)
		}
		// Removed by its owning source's snapshot: rediscovery must not revive it.
		if d := e.snapshot("discovery", nil, nil, at(3)); len(d.Removed) != 1 {
			t.Fatalf("owner snapshot removed = %v", keysOf(d.Removed))
		}
		d := e.discover([]store.AssetUpsert{mk("2")}, nil, at(4))
		if len(d.Revived) != 0 || d.Ignored != 1 {
			t.Errorf("rediscovery of source-removed asset: %+v", d)
		}
	})
}

func testRelations(t *testing.T, f Factory) {
	rel := func(from, to string, typ model.RelationType) model.RelationInput {
		return model.RelationInput{FromKind: model.KindHostname, FromKey: from, ToKind: model.KindIP, ToKey: to, Type: typ}
	}
	setup := func(e *env) {
		e.snapshot("cf", []store.AssetUpsert{
			host("a.x.io", "cf"),
			au(model.KindIP, "1.1.1.1", "cf", model.ScopeOwned, nil),
			au(model.KindIP, "2.2.2.2", "cf", model.ScopeOwned, nil),
		}, []model.RelationInput{
			rel("a.x.io", "1.1.1.1", model.RelResolvesTo),
			rel("a.x.io", "2.2.2.2", model.RelResolvesTo),
			rel("a.x.io", "1.1.1.1", model.RelProxiedBy),
		}, at(0))
	}

	t.Run("edges in both directions", func(t *testing.T) {
		e := newEnv(t, f)
		setup(e)
		a := e.asset(model.KindHostname, "a.x.io")
		out, err := e.s.Edges(e.ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 3 {
			t.Fatalf("outbound edges = %d, want 3: %+v", len(out), out)
		}
		for _, ed := range out {
			if !ed.Outbound || ed.Other.Kind != model.KindIP {
				t.Errorf("edge = %+v", ed)
			}
		}
		ip := e.asset(model.KindIP, "1.1.1.1")
		in, err := e.s.Edges(e.ctx, ip.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(in) != 2 {
			t.Fatalf("inbound edges = %d, want 2", len(in))
		}
		types := map[model.RelationType]bool{}
		for _, ed := range in {
			if ed.Outbound || ed.Other.Key != "a.x.io" {
				t.Errorf("edge = %+v", ed)
			}
			types[ed.Type] = true
		}
		if !types[model.RelResolvesTo] || !types[model.RelProxiedBy] {
			t.Errorf("types = %v", types)
		}
	})

	t.Run("upsert is idempotent", func(t *testing.T) {
		e := newEnv(t, f)
		setup(e)
		setup(e)
		e.discover(nil, []model.RelationInput{rel("a.x.io", "1.1.1.1", model.RelResolvesTo)}, at(1))
		a := e.asset(model.KindHostname, "a.x.io")
		out, _ := e.s.Edges(e.ctx, a.ID)
		if len(out) != 3 {
			t.Errorf("edges after repeats = %d, want 3", len(out))
		}
	})

	t.Run("AddDiscovered relations link existing assets", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("a.x.io", "cf")}, nil, at(0))
		e.discover([]store.AssetUpsert{au(model.KindIP, "9.9.9.9", "discovery", model.ScopeOwned, nil)},
			[]model.RelationInput{rel("a.x.io", "9.9.9.9", model.RelResolvesTo)}, at(1))
		a := e.asset(model.KindHostname, "a.x.io")
		out, _ := e.s.Edges(e.ctx, a.ID)
		if len(out) != 1 || out[0].Other.Key != "9.9.9.9" {
			t.Errorf("edges = %+v", out)
		}
	})

	t.Run("asset without relations has no edges", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("lonely.x.io", "cf", at(0))
		out, err := e.s.Edges(e.ctx, a.ID)
		if err != nil || len(out) != 0 {
			t.Errorf("edges = %v, %v", out, err)
		}
	})
}

func testListAssets(t *testing.T, f Factory) {
	seed := func(e *env) {
		mk := func(kind model.AssetKind, key, src, zone string, scope model.ScopeClass) store.AssetUpsert {
			a := au(kind, key, src, scope, nil)
			a.Zone = zone
			return a
		}
		e.snapshot("cf", []store.AssetUpsert{
			mk(model.KindHostname, "a.x.io", "cf", "x.io", model.ScopeOwned),
			mk(model.KindHostname, "b.x.io", "cf", "x.io", model.ScopeOwned),
			mk(model.KindIP, "1.1.1.1", "cf", "", model.ScopeShared),
			mk(model.KindHostname, "gone.x.io", "cf", "x.io", model.ScopeOwned),
		}, nil, at(0))
		e.snapshot("cf", []store.AssetUpsert{
			mk(model.KindHostname, "a.x.io", "cf", "x.io", model.ScopeOwned),
			mk(model.KindHostname, "b.x.io", "cf", "x.io", model.ScopeOwned),
			mk(model.KindIP, "1.1.1.1", "cf", "", model.ScopeShared),
		}, nil, at(1))
		e.snapshot("r53", []store.AssetUpsert{
			mk(model.KindHostname, "c.y.io", "r53", "y.io", model.ScopeExternal),
			mk(model.KindHostname, "50%_off.y.io", "r53", "y.io", model.ScopeOwned),
		}, nil, at(1))
	}
	// Expected order is by kind then key.
	cases := []struct {
		name      string
		f         store.AssetFilter
		want      []string
		wantTotal int
	}{
		{"all non-removed", store.AssetFilter{}, []string{"50%_off.y.io", "a.x.io", "b.x.io", "c.y.io", "1.1.1.1"}, 5},
		{"include removed", store.AssetFilter{IncludeRemoved: true}, []string{"50%_off.y.io", "a.x.io", "b.x.io", "c.y.io", "gone.x.io", "1.1.1.1"}, 6},
		{"kind", store.AssetFilter{Kind: model.KindIP}, []string{"1.1.1.1"}, 1},
		{"source", store.AssetFilter{Source: "r53"}, []string{"50%_off.y.io", "c.y.io"}, 2},
		{"scope", store.AssetFilter{Scope: model.ScopeExternal}, []string{"c.y.io"}, 1},
		{"zone", store.AssetFilter{Zone: "x.io"}, []string{"a.x.io", "b.x.io"}, 2},
		{"zone with removed", store.AssetFilter{Zone: "x.io", IncludeRemoved: true}, []string{"a.x.io", "b.x.io", "gone.x.io"}, 3},
		{"query substring", store.AssetFilter{Query: "x.io"}, []string{"a.x.io", "b.x.io"}, 2},
		{"query is case-insensitive", store.AssetFilter{Query: "A.X"}, []string{"a.x.io"}, 1},
		{"query escapes wildcards", store.AssetFilter{Query: "%_"}, []string{"50%_off.y.io"}, 1},
		{"combined", store.AssetFilter{Kind: model.KindHostname, Source: "cf", Query: "b."}, []string{"b.x.io"}, 1},
		{"no match", store.AssetFilter{Query: "zzz"}, nil, 0},
		{"limit", store.AssetFilter{Limit: 2}, []string{"50%_off.y.io", "a.x.io"}, 5},
		{"limit+offset", store.AssetFilter{Limit: 2, Offset: 2}, []string{"b.x.io", "c.y.io"}, 5},
		{"offset past end", store.AssetFilter{Limit: 2, Offset: 10}, nil, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, f)
			seed(e)
			got, total, err := e.s.ListAssets(e.ctx, tc.f)
			if err != nil {
				t.Fatal(err)
			}
			var gotKeys []string
			for _, a := range got {
				gotKeys = append(gotKeys, a.Key)
			}
			if !equalStrings(gotKeys, tc.want) {
				t.Errorf("keys = %v, want %v", gotKeys, tc.want)
			}
			if total != tc.wantTotal {
				t.Errorf("total = %d, want %d", total, tc.wantTotal)
			}
		})
	}
}

func testObservations(t *testing.T, f Factory) {
	t.Run("latest per check", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		b := e.seedHost("b.x.io", "cf", at(0))
		save := func(id int64, check string, data map[string]any, now time.Time) {
			t.Helper()
			if err := e.s.SaveObservation(e.ctx, id, model.ObservationInput{Check: check, Data: data}, now); err != nil {
				t.Fatal(err)
			}
		}
		save(a.ID, "http.probe", map[string]any{"status": "200"}, at(1))
		save(a.ID, "tls.cert", map[string]any{"days": "30"}, at(1))
		save(a.ID, "http.probe", map[string]any{"status": "500"}, at(2))
		save(b.ID, "http.probe", map[string]any{"status": "404"}, at(2))

		got, err := e.s.LatestObservations(e.ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("observations = %d, want 2: %+v", len(got), got)
		}
		by := map[string]model.Observation{}
		for _, o := range got {
			by[o.Check] = o
		}
		if h := by["http.probe"]; h.Data["status"] != "500" || !h.ObservedAt.Equal(at(2)) || h.AssetID != a.ID {
			t.Errorf("http.probe = %+v", h)
		}
		if c := by["tls.cert"]; c.Data["days"] != "30" || !c.ObservedAt.Equal(at(1)) {
			t.Errorf("tls.cert = %+v", c)
		}
		other, _ := e.s.LatestObservations(e.ctx, b.ID)
		if len(other) != 1 || other[0].Data["status"] != "404" {
			t.Errorf("other asset observations = %+v", other)
		}
	})

	t.Run("none for fresh asset", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		got, err := e.s.LatestObservations(e.ctx, a.ID)
		if err != nil || len(got) != 0 {
			t.Errorf("= %v, %v", got, err)
		}
	})
}

func testBaselines(t *testing.T, f Factory) {
	t.Run("round trip and overwrite", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		if _, err := e.s.GetBaseline(e.ctx, a.ID, "net.ports"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing baseline err = %v, want ErrNotFound", err)
		}
		b := store.Baseline{
			AssetID: a.ID, Check: "net.ports",
			Data: map[string]any{"ports": []any{"22", "443"}}, Consistent: 1, UpdatedAt: at(1),
		}
		if err := e.s.SaveBaseline(e.ctx, b); err != nil {
			t.Fatal(err)
		}
		got, err := e.s.GetBaseline(e.ctx, a.ID, "net.ports")
		if err != nil {
			t.Fatal(err)
		}
		ports, _ := got.Data["ports"].([]any)
		if got.AssetID != a.ID || got.Check != "net.ports" || got.Stable || got.Consistent != 1 ||
			len(ports) != 2 || ports[0] != "22" || !got.UpdatedAt.Equal(at(1)) {
			t.Errorf("baseline = %+v", got)
		}
		b.Stable, b.Consistent, b.UpdatedAt = true, 3, at(2)
		b.Data = map[string]any{"ports": []any{"443"}}
		if err := e.s.SaveBaseline(e.ctx, b); err != nil {
			t.Fatal(err)
		}
		got, _ = e.s.GetBaseline(e.ctx, a.ID, "net.ports")
		if !got.Stable || got.Consistent != 3 || !got.UpdatedAt.Equal(at(2)) || len(got.Data["ports"].([]any)) != 1 {
			t.Errorf("overwritten baseline = %+v", got)
		}
		if _, err := e.s.GetBaseline(e.ctx, a.ID, "other"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("other check err = %v", err)
		}
	})
}
