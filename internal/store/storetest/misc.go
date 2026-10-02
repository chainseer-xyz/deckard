package storetest

import (
	"reflect"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func countTypes(evs []store.Event) map[string]int {
	m := map[string]int{}
	for _, ev := range evs {
		m[ev.Type]++
	}
	return m
}

func testEvents(t *testing.T, f Factory) {
	t.Run("store writes events for inventory and finding transitions", func(t *testing.T) {
		e := newEnv(t, f)
		a := au(model.KindHostname, "a.x.io", "cf", model.ScopeOwned, map[string]any{"v": "1"})
		b := host("b.x.io", "cf")
		e.snapshot("cf", []store.AssetUpsert{a, b}, nil, at(1))                                                                               // 2 added
		e.snapshot("cf", []store.AssetUpsert{au(model.KindHostname, "a.x.io", "cf", model.ScopeOwned, map[string]any{"v": "2"})}, nil, at(2)) // changed a, removed b
		e.snapshot("cf", []store.AssetUpsert{a, b}, nil, at(3))                                                                               // changed a, revived b
		e.discover([]store.AssetUpsert{host("c.x.io", "disc")}, nil, at(4))                                                                   // added c
		id := e.asset(model.KindHostname, "a.x.io").ID
		e.reconcile(id, "c1", []model.FindingInput{fi("c1", "k", model.SeverityLow)}, 1, at(5)) // opened
		e.reconcile(id, "c1", nil, 1, at(6))                                                    // resolved
		e.reconcile(id, "c1", []model.FindingInput{fi("c1", "k", model.SeverityLow)}, 1, at(7)) // reopened

		evs, err := e.s.ListEvents(e.ctx, at(0), 0)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]int{
			"asset_added": 3, "asset_changed": 2, "asset_removed": 1, "asset_revived": 1,
			"finding_opened": 1, "finding_resolved": 1, "finding_reopened": 1,
		}
		if got := countTypes(evs); !reflect.DeepEqual(got, want) {
			t.Fatalf("event counts = %v, want %v", got, want)
		}
		for i := 1; i < len(evs); i++ {
			if evs[i].At.After(evs[i-1].At) {
				t.Errorf("events not newest-first at %d", i)
			}
		}
		for _, ev := range evs {
			if ev.ID == 0 || ev.Subject == "" || ev.At.IsZero() {
				t.Errorf("incomplete event %+v", ev)
			}
			if ev.Type == "asset_removed" && ev.Subject != "b.x.io" {
				t.Errorf("removed subject = %q", ev.Subject)
			}
			if ev.Type == "finding_opened" && ev.Subject != "a.x.io" {
				t.Errorf("finding subject = %q", ev.Subject)
			}
		}
	})

	t.Run("since and limit", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("a", "cf")}, nil, at(1))
		e.snapshot("cf", []store.AssetUpsert{host("a", "cf"), host("b", "cf")}, nil, at(5))
		e.snapshot("cf", []store.AssetUpsert{host("a", "cf"), host("b", "cf"), host("c", "cf")}, nil, at(9))
		cases := []struct {
			name  string
			since int
			limit int
			want  []string
		}{
			{"all", 0, 0, []string{"c", "b", "a"}},
			{"since inclusive", 5, 0, []string{"c", "b"}},
			{"since late", 6, 0, []string{"c"}},
			{"since after all", 10, 0, nil},
			{"limit keeps newest", 0, 2, []string{"c", "b"}},
		}
		for _, c := range cases {
			evs, err := e.s.ListEvents(e.ctx, at(c.since), c.limit)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, ev := range evs {
				got = append(got, ev.Subject)
			}
			if !equalStrings(got, c.want) {
				t.Errorf("%s: subjects = %v, want %v", c.name, got, c.want)
			}
		}
	})

	t.Run("no-op snapshot writes no events", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("a", "cf")}, nil, at(1))
		e.snapshot("cf", []store.AssetUpsert{host("a", "cf")}, nil, at(2))
		evs, _ := e.s.ListEvents(e.ctx, at(0), 0)
		if len(evs) != 1 {
			t.Errorf("events = %d, want 1", len(evs))
		}
	})
}

func testSyncsScans(t *testing.T, f Factory) {
	t.Run("RecordSync upserts per source", func(t *testing.T) {
		e := newEnv(t, f)
		if got, err := e.s.ListSyncs(e.ctx); err != nil || len(got) != 0 {
			t.Fatalf("empty ListSyncs = %v, %v", got, err)
		}
		rec := func(s store.SyncStatus) {
			t.Helper()
			if err := e.s.RecordSync(e.ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		rec(store.SyncStatus{Source: "r53", Type: "route53", LastRun: at(1), LastOK: at(1), AssetCount: 5, DurationMS: 30})
		rec(store.SyncStatus{Source: "cf", Type: "cloudflare", LastRun: at(1), LastOK: at(1), AssetCount: 10, DurationMS: 20})
		rec(store.SyncStatus{Source: "cf", Type: "cloudflare", LastRun: at(2), LastOK: at(2), AssetCount: 12, DurationMS: 25})
		got, err := e.s.ListSyncs(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].Source != "cf" || got[1].Source != "r53" {
			t.Fatalf("syncs = %+v", got)
		}
		if c := got[0]; c.Type != "cloudflare" || c.AssetCount != 12 || c.DurationMS != 25 || !c.LastRun.Equal(at(2)) || !c.LastOK.Equal(at(2)) || c.Error != "" {
			t.Errorf("cf = %+v", c)
		}
		// A failed run records the error and keeps the last success time.
		rec(store.SyncStatus{Source: "cf", Type: "cloudflare", LastRun: at(3), Error: "boom"})
		got, _ = e.s.ListSyncs(e.ctx)
		if c := got[0]; c.Error != "boom" || !c.LastRun.Equal(at(3)) || !c.LastOK.Equal(at(2)) {
			t.Errorf("after failure cf = %+v", c)
		}
	})

	t.Run("RecordScan and ListScans newest first", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		for i, c := range []string{"c1", "c2", "c3"} {
			err := e.s.RecordScan(e.ctx, store.ScanRun{AssetID: a.ID, Check: c, Tier: "passive", StartedAt: at(i), DurationMS: int64(10 * (i + 1)), Findings: i})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := e.s.RecordScan(e.ctx, store.ScanRun{AssetID: a.ID, Check: "c4", Tier: "active", StartedAt: at(3), Error: "timeout"}); err != nil {
			t.Fatal(err)
		}
		got, err := e.s.ListScans(e.ctx, 3)
		if err != nil {
			t.Fatal(err)
		}
		var checks []string
		for _, s := range got {
			checks = append(checks, s.Check)
		}
		if !equalStrings(checks, []string{"c4", "c3", "c2"}) {
			t.Fatalf("checks = %v, want [c4 c3 c2]", checks)
		}
		if got[0].Error != "timeout" || got[0].Tier != "active" || got[0].ID == 0 || got[0].AssetID != a.ID {
			t.Errorf("c4 = %+v", got[0])
		}
		if got[1].DurationMS != 30 || got[1].Findings != 2 || !got[1].StartedAt.Equal(at(2)) {
			t.Errorf("c3 = %+v", got[1])
		}
		all, _ := e.s.ListScans(e.ctx, 0)
		if len(all) != 4 {
			t.Errorf("unlimited ListScans = %d, want 4", len(all))
		}
	})
}

func testStats(t *testing.T, f Factory) {
	t.Run("counts non-removed assets and open findings only", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{
			host("a.x.io", "cf"),
			host("b.x.io", "cf"),
			host("gone.x.io", "cf"),
			au(model.KindIP, "1.1.1.1", "cf", model.ScopeShared, nil),
		}, nil, at(0))
		e.snapshot("cf", []store.AssetUpsert{
			host("a.x.io", "cf"), host("b.x.io", "cf"), au(model.KindIP, "1.1.1.1", "cf", model.ScopeShared, nil),
		}, nil, at(1))
		e.snapshot("r53", []store.AssetUpsert{au(model.KindHostname, "c.y.io", "r53", model.ScopeExternal, nil)}, nil, at(1))

		a, b := e.asset(model.KindHostname, "a.x.io"), e.asset(model.KindHostname, "b.x.io")
		e.reconcile(a.ID, "c1", []model.FindingInput{fi("c1", "h", model.SeverityHigh), fi("c1", "l", model.SeverityLow), fi("c1", "gone", model.SeverityHigh), fi("c1", "ack", model.SeverityHigh)}, 1, at(2))
		e.reconcile(b.ID, "c2", []model.FindingInput{fi("c2", "h2", model.SeverityHigh)}, 1, at(2))
		e.reconcile(a.ID, "c1", []model.FindingInput{fi("c1", "h", model.SeverityHigh), fi("c1", "l", model.SeverityLow), fi("c1", "ack", model.SeverityHigh)}, 1, at(3)) // resolves "gone"
		if err := e.s.ChangeFindingStatus(e.ctx, e.findingByTitle(a.ID, "c1", "ack").ID, store.StatusChange{Status: model.StatusAcknowledged}, at(4)); err != nil {
			t.Fatal(err)
		}

		st, err := e.s.Stats(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := store.Stats{
			AssetsByKind:    map[string]int{"hostname": 3, "ip": 1},
			AssetsBySource:  map[string]int{"cf": 3, "r53": 1},
			AssetsByScope:   map[string]int{"owned": 2, "shared": 1, "external": 1},
			FindingsBySev:   map[string]int{"high": 2, "low": 1},
			FindingsByCheck: map[string]int{"c1": 2, "c2": 1},
		}
		if !reflect.DeepEqual(st, want) {
			t.Errorf("stats = %+v\nwant   %+v", st, want)
		}
	})

	t.Run("empty store has non-nil maps", func(t *testing.T) {
		e := newEnv(t, f)
		st, err := e.s.Stats(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.AssetsByKind == nil || st.AssetsBySource == nil || st.AssetsByScope == nil || st.FindingsBySev == nil || st.FindingsByCheck == nil {
			t.Errorf("nil map in %+v", st)
		}
		if len(st.AssetsByKind)+len(st.FindingsBySev) != 0 {
			t.Errorf("stats = %+v", st)
		}
	})
}
