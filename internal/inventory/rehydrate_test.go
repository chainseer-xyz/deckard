package inventory_test

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func zoneAsset(n string) model.AssetInput { return model.AssetInput{Kind: model.KindZone, Key: n} }

func sortedZones(c *fakeCls) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]string{}, c.zones...)
	sort.Strings(out)
	return out
}

func ownedPrefixes(c *fakeCls) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []string{}
	for _, p := range c.owned {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out
}

func restartFixtures() (cf, k8s, stat *fakeSrc) {
	cf = &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{
		Zones: []source.Zone{zone("example.com"), zone("other.net")},
		Assets: []model.AssetInput{
			zoneAsset("example.com"), zoneAsset("other.net"), host("www.example.com"),
			ip("192.0.2.10", map[string]any{"origin": true}),  // relation only, not ownership evidence
			ip("104.16.1.1", map[string]any{"origin": true}),  // shared edge: never owned
			ip("192.0.2.99", map[string]any{"proxied": true}), // no claim
		},
	}}
	k8s = &fakeSrc{name: "k8s", typ: "kubernetes", d: &source.Discovery{Assets: []model.AssetInput{
		ip("198.51.100.7", map[string]any{"cluster": "prod"}),
	}}}
	stat = &fakeSrc{name: "static", typ: "static", d: &source.Discovery{Assets: []model.AssetInput{
		ip("203.0.113.0/24", map[string]any{"owned": true}),
	}}}
	return
}

var probeKeys = []struct {
	kind model.AssetKind
	key  string
}{
	{model.KindHostname, "www.example.com"}, {model.KindHostname, "x.other.net"}, {model.KindHostname, "evil.org"},
	{model.KindIP, "192.0.2.10"}, {model.KindIP, "104.16.1.1"}, {model.KindIP, "192.0.2.99"},
	{model.KindIP, "198.51.100.7"}, {model.KindIP, "203.0.113.50"}, {model.KindIP, "8.8.8.8"},
}

func classes(c *fakeCls) []model.ScopeClass {
	var out []model.ScopeClass
	for _, p := range probeKeys {
		out = append(out, c.Classify(p.kind, p.key))
	}
	return out
}

func TestRehydrateAfterRestart(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls1 := &fakeCls{sharedPfx: pfx("104.16.0.0/13")}
	svc1 := inventory.New(st, cls1, quiet)
	cf, k8s, stat := restartFixtures()
	for _, s := range []*fakeSrc{cf, k8s, stat} {
		if _, err := svc1.Sync(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	want := classes(cls1)
	if want[3] != model.ScopeExternal || want[4] != model.ScopeShared || want[7] != model.ScopeOwned {
		t.Fatalf("fixture sanity: %v", want)
	}

	// "Restart": new process, empty classifier, same database.
	cls2 := &fakeCls{sharedPfx: pfx("104.16.0.0/13")}
	svc2 := inventory.New(st, cls2, quiet)
	if got := classes(cls2); reflect.DeepEqual(got, want) {
		t.Fatal("test is vacuous: fresh classifier already classifies identically")
	}
	if err := svc2.Rehydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := classes(cls2); !reflect.DeepEqual(got, want) {
		t.Errorf("classes after rehydrate = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(sortedZones(cls2), sortedZones(cls1)) {
		t.Errorf("zones = %v, want %v", sortedZones(cls2), sortedZones(cls1))
	}
	if !reflect.DeepEqual(ownedPrefixes(cls2), ownedPrefixes(cls1)) {
		t.Errorf("prefixes = %v, want %v", ownedPrefixes(cls2), ownedPrefixes(cls1))
	}

	// Idempotent.
	if err := svc2.Rehydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := classes(cls2); !reflect.DeepEqual(got, want) {
		t.Errorf("classes after second rehydrate = %v", got)
	}

	// Per-source bookkeeping is seeded: a later Sync of cf that drops a zone
	// shrinks the union instead of leaving the rehydrated zone stuck.
	cf.d = &source.Discovery{Zones: []source.Zone{zone("example.com")}, Assets: []model.AssetInput{zoneAsset("example.com"), host("www.example.com")}}
	if _, err := svc2.Sync(ctx, cf); err != nil {
		t.Fatal(err)
	}
	if got := sortedZones(cls2); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Errorf("zones after sync = %v", got)
	}
	// k8s' registration (rehydrated, not re-synced) survives cf's sync.
	if got := cls2.Classify(model.KindIP, "198.51.100.7"); got != model.ScopeOwned {
		t.Errorf("k8s prefix lost: %s", got)
	}
}

func TestRehydrateIgnoresRemovedAssets(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	svc1 := inventory.New(st, &fakeCls{}, quiet)
	cf, _, _ := restartFixtures()
	if _, err := svc1.Sync(ctx, cf); err != nil {
		t.Fatal(err)
	}
	cf.d = &source.Discovery{Zones: []source.Zone{zone("example.com")}, Assets: []model.AssetInput{zoneAsset("example.com")}}
	if _, err := svc1.Sync(ctx, cf); err != nil {
		t.Fatal(err)
	}
	cls := &fakeCls{}
	if err := inventory.New(st, cls, quiet).Rehydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sortedZones(cls); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Errorf("zones = %v", got)
	}
	if got := ownedPrefixes(cls); len(got) != 0 {
		t.Errorf("prefixes from removed IPs: %v", got)
	}
	// Empty database is fine too.
	if err := inventory.New(pgtest.New(t), &fakeCls{}, quiet).Rehydrate(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRunRefreshPicksUpOtherReplicasChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := pgtest.New(t)

	a := inventory.New(st, &fakeCls{}, quiet) // the replica that syncs
	clsB := &fakeCls{}
	b := inventory.New(st, clsB, quiet) // a replica that only refreshes
	cf, _, _ := restartFixtures()
	if _, err := a.Sync(ctx, cf); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() { defer close(done); b.RunRefresh(ctx, 10*time.Millisecond) }()
	waitFor(t, func() bool { return reflect.DeepEqual(sortedZones(clsB), []string{"example.com", "other.net"}) })

	// The zone is dropped by the syncing replica; the refresher follows.
	cf.d = &source.Discovery{Zones: []source.Zone{zone("example.com")}, Assets: []model.AssetInput{zoneAsset("example.com"), host("www.example.com")}}
	if _, err := a.Sync(ctx, cf); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return reflect.DeepEqual(sortedZones(clsB), []string{"example.com"}) })

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunRefresh did not stop on ctx cancel")
	}
}

type failingStore struct {
	store.Store
}

func (failingStore) ListAssets(context.Context, store.AssetFilter) ([]model.Asset, int, error) {
	panic("boom")
}

func TestRunRefreshSurvivesErrorsAndPanics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	svc := inventory.New(failingStore{}, &fakeCls{}, quiet)
	done := make(chan struct{})
	go func() { defer close(done); svc.RunRefresh(ctx, 5*time.Millisecond) }()
	time.Sleep(60 * time.Millisecond) // several ticks, each panicking
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunRefresh did not stop")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}

func TestReplaceDerivedFiltersScopeAndGarbageCollects(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{}
	svc := inventory.New(st, cls, quiet)
	if _, err := svc.Sync(ctx, &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{
		Zones: []source.Zone{zone("example.com")}, Assets: []model.AssetInput{host("www.example.com")},
	}}); err != nil {
		t.Fatal(err)
	}
	parent, _ := st.GetAssetByKey(ctx, model.KindHostname, "www.example.com")
	mk := func(k string) model.AssetInput {
		return model.AssetInput{Kind: model.KindHostname, Key: k, Source: "net.ports"}
	}
	d, err := svc.ReplaceDerived(ctx, parent.ID, "net.ports", []model.AssetInput{mk("a.example.com"), mk("evil.org")}, nil)
	if err != nil || len(d.Added) != 1 {
		t.Fatalf("diff=%+v err=%v", d, err)
	}
	// Nothing observed any more (even when nothing is in scope): GC runs.
	d, err = svc.ReplaceDerived(ctx, parent.ID, "net.ports", []model.AssetInput{mk("evil.org")}, nil)
	if err != nil || len(d.Removed) != 1 || d.Removed[0].Key != "a.example.com" {
		t.Fatalf("diff=%+v err=%v", d, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.ReplaceDerived(cctx, parent.ID, "net.ports", nil, nil); err == nil {
		t.Fatal("want ctx error")
	}
}
