// Package storetest is a reusable contract suite for store.Store
// implementations. Call Run from a test with a factory that returns a fresh,
// migrated, empty store (registering its own cleanup).
package storetest

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Factory returns a fresh, migrated, empty store. It must register any
// cleanup (including Close) with t.
type Factory func(t *testing.T) store.Store

// Run executes the full contract suite against stores built by newStore.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	groups := []struct {
		name string
		fn   func(*testing.T, Factory)
	}{
		{"Lifecycle", testLifecycle},
		{"Assets", testAssets},
		{"Ownership", testOwnership},
		{"OwnershipRules", testOwnershipRules},
		{"DerivedAttrs", testDerivedAttrs},
		{"UpsertSnapshot", testUpsertSnapshot},
		{"SyncWarning", testSyncWarning},
		{"ReplaceDerived", testReplaceDerived},
		{"Relations", testRelations},
		{"ListAssets", testListAssets},
		{"Observations", testObservations},
		{"Baselines", testBaselines},
		{"Reconcile", testReconcile},
		{"ReconcilePartial", testReconcilePartial},
		{"ReconcileAcrossKinds", testReconcileAcrossKinds},
		{"PreservedStatuses", testPreservedStatuses},
		{"FindingStatus", testFindingStatus},
		{"ListFindings", testListFindings},
		{"Events", testEvents},
		{"SyncsScans", testSyncsScans},
		{"RemovedAssetFindings", testRemovedAssetFindings},
		{"ScanHistory", testScanHistory},
		{"Stats", testStats},
		{"NotFound", testNotFound},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) { g.fn(t, newStore) })
	}
}

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

type env struct {
	t   *testing.T
	s   store.Store
	ctx context.Context
}

func newEnv(t *testing.T, f Factory) *env {
	t.Helper()
	return &env{t: t, s: f(t), ctx: context.Background()}
}

func au(kind model.AssetKind, key, source string, scope model.ScopeClass, attrs map[string]any) store.AssetUpsert {
	return store.AssetUpsert{
		AssetInput: model.AssetInput{Kind: kind, Key: key, Source: source, Attrs: attrs},
		Scope:      scope,
	}
}

func host(key, source string) store.AssetUpsert {
	return au(model.KindHostname, key, source, model.ScopeOwned, nil)
}

func (e *env) snapshot(source string, assets []store.AssetUpsert, rels []model.RelationInput, now time.Time) store.InventoryDiff {
	e.t.Helper()
	d, err := e.s.ApplySnapshot(e.ctx, source, assets, rels, now)
	if err != nil {
		e.t.Fatalf("ApplySnapshot(%s): %v", source, err)
	}
	return d
}

func (e *env) discover(assets []store.AssetUpsert, rels []model.RelationInput, now time.Time) store.InventoryDiff {
	e.t.Helper()
	d, err := e.s.AddDiscovered(e.ctx, assets, rels, now)
	if err != nil {
		e.t.Fatalf("AddDiscovered: %v", err)
	}
	return d
}

func (e *env) asset(kind model.AssetKind, key string) *model.Asset {
	e.t.Helper()
	a, err := e.s.GetAssetByKey(e.ctx, kind, key)
	if err != nil {
		e.t.Fatalf("GetAssetByKey(%s,%s): %v", kind, key, err)
	}
	return a
}

// seedHost snapshots one hostname under source and returns it.
func (e *env) seedHost(key, source string, now time.Time) *model.Asset {
	e.t.Helper()
	e.snapshot(source, []store.AssetUpsert{host(key, source)}, nil, now)
	return e.asset(model.KindHostname, key)
}

func keysOf(as []model.Asset) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.Key)
	}
	sort.Strings(out)
	return out
}

func sorted(s ...string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func titles(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Title)
	}
	sort.Strings(out)
	return out
}

func fi(check, key string, sev model.Severity) model.FindingInput {
	return model.FindingInput{Check: check, Key: key, Severity: sev, Title: key, Description: "desc " + key}
}

func (e *env) reconcile(assetID int64, check string, fs []model.FindingInput, resolveAfter int, now time.Time) store.ReconcileResult {
	e.t.Helper()
	r, err := e.s.ReconcileFindings(e.ctx, store.ReconcileInput{
		AssetID: assetID, Check: check, Findings: fs, ResolveAfter: resolveAfter, Now: now,
	})
	if err != nil {
		e.t.Fatalf("ReconcileFindings: %v", err)
	}
	return r
}

func (e *env) finding(id int64) *model.Finding {
	e.t.Helper()
	f, err := e.s.GetFinding(e.ctx, id)
	if err != nil {
		e.t.Fatalf("GetFinding(%d): %v", id, err)
	}
	return f
}

func (e *env) findingByTitle(assetID int64, check, title string) *model.Finding {
	e.t.Helper()
	fs, _, err := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: assetID, Check: check, Query: title})
	if err != nil {
		e.t.Fatalf("ListFindings: %v", err)
	}
	for i := range fs {
		if fs[i].Title == title {
			return &fs[i]
		}
	}
	e.t.Fatalf("finding %q not found", title)
	return nil
}
