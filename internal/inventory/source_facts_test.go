package inventory_test

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const overlapIP = "93.184.216.34"

func sourceFactsGuard(t *testing.T, cfg config.ScopeConfig) *scope.Guard {
	t.Helper()
	g, err := scope.NewGuard(cfg, scope.WithLogger(quiet))
	if err != nil {
		t.Fatal(err)
	}
	// An explicit authoritative claim may override a provider range, while a
	// Cloudflare origin relationship alone cannot. No network calls occur.
	g.SetSharedRanges([]netip.Prefix{netip.MustParsePrefix(overlapIP + "/32")})
	return g
}

func syncFactsSource(t *testing.T, svc *inventory.Service, src *fakeSrc) {
	t.Helper()
	if _, err := svc.Sync(context.Background(), src); err != nil {
		t.Fatal(err)
	}
}

func assertFactsClass(t *testing.T, g *scope.Guard, kind model.AssetKind, key string, want model.ScopeClass) {
	t.Helper()
	if got := g.Classify(kind, key); got != want {
		t.Fatalf("classify %s %s = %s, want %s", kind, key, got, want)
	}
}

func rehydrateFacts(t *testing.T, st store.Store, cfg config.ScopeConfig) (*inventory.Service, *scope.Guard) {
	t.Helper()
	g := sourceFactsGuard(t, cfg)
	svc := inventory.New(st, g, quiet)
	if err := svc.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return svc, g
}

func TestSourceFactsRehydrateIPArrivalOrders(t *testing.T) {
	orders := [][]string{
		{"cf", "aws", "k8s"}, {"cf", "k8s", "aws"},
		{"aws", "cf", "k8s"}, {"aws", "k8s", "cf"},
		{"k8s", "cf", "aws"}, {"k8s", "aws", "cf"},
	}
	for _, order := range orders {
		t.Run(strings.Join(order, "-"), func(t *testing.T) {
			st := pgtest.New(t)
			g := sourceFactsGuard(t, config.ScopeConfig{})
			svc := inventory.New(st, g, quiet)
			facts := map[string]map[string]any{
				"cf":  {"origin": true},
				"aws": {"owned": true, "resource_id": "eipalloc-example"},
				"k8s": {"cluster": "staging"},
			}
			types := map[string]string{"cf": "cloudflare", "aws": "aws", "k8s": "kubernetes"}
			sources := map[string]*fakeSrc{}
			for name, attrs := range facts {
				sources[name] = &fakeSrc{name: name, typ: types[name], d: &source.Discovery{Assets: []model.AssetInput{ip(overlapIP, attrs)}}}
			}
			for _, name := range order {
				syncFactsSource(t, svc, sources[name])
			}
			assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeOwned)
			a, err := st.GetAssetByKey(context.Background(), model.KindIP, overlapIP)
			if err != nil {
				t.Fatal(err)
			}
			if a.Source != order[0] || !reflect.DeepEqual(a.Attrs, facts[order[0]]) {
				t.Fatalf("canonical facts changed: source=%s attrs=%v", a.Source, a.Attrs)
			}
			if !slices.Equal(a.Reporters, []string{"aws", "cf", "k8s"}) {
				t.Fatalf("reporters=%v", a.Reporters)
			}
			for name, attrs := range facts {
				if !reflect.DeepEqual(a.SourceFacts[name].Attrs, attrs) {
					t.Fatalf("%s facts=%v, want %v", name, a.SourceFacts[name].Attrs, attrs)
				}
			}

			// A fresh replica restores both owners regardless of the canonical
			// first writer. Withdrawing AWS cannot discard Kubernetes' claim.
			svc, g = rehydrateFacts(t, st, config.ScopeConfig{})
			assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeOwned)
			sources["aws"].d = &source.Discovery{}
			syncFactsSource(t, svc, sources["aws"])
			assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeOwned)
			svc, g = rehydrateFacts(t, st, config.ScopeConfig{})
			assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeOwned)
			sources["k8s"].d = &source.Discovery{}
			syncFactsSource(t, svc, sources["k8s"])
			assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeShared)
			_, g = rehydrateFacts(t, st, config.ScopeConfig{})
			assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeShared)
			a, err = st.GetAssetByKey(context.Background(), model.KindIP, overlapIP)
			if err != nil {
				t.Fatal(err)
			}
			if a.Source != "cf" || !slices.Equal(a.Reporters, []string{"cf"}) || len(a.SourceFacts) != 1 || a.Attrs["owned"] != nil {
				t.Fatalf("withdrawn owners left facts behind: %+v", a)
			}
		})
	}
}

func TestSourceFactsRehydrateZoneOverlap(t *testing.T) {
	for _, order := range [][]string{{"cf", "r53"}, {"r53", "cf"}} {
		t.Run(strings.Join(order, "-"), func(t *testing.T) {
			st := pgtest.New(t)
			svc := inventory.New(st, sourceFactsGuard(t, config.ScopeConfig{}), quiet)
			sources := map[string]*fakeSrc{
				"cf":  {name: "cf", typ: "cloudflare"},
				"r53": {name: "r53", typ: "route53"},
			}
			for _, name := range order {
				sources[name].d = &source.Discovery{Zones: []source.Zone{zone("example.com")}, Assets: []model.AssetInput{zoneAsset("example.com")}}
				syncFactsSource(t, svc, sources[name])
			}
			svc, g := rehydrateFacts(t, st, config.ScopeConfig{})
			assertFactsClass(t, g, model.KindHostname, "www.example.com", model.ScopeOwned)
			sources[order[0]].d = &source.Discovery{}
			syncFactsSource(t, svc, sources[order[0]])
			assertFactsClass(t, g, model.KindHostname, "www.example.com", model.ScopeOwned)
			svc, g = rehydrateFacts(t, st, config.ScopeConfig{})
			assertFactsClass(t, g, model.KindHostname, "www.example.com", model.ScopeOwned)
			sources[order[1]].d = &source.Discovery{}
			syncFactsSource(t, svc, sources[order[1]])
			assertFactsClass(t, g, model.KindHostname, "www.example.com", model.ScopeExternal)
			_, g = rehydrateFacts(t, st, config.ScopeConfig{})
			assertFactsClass(t, g, model.KindHostname, "www.example.com", model.ScopeExternal)
		})
	}
}

func TestSourceFactsPartialUpdatesAndExclusions(t *testing.T) {
	st := pgtest.New(t)
	ctx := context.Background()
	svc := inventory.New(st, sourceFactsGuard(t, config.ScopeConfig{}), quiet)
	cf := &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{Assets: []model.AssetInput{ip(overlapIP, map[string]any{"origin": true})}}}
	aws := &fakeSrc{name: "aws", typ: "aws", d: &source.Discovery{Assets: []model.AssetInput{
		ip(overlapIP, map[string]any{"owned": true}), ip("93.184.216.35", map[string]any{"owned": true}),
	}}}
	syncFactsSource(t, svc, cf)
	syncFactsSource(t, svc, aws)
	svc, g := rehydrateFacts(t, st, config.ScopeConfig{})

	// Absence from a partial result does not retract an earlier claim. An
	// explicit changed fact for a present IP does replace that IP's claim.
	aws.d = &source.Discovery{Partial: true, PartialReasons: []string{"regional outage"}, Assets: []model.AssetInput{ip(overlapIP, map[string]any{"owned": false})}}
	syncFactsSource(t, svc, aws)
	assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeShared)
	assertFactsClass(t, g, model.KindIP, "93.184.216.35", model.ScopeOwned)
	svc, g = rehydrateFacts(t, st, config.ScopeConfig{})
	assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeShared)
	assertFactsClass(t, g, model.KindIP, "93.184.216.35", model.ScopeOwned)
	a, err := st.GetAssetByKey(ctx, model.KindIP, overlapIP)
	if err != nil || a.SourceFacts["aws"].Attrs["owned"] != false {
		t.Fatalf("present partial fact not replaced: asset=%v err=%v", a, err)
	}

	aws.d = &source.Discovery{Assets: []model.AssetInput{ip(overlapIP, map[string]any{"owned": true})}}
	syncFactsSource(t, svc, aws)
	assertFactsClass(t, g, model.KindIP, "93.184.216.35", model.ScopeExternal)
	_, g = rehydrateFacts(t, st, config.ScopeConfig{Exclude: []string{overlapIP + "/32", "secret.example.com"}})
	assertFactsClass(t, g, model.KindIP, overlapIP, model.ScopeExcluded)
	assertFactsClass(t, g, model.KindIP, "93.184.216.35", model.ScopeExternal)
	cf.d = &source.Discovery{Zones: []source.Zone{zone("example.com")}, Assets: []model.AssetInput{zoneAsset("example.com")}}
	syncFactsSource(t, svc, cf)
	_, g = rehydrateFacts(t, st, config.ScopeConfig{Exclude: []string{overlapIP + "/32", "secret.example.com"}})
	assertFactsClass(t, g, model.KindHostname, "www.example.com", model.ScopeOwned)
	assertFactsClass(t, g, model.KindHostname, "secret.example.com", model.ScopeExcluded)
}

func TestSourceFactsRehydrateLegacyAndMissingFacts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		asset     model.Asset
		want      model.ScopeClass
		withdraw  string
		afterDrop model.ScopeClass
	}{
		{name: "legacy canonical fallback", asset: model.Asset{Source: "cf", Attrs: map[string]any{"owned": true}}, want: model.ScopeOwned, withdraw: "cf", afterDrop: model.ScopeShared},
		{name: "missing secondary attrs do not borrow canonical", asset: model.Asset{Source: "cf", Attrs: map[string]any{"owned": true}, Reporters: []string{"aws", "cf"}}, want: model.ScopeOwned, withdraw: "cf", afterDrop: model.ScopeShared},
		{name: "secondary empty attrs do not borrow canonical", asset: model.Asset{Source: "cf", Attrs: map[string]any{"owned": true}, Reporters: []string{"aws", "cf"}, SourceFacts: map[string]model.SourceFact{"aws": {}}}, want: model.ScopeOwned, withdraw: "cf", afterDrop: model.ScopeShared},
		{name: "explicit own fact replaces canonical fallback", asset: model.Asset{Source: "cf", Attrs: map[string]any{"owned": true}, Reporters: []string{"cf"}, SourceFacts: map[string]model.SourceFact{"cf": {Attrs: map[string]any{"owned": false}}}}, want: model.ScopeShared},
		{name: "orphan fact does not assert authority", asset: model.Asset{Source: "cf", Reporters: []string{"cf"}, SourceFacts: map[string]model.SourceFact{"aws": {Attrs: map[string]any{"owned": true}}}}, want: model.ScopeShared},
		{name: "nonmember canonical does not assert authority", asset: model.Asset{Source: "cf", Attrs: map[string]any{"owned": true}, Reporters: []string{"aws"}}, want: model.ScopeShared},
		{name: "secondary Kubernetes identity proves claim", asset: model.Asset{Source: "cf", Reporters: []string{"cf", "k8s"}}, want: model.ScopeOwned, withdraw: "k8s", afterDrop: model.ScopeShared},
		{name: "derived attrs cannot assert ownership", asset: model.Asset{Source: "net.ports", Attrs: map[string]any{"owned": true}}, want: model.ScopeShared},
		{name: "ingested attrs cannot assert ownership", asset: model.Asset{Source: "ingest:prowler", Attrs: map[string]any{"owned": true}}, want: model.ScopeShared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fakestore.New()
			tc.asset.ID, tc.asset.Kind, tc.asset.Key = 1, model.KindIP, overlapIP
			st.Assets[1] = tc.asset
			st.Syncs = []store.SyncStatus{{Source: "cf", Type: "cloudflare"}, {Source: "aws", Type: "aws"}, {Source: "k8s", Type: "kubernetes"}}
			svc, g := rehydrateFacts(t, st, config.ScopeConfig{})
			assertFactsClass(t, g, model.KindIP, overlapIP, tc.want)
			if tc.withdraw != "" {
				typ := map[string]string{"cf": "cloudflare", "k8s": "kubernetes"}[tc.withdraw]
				syncFactsSource(t, svc, &fakeSrc{name: tc.withdraw, typ: typ, d: &source.Discovery{}})
				assertFactsClass(t, g, model.KindIP, overlapIP, tc.afterDrop)
			}
		})
	}
}
