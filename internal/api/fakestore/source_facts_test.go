package fakestore_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestListAssetsMatchesReporterSources(t *testing.T) {
	st := fakestore.New()
	st.Assets[1] = model.Asset{ID: 1, Source: "cf", Reporters: []string{"aws", "cf"}}
	st.Assets[2] = model.Asset{ID: 2, Source: "aws"}                                                     // legacy canonical source
	st.Assets[3] = model.Asset{ID: 3, Source: "cf", SourceFacts: map[string]model.SourceFact{"aws": {}}} // facts alone do not assert membership
	st.Assets[4] = model.Asset{ID: 4, Source: "k8s", Reporters: []string{"aws", "k8s"}}
	for _, tc := range []struct {
		source string
		ids    []int64
	}{
		{"aws", []int64{1, 2, 4}},
		{"cf", []int64{1, 3}},
		{"k8s", []int64{4}},
		{"missing", nil},
		{"", []int64{1, 2, 3, 4}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			assets, total, err := st.ListAssets(context.Background(), store.AssetFilter{Source: tc.source})
			if err != nil {
				t.Fatal(err)
			}
			var ids []int64
			for _, a := range assets {
				ids = append(ids, a.ID)
			}
			if total != len(tc.ids) || !reflect.DeepEqual(ids, tc.ids) {
				t.Fatalf("ids=%v total=%d, want %v total=%d", ids, total, tc.ids, len(tc.ids))
			}
		})
	}
	page, total, err := st.ListAssets(context.Background(), store.AssetFilter{Source: "aws", Limit: 1, Offset: 1})
	if err != nil || total != 3 || len(page) != 1 || page[0].ID != 2 {
		t.Fatalf("page=%v total=%d err=%v", page, total, err)
	}
}

func TestAssetReadsCloneSourceFacts(t *testing.T) {
	ctx := context.Background()
	readers := map[string]func(*fakestore.Store) (model.Asset, error){
		"id": func(st *fakestore.Store) (model.Asset, error) {
			a, err := st.GetAsset(ctx, 1)
			if err != nil {
				return model.Asset{}, err
			}
			return *a, nil
		},
		"key": func(st *fakestore.Store) (model.Asset, error) {
			a, err := st.GetAssetByKey(ctx, model.KindIP, "93.184.216.34")
			if err != nil {
				return model.Asset{}, err
			}
			return *a, nil
		},
		"list": func(st *fakestore.Store) (model.Asset, error) {
			as, _, err := st.ListAssets(ctx, store.AssetFilter{IncludeRemoved: true})
			if err != nil {
				return model.Asset{}, err
			}
			return as[0], nil
		},
		"edges": func(st *fakestore.Store) (model.Asset, error) {
			es, err := st.Edges(ctx, 2)
			if err != nil {
				return model.Asset{}, err
			}
			return es[0].Other, nil
		},
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			st := fakestore.New()
			removed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			st.Assets[1] = model.Asset{
				ID: 1, Kind: model.KindIP, Key: "93.184.216.34", Source: "cf", RemovedAt: &removed,
				Attrs:     map[string]any{"nested": map[string]any{"list": []any{map[string]any{"value": "canonical"}}}},
				Reporters: []string{"aws", "cf"},
				SourceFacts: map[string]model.SourceFact{
					"aws": {Zone: "aws.example.com", Attrs: map[string]any{
						"nested": map[string]any{"value": "aws"}, "list": []any{map[string]any{"value": "aws"}},
						"strings": []string{"aws"}, "tags": map[string]string{"value": "aws"},
						"typed": map[string][]map[string]any{"entries": {{"value": "aws"}}},
					}},
					"cf": {Attrs: map[string]any{"origin": true}},
				},
			}
			st.Rels = []model.Relation{{FromID: 2, ToID: 1, Type: model.RelResolvesTo}}
			before, err := read(st)
			if err != nil {
				t.Fatal(err)
			}
			a, err := read(st)
			if err != nil {
				t.Fatal(err)
			}
			a.Attrs["nested"].(map[string]any)["list"].([]any)[0].(map[string]any)["value"] = "changed"
			a.Reporters[0] = "changed"
			a.SourceFacts["aws"].Attrs["nested"].(map[string]any)["value"] = "changed"
			a.SourceFacts["aws"].Attrs["list"].([]any)[0].(map[string]any)["value"] = "changed"
			a.SourceFacts["aws"].Attrs["strings"].([]string)[0] = "changed"
			a.SourceFacts["aws"].Attrs["tags"].(map[string]string)["value"] = "changed"
			a.SourceFacts["aws"].Attrs["typed"].(map[string][]map[string]any)["entries"][0]["value"] = "changed"
			delete(a.SourceFacts, "cf")
			*a.RemovedAt = removed.Add(time.Hour)
			after, err := read(st)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("read result changed stored facts: before=%v after=%v", before, after)
			}
		})
	}
}

func TestRetirementRefusesChangedSourceFacts(t *testing.T) {
	ctx := context.Background()
	for name, update := range map[string]func(*model.Asset){
		"zone":      func(a *model.Asset) { a.Zone = "other.example.com" },
		"reporters": func(a *model.Asset) { a.Reporters = append(a.Reporters, "aws") },
		"facts":     func(a *model.Asset) { a.SourceFacts["cf"].Attrs["origin"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			st := fakestore.New()
			st.Assets[1] = model.Asset{
				ID: 1, Kind: model.KindIP, Key: "93.184.216.34", Source: "cf", Scope: model.ScopeOwned,
				Reporters: []string{"cf"}, SourceFacts: map[string]model.SourceFact{"cf": {Attrs: map[string]any{"origin": false}}},
			}
			st.Findings[1] = model.Finding{ID: 1, AssetID: 1, Check: "origin.exposed", Status: model.StatusOpen}
			before, err := st.GetAsset(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			st.Do(func(st *fakestore.Store) {
				a := st.Assets[1]
				update(&a)
				st.Assets[1] = a
			})
			n, err := st.ResolveInapplicableFindings(ctx, *before, "origin.exposed", time.Now())
			if err != nil || n != 0 || st.Findings[1].Status != model.StatusOpen || len(st.Events) != 0 {
				t.Fatalf("stale facts retired finding: resolved=%d status=%s events=%d err=%v", n, st.Findings[1].Status, len(st.Events), err)
			}
		})
	}
}
