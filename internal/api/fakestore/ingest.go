package fakestore

import (
	"context"
	"fmt"
	"sort"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// ingestState mirrors the postgres ingest_scopes row of one (tool, scope).
type ingestState struct {
	sc     store.IngestScope
	digest string
}

type ingestKey struct{ tool, scope string }

// IngestFindings is the in-memory version of the postgres ingest; the
// storetest ingest contract runs against both.
func (s *Store) IngestFindings(_ context.Context, in store.IngestInput) (store.IngestResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ingest == nil {
		s.ingest = map[ingestKey]*ingestState{}
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = in.Now
	}
	var res store.IngestResult
	st := s.ingest[ingestKey{in.Tool, in.Scope}]
	if st != nil && in.Digest != "" && in.Digest == st.digest {
		res.Replay = true
		return res, nil
	}
	complete := in.Complete
	if complete && st != nil && !in.ObservedAt.After(st.sc.ObservedAt) {
		complete, res.NotCompleteReason = false, "observed_at is not after the newest run already accepted for this tool and scope"
	}

	// One pass per asset, like postgres: create or claim it when any item
	// names it without ref, then check ref items against the result.
	type akey struct {
		kind model.AssetKind
		key  string
	}
	groups := map[akey][]store.IngestItem{}
	create := map[akey]bool{}
	for _, it := range in.Items {
		k := akey{it.AssetKind, it.AssetKey}
		groups[k] = append(groups[k], it)
		create[k] = create[k] || !it.Ref
	}
	assets := map[int]model.Asset{}
	for k, its := range groups {
		var a model.Asset
		found := true
		if create[k] {
			a = s.claimLocked(in, k.kind, k.key)
		} else {
			a, found = s.assetByKeyLocked(k.kind, k.key)
		}
		for _, it := range its {
			if reason := refProblem(it, a, found); reason != "" {
				res.Rejected = append(res.Rejected, store.IngestRejection{Index: it.Index, Reason: reason})
				continue
			}
			assets[it.Index] = a
		}
	}
	sort.Slice(res.Rejected, func(i, j int) bool { return res.Rejected[i].Index < res.Rejected[j].Index })
	if complete && len(res.Rejected) > 0 {
		complete, res.NotCompleteReason = false, fmt.Sprintf("%d item(s) rejected", len(res.Rejected))
	}
	res.Complete = complete

	var ids []int64
	for id, f := range s.Findings {
		if f.Check == in.Check && f.IngestScope == in.Scope {
			ids = append(ids, id)
		}
	}
	items := make([]item, 0, len(in.Items))
	for _, it := range in.Items {
		a, ok := assets[it.Index]
		if !ok {
			continue
		}
		items = append(items, item{fp: model.Fingerprint(in.Check, in.Scope, it.Finding.Key), asset: a, fi: it.Finding})
	}
	res.ReconcileResult, res.Refreshed, res.Pending = s.reconcileLocked(set{
		check: in.Check, ids: ids, items: items, partial: !complete, resolveAfter: in.ResolveAfter,
		now: in.Now, ingestScope: in.Scope, source: in.Source,
	})

	if st == nil {
		st = &ingestState{sc: store.IngestScope{Tool: in.Tool, Scope: in.Scope, CreatedAt: in.Now, ObservedAt: in.ObservedAt}}
		s.ingest[ingestKey{in.Tool, in.Scope}] = st
	}
	st.sc.LastAt = in.Now
	if complete {
		st.sc.CompleteAt = in.Now
	}
	if in.ObservedAt.After(st.sc.ObservedAt) {
		st.sc.ObservedAt = in.ObservedAt
	}
	st.digest = in.Digest
	return res, nil
}

// refProblem mirrors the postgres rule: a ref item needs an existing, live,
// owned asset.
func refProblem(it store.IngestItem, a model.Asset, found bool) string {
	switch {
	case !it.Ref:
		return ""
	case !found:
		return "asset.ref: no such asset"
	case a.RemovedAt != nil:
		return "asset.ref: asset is removed from the inventory"
	case a.Scope != model.ScopeOwned:
		return "asset.ref: asset is not owned"
	}
	return ""
}

func (s *Store) assetByKeyLocked(kind model.AssetKind, key string) (model.Asset, bool) {
	for _, a := range s.Assets {
		if a.Kind == kind && a.Key == key {
			return a, true
		}
	}
	return model.Asset{}, false
}

// claimLocked returns the asset (kind, key) for a non-ref item, creating,
// reviving or refreshing it like the postgres ingest does.
func (s *Store) claimLocked(in store.IngestInput, kind model.AssetKind, key string) model.Asset {
	a, found := s.assetByKeyLocked(kind, key)
	switch {
	case !found:
		var next int64 = 1
		for id := range s.Assets {
			if id >= next {
				next = id + 1
			}
		}
		a = model.Asset{ID: next, Kind: kind, Key: key, Source: in.Source, Scope: in.AssetScope, FirstSeen: in.Now, LastSeen: in.Now}
	case a.RemovedAt != nil:
		a.Source, a.Scope, a.LastSeen, a.RemovedAt = in.Source, in.AssetScope, in.Now, nil
	case a.Source == in.Source:
		a.Scope, a.LastSeen = in.AssetScope, in.Now
	default:
		return a // another source's live asset: attach untouched
	}
	s.Assets[a.ID] = a
	return a
}

// ListIngestScopes implements store.Store.
func (s *Store) ListIngestScopes(context.Context) ([]store.IngestScope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.IngestScope, 0, len(s.ingest))
	for _, st := range s.ingest {
		sc := st.sc
		sc.Open = 0
		for _, f := range s.Findings {
			a := s.Assets[f.AssetID]
			if f.Check == model.IngestCheck(sc.Tool) && f.IngestScope == sc.Scope && f.Status == model.StatusOpen && a.RemovedAt == nil {
				sc.Open++
			}
		}
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Scope < out[j].Scope
	})
	return out, nil
}
