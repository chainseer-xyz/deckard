package fakestore

import (
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/storetest"
)

// seed is a minimal ApplySnapshot for the ingest contract: it upserts the
// source's assets and marks its other assets removed (resolving their open
// findings, as the postgres store does).
func seed(t *testing.T, st store.Store, source string, assets []store.AssetUpsert, now time.Time) {
	t.Helper()
	s := st.(*Store)
	s.Do(func(s *Store) {
		seen := map[int64]bool{}
		for _, in := range assets {
			a, found := s.assetByKeyLocked(in.Kind, in.Key)
			if !found {
				var next int64 = 1
				for id := range s.Assets {
					if id >= next {
						next = id + 1
					}
				}
				a = model.Asset{ID: next, Kind: in.Kind, Key: in.Key, Source: source, FirstSeen: now}
			}
			a.Scope, a.Attrs, a.LastSeen, a.RemovedAt = in.Scope, in.Attrs, now, nil
			s.Assets[a.ID] = a
			seen[a.ID] = true
		}
		for id, a := range s.Assets {
			if a.Source != source || seen[id] || a.RemovedAt != nil {
				continue
			}
			removed := now
			a.RemovedAt = &removed
			s.Assets[id] = a
			for fid, f := range s.Findings {
				if f.AssetID == id && (f.Status == model.StatusOpen || f.Status == model.StatusAcknowledged) {
					f.Status, f.ResolvedAt = model.StatusResolved, &removed
					s.Findings[fid] = f
				}
			}
		}
	})
}

func TestIngestContract(t *testing.T) {
	storetest.RunIngest(t, func(*testing.T) store.Store { return New() }, seed)
}
