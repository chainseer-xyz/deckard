package fakestore

import (
	"context"
	"reflect"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func (s *Store) ResolveInapplicableFindings(_ context.Context, asset model.Asset, check string, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.Assets[asset.ID]
	if !ok || current.RemovedAt != nil || current.Scope != model.ScopeOwned || current.Kind != asset.Kind ||
		current.Key != asset.Key || current.Source != asset.Source || !reflect.DeepEqual(current.Attrs, asset.Attrs) {
		return 0, nil
	}
	n := 0
	for id, f := range s.Findings {
		if f.AssetID != asset.ID || (f.Check != check && f.Check != "drift."+check) || f.Status == model.StatusResolved {
			continue
		}
		f.Status, f.ResolvedAt, f.SuppressedUntil = model.StatusResolved, &now, nil
		s.Findings[id] = f
		s.Events = append(s.Events, store.Event{ID: int64(len(s.Events) + 1), Type: "finding_resolved", Subject: asset.Key,
			Data: map[string]any{"id": f.ID, "check": f.Check, "reason": "no_longer_applicable"}, At: now})
		n++
	}
	return n, nil
}
