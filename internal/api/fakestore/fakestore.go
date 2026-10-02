// Package fakestore is a small in-memory store.Store for tests. It implements
// just enough filtering and lifecycle behaviour for API and metrics tests; it
// is not a substitute for the storetest contract suite.
package fakestore

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Store is an in-memory store.Store.
type Store struct {
	mu sync.Mutex

	PingErr   error
	StatsErr  error
	EventsErr error
	Assets    map[int64]model.Asset
	Rels      []model.Relation
	Obs       map[int64][]model.Observation
	Bases     map[int64][]store.Baseline
	Findings  map[int64]model.Finding
	Syncs     []store.SyncStatus
	Scans     []store.ScanRun
	Events    []store.Event
	StatsVal  store.Stats

	// Changes records every ChangeFindingStatus call for assertions.
	Changes []Change

	statsCalls  int
	eventsCalls int
}

// Change is a recorded ChangeFindingStatus call.
type Change struct {
	ID int64
	store.StatusChange
}

var _ store.Store = (*Store)(nil)

// New returns an empty store.
func New() *Store {
	return &Store{
		Assets:   map[int64]model.Asset{},
		Obs:      map[int64][]model.Observation{},
		Bases:    map[int64][]store.Baseline{},
		Findings: map[int64]model.Finding{},
	}
}

// StatsCalls reports how many times Stats was called.
func (s *Store) StatsCalls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.statsCalls }

// EventsCalls reports how many times ListEvents was called.
func (s *Store) EventsCalls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.eventsCalls }

// Do runs fn with the store locked, for test setup that mutates fields.
func (s *Store) Do(fn func(*Store)) { s.mu.Lock(); defer s.mu.Unlock(); fn(s) }

func (s *Store) Migrate(context.Context) error { return nil }
func (s *Store) Close()                        {}

func (s *Store) Ping(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.PingErr
}

func (s *Store) ApplySnapshot(context.Context, string, []store.AssetUpsert, []model.RelationInput, time.Time) (store.InventoryDiff, error) {
	return store.InventoryDiff{}, nil
}

func (s *Store) UpsertSnapshot(context.Context, string, []store.AssetUpsert, []model.RelationInput, time.Time) (store.InventoryDiff, error) {
	return store.InventoryDiff{}, nil
}

func (s *Store) AddDiscovered(context.Context, []store.AssetUpsert, []model.RelationInput, time.Time) (store.InventoryDiff, error) {
	return store.InventoryDiff{}, nil
}

func (s *Store) ReplaceDerived(context.Context, int64, string, []store.AssetUpsert, []model.RelationInput, time.Time) (store.InventoryDiff, error) {
	return store.InventoryDiff{}, nil
}

func (s *Store) PruneRelations(context.Context, time.Time) (int, error) { return 0, nil }

func (s *Store) GetAsset(_ context.Context, id int64) (*model.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Assets[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &a, nil
}

func (s *Store) GetAssetByKey(_ context.Context, kind model.AssetKind, key string) (*model.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.Assets {
		if a.Kind == kind && a.Key == key {
			return &a, nil
		}
	}
	return nil, store.ErrNotFound
}

func page(n, limit, offset int) (int, int) {
	if offset > n {
		offset = n
	}
	end := n
	if limit > 0 && offset+limit < n {
		end = offset + limit
	}
	return offset, end
}

func (s *Store) ListAssets(_ context.Context, f store.AssetFilter) ([]model.Asset, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Asset
	for _, a := range s.Assets {
		if f.Kind != "" && a.Kind != f.Kind || f.Source != "" && a.Source != f.Source ||
			f.Scope != "" && a.Scope != f.Scope || f.Zone != "" && a.Zone != f.Zone ||
			f.Query != "" && !strings.Contains(a.Key, f.Query) ||
			!f.IncludeRemoved && a.RemovedAt != nil {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	lo, hi := page(len(out), f.Limit, f.Offset)
	return out[lo:hi], len(out), nil
}

func (s *Store) Edges(_ context.Context, id int64) ([]store.Edge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Edge
	for _, r := range s.Rels {
		switch id {
		case r.FromID:
			out = append(out, store.Edge{Other: s.Assets[r.ToID], Type: r.Type, Outbound: true})
		case r.ToID:
			out = append(out, store.Edge{Other: s.Assets[r.FromID], Type: r.Type})
		}
	}
	return out, nil
}

func (s *Store) SaveObservation(_ context.Context, id int64, o model.ObservationInput, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Obs[id] = append(s.Obs[id], model.Observation{AssetID: id, Check: o.Check, Data: o.Data, ObservedAt: now})
	return nil
}

func (s *Store) LatestObservations(_ context.Context, id int64) ([]model.Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.Observation(nil), s.Obs[id]...), nil
}

func (s *Store) GetBaseline(_ context.Context, id int64, check string) (*store.Baseline, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.Bases[id] {
		if b.Check == check {
			return &b, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) SaveBaseline(_ context.Context, b store.Baseline) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Bases[b.AssetID] = append(s.Bases[b.AssetID], b)
	return nil
}

// ReconcileFindings is a compact in-memory version of the postgres lifecycle:
// open/reopen/refresh what the run reports and, unless the run is partial,
// count misses and resolve. A PartialRun never counts misses or resolves.
func (s *Store) ReconcileFindings(_ context.Context, in store.ReconcileInput) (store.ReconcileResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res store.ReconcileResult
	a, ok := s.Assets[in.AssetID]
	if !ok {
		return res, store.ErrNotFound
	}
	resolveAfter := in.ResolveAfter
	if resolveAfter < 1 {
		resolveAfter = 1
	}
	existing := map[string]int64{}
	var ids []int64
	for id, f := range s.Findings {
		if f.AssetID == in.AssetID && f.Check == in.Check {
			existing[f.Fingerprint] = id
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	present := map[string]bool{}
	for _, fi := range in.Findings {
		fp := model.Fingerprint(in.Check, a.Key, fi.Key)
		present[fp] = true
		id, found := existing[fp]
		if !found {
			var next int64 = 1
			for k := range s.Findings {
				if k >= next {
					next = k + 1
				}
			}
			f := model.Finding{
				ID: next, Fingerprint: fp, Check: in.Check, AssetID: a.ID, AssetKey: a.Key, Zone: a.Zone, Source: a.Source,
				Severity: fi.Severity, Title: fi.Title, Description: fi.Description, Evidence: fi.Evidence,
				Remediation: fi.Remediation, Tags: fi.Tags, Status: model.StatusOpen, FirstSeen: in.Now, LastSeen: in.Now,
			}
			s.Findings[next] = f
			existing[fp] = next
			res.Opened = append(res.Opened, f)
			continue
		}
		f := s.Findings[id]
		wasResolved := f.Status == model.StatusResolved
		f.Severity, f.Title, f.Description, f.Evidence = fi.Severity, fi.Title, fi.Description, fi.Evidence
		f.Remediation, f.Tags, f.LastSeen, f.MissedRuns = fi.Remediation, fi.Tags, in.Now, 0
		if wasResolved {
			f.Status, f.ResolvedAt = model.StatusOpen, nil
			f.ReopenedCount++
		}
		s.Findings[id] = f
		switch {
		case wasResolved:
			res.Reopened = append(res.Reopened, f)
		case f.Status == model.StatusOpen:
			res.Updated = append(res.Updated, f)
		}
	}
	if in.PartialRun {
		return res, nil
	}
	for _, id := range ids {
		f := s.Findings[id]
		if present[f.Fingerprint] || f.Status == model.StatusResolved {
			continue
		}
		f.MissedRuns++
		if f.MissedRuns >= resolveAfter {
			now := in.Now
			f.Status, f.ResolvedAt, f.SuppressedUntil = model.StatusResolved, &now, nil
			res.Resolved = append(res.Resolved, f)
		}
		s.Findings[id] = f
	}
	return res, nil
}

func (s *Store) GetFinding(_ context.Context, id int64) (*model.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.Findings[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &f, nil
}

func (s *Store) ListFindings(_ context.Context, f store.FindingFilter) ([]model.Finding, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Finding
	for _, x := range s.Findings {
		if len(f.Statuses) > 0 {
			ok := false
			for _, st := range f.Statuses {
				ok = ok || st == x.Status
			}
			if !ok {
				continue
			}
		}
		if f.MinSeverity != "" && !x.Severity.AtLeast(f.MinSeverity) || f.Check != "" && x.Check != f.Check ||
			f.Zone != "" && x.Zone != f.Zone || f.Source != "" && x.Source != f.Source ||
			f.AssetID != 0 && x.AssetID != f.AssetID ||
			f.Query != "" && !strings.Contains(x.Title+" "+x.AssetKey, f.Query) {
			continue
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	lo, hi := page(len(out), f.Limit, f.Offset)
	return out[lo:hi], len(out), nil
}

func (s *Store) ChangeFindingStatus(_ context.Context, id int64, c store.StatusChange, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.Findings[id]
	if !ok {
		return store.ErrNotFound
	}
	f.Status = c.Status
	f.SuppressedUntil = c.Until
	f.SuppressionNote = c.Note
	s.Findings[id] = f
	s.Changes = append(s.Changes, Change{ID: id, StatusChange: c})
	return nil
}

func (s *Store) ExpireSuppressions(context.Context, time.Time) (int, error) { return 0, nil }

func (s *Store) ResolvedSince(context.Context, time.Time) ([]model.Finding, error) { return nil, nil }

func (s *Store) RecordSync(_ context.Context, st store.SyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Syncs = append(s.Syncs, st)
	return nil
}

func (s *Store) ListSyncs(context.Context) ([]store.SyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.SyncStatus(nil), s.Syncs...), nil
}

func (s *Store) RecordScan(_ context.Context, r store.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Scans = append(s.Scans, r)
	return nil
}

func (s *Store) ListScans(_ context.Context, limit int) ([]store.ScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]store.ScanRun(nil), s.Scans...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) LastScans(context.Context) ([]store.ScanLast, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type k struct {
		asset int64
		check string
	}
	m := map[k]*store.ScanLast{}
	var order []k
	for _, r := range s.Scans {
		key := k{r.AssetID, r.Check}
		l := m[key]
		if l == nil {
			l = &store.ScanLast{AssetID: r.AssetID, Check: r.Check}
			m[key] = l
			order = append(order, key)
		}
		if r.StartedAt.After(l.LastAttempt) {
			l.LastAttempt = r.StartedAt
		}
		if r.Error == "" && r.StartedAt.After(l.LastSuccess) {
			l.LastSuccess = r.StartedAt
		}
	}
	out := make([]store.ScanLast, 0, len(order))
	for _, key := range order {
		out = append(out, *m[key])
	}
	return out, nil
}

func (s *Store) PruneScans(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.Scans[:0:0]
	for _, r := range s.Scans {
		if !r.StartedAt.Before(olderThan) {
			kept = append(kept, r)
		}
	}
	n := len(s.Scans) - len(kept)
	s.Scans = kept
	return n, nil
}

// ListEvents returns events strictly newer than since, oldest first.
func (s *Store) ListEvents(_ context.Context, since time.Time, limit int) ([]store.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventsCalls++
	if s.EventsErr != nil {
		return nil, s.EventsErr
	}
	var out []store.Event
	for _, e := range s.Events {
		if e.At.After(since) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) Stats(context.Context) (store.Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statsCalls++
	return s.StatsVal, s.StatsErr
}
