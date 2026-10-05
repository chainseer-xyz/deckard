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
	ingest      map[ingestKey]*ingestState
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
	a = cloneAsset(a)
	return &a, nil
}

func (s *Store) GetAssetByKey(_ context.Context, kind model.AssetKind, key string) (*model.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.Assets {
		if a.Kind == kind && a.Key == key {
			a = cloneAsset(a)
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
		if f.Kind != "" && a.Kind != f.Kind || f.Source != "" && !assetHasSource(a, f.Source) ||
			f.Scope != "" && a.Scope != f.Scope || f.Zone != "" && a.Zone != f.Zone ||
			f.Query != "" && !strings.Contains(a.Key, f.Query) ||
			!f.IncludeRemoved && a.RemovedAt != nil {
			continue
		}
		if f.OpenMinSeverity != "" {
			matches := false
			for _, finding := range s.Findings {
				matches = matches || finding.AssetID == a.ID && finding.Status == model.StatusOpen && finding.Severity.AtLeast(f.OpenMinSeverity)
			}
			if !matches {
				continue
			}
		}
		out = append(out, cloneAsset(a))
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
			out = append(out, store.Edge{Other: cloneAsset(s.Assets[r.ToID]), Type: r.Type, Outbound: true})
		case r.ToID:
			out = append(out, store.Edge{Other: cloneAsset(s.Assets[r.FromID]), Type: r.Type})
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
	a, ok := s.Assets[in.AssetID]
	if !ok {
		return store.ReconcileResult{}, store.ErrNotFound
	}
	var ids []int64
	for id, f := range s.Findings {
		if f.AssetID == in.AssetID && f.Check == in.Check {
			ids = append(ids, id)
		}
	}
	items := make([]item, 0, len(in.Findings))
	for _, fi := range in.Findings {
		items = append(items, item{fp: model.Fingerprint(in.Check, a.Key, fi.Key), asset: a, fi: fi})
	}
	res, _, _ := s.reconcileLocked(set{check: in.Check, ids: ids, items: items, partial: in.PartialRun, resolveAfter: in.ResolveAfter, now: in.Now})
	return res, nil
}

type item struct {
	fp    string
	asset model.Asset
	fi    model.FindingInput
}

type set struct {
	check        string
	ids          []int64 // the reconciliation set's existing findings
	items        []item
	partial      bool
	resolveAfter int
	now          time.Time
	ingestScope  string
	source       string // finding source override ("" = the asset's)
}

// reconcileLocked mirrors the postgres reconcileTx. It returns the result plus
// the refreshed and pending counts. s.mu must be held.
func (s *Store) reconcileLocked(in set) (store.ReconcileResult, int, int) {
	var res store.ReconcileResult
	refreshed, pending := 0, 0
	resolveAfter := in.resolveAfter
	if resolveAfter < 1 {
		resolveAfter = 1
	}
	sort.Slice(in.ids, func(i, j int) bool { return in.ids[i] < in.ids[j] })
	existing := map[string]int64{}
	for _, id := range in.ids {
		existing[s.Findings[id].Fingerprint] = id
	}
	var order []string
	byFP := map[string]item{}
	for _, it := range in.items {
		if _, dup := byFP[it.fp]; !dup {
			order = append(order, it.fp)
		}
		byFP[it.fp] = it // last duplicate wins
	}
	var next int64 = 1
	for k := range s.Findings {
		if k >= next {
			next = k + 1
		}
	}
	present := map[string]bool{}
	for _, fp := range order {
		it, fi, a := byFP[fp], byFP[fp].fi, byFP[fp].asset
		present[fp] = true
		source := a.Source
		if in.source != "" {
			source = in.source
		}
		id, found := existing[fp]
		if !found {
			f := model.Finding{
				ID: next, Fingerprint: fp, Check: in.check, AssetID: a.ID, AssetKey: a.Key, Zone: a.Zone, Source: source,
				Severity: fi.Severity, Title: fi.Title, Description: fi.Description, Evidence: fi.Evidence,
				Remediation: fi.Remediation, Tags: fi.Tags, Status: model.StatusOpen, FirstSeen: in.now, LastSeen: in.now,
				IngestScope: in.ingestScope,
			}
			s.Findings[next] = f
			next++
			res.Opened = append(res.Opened, f)
			continue
		}
		refreshed++
		f := s.Findings[id]
		wasResolved := f.Status == model.StatusResolved
		wasOpen := f.Status == model.StatusOpen
		f.Severity, f.Title, f.Description, f.Evidence = fi.Severity, fi.Title, fi.Description, fi.Evidence
		f.Remediation, f.Tags, f.LastSeen, f.MissedRuns = fi.Remediation, fi.Tags, in.now, 0
		f.AssetID, f.AssetKey, f.Zone = it.asset.ID, it.asset.Key, it.asset.Zone
		if in.source == "" {
			f.Source = a.Source
		}
		if wasResolved {
			f.Status, f.ResolvedAt = model.StatusOpen, nil
			f.ReopenedCount++
		}
		s.Findings[id] = f
		switch {
		case wasResolved:
			res.Reopened = append(res.Reopened, f)
		case wasOpen:
			res.Updated = append(res.Updated, f)
		}
	}
	if in.partial {
		return res, refreshed, pending
	}
	for _, id := range in.ids {
		f := s.Findings[id]
		if present[f.Fingerprint] || f.Status == model.StatusResolved {
			continue
		}
		f.MissedRuns++
		if f.MissedRuns >= resolveAfter {
			now := in.now
			f.Status, f.ResolvedAt, f.SuppressedUntil = model.StatusResolved, &now, nil
			res.Resolved = append(res.Resolved, f)
		} else {
			pending++
		}
		s.Findings[id] = f
	}
	return res, refreshed, pending
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
		if f.MinSeverity != "" && !x.Severity.AtLeast(f.MinSeverity) || f.Severity != "" && x.Severity != f.Severity || f.Check != "" && x.Check != f.Check ||
			f.Zone != "" && x.Zone != f.Zone || f.Source != "" && x.Source != f.Source ||
			f.AssetID != 0 && x.AssetID != f.AssetID ||
			f.Query != "" && !strings.Contains(x.Title+" "+x.AssetKey, f.Query) {
			continue
		}
		if f.GroupKey != nil && findingGroupKey(x, f.GroupBy) != *f.GroupKey ||
			f.AttentionOnly && (x.Status != model.StatusOpen || !x.Severity.AtLeast(model.SeverityHigh) && !findingKEV(x)) ||
			!f.FirstSeenAfter.IsZero() && x.FirstSeen.Before(f.FirstSeenAfter) {
			continue
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return findingLess(out[i], out[j], f) })
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
		if r.Settled() && r.StartedAt.After(l.LastSuccess) {
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

// ListEvents returns events at or after since, newest first.
func (s *Store) ListEvents(_ context.Context, since time.Time, limit int) ([]store.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventsCalls++
	if s.EventsErr != nil {
		return nil, s.EventsErr
	}
	var out []store.Event
	for _, e := range s.Events {
		if !e.At.Before(since) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].ID > out[j].ID
	})
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
