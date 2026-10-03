package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// ---- store ----

type fakeStore struct {
	mu        sync.Mutex
	assets    map[int64]model.Asset
	edges     map[int64][]store.Edge
	baselines map[ScanKey]*store.Baseline
	scans     []store.ScanRun
	expired   int
	failGet   error

	findings     []model.Finding
	findingsErr  error
	findingsReqs []store.FindingFilter

	prunedScans []time.Time
	prunedRels  []time.Time
	pruneErr    error
}

func newFakeStore(as ...model.Asset) *fakeStore {
	s := &fakeStore{assets: map[int64]model.Asset{}, edges: map[int64][]store.Edge{}, baselines: map[ScanKey]*store.Baseline{}}
	for _, a := range as {
		s.assets[a.ID] = a
	}
	return s
}

func (s *fakeStore) GetAsset(_ context.Context, id int64) (*model.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failGet != nil {
		return nil, s.failGet
	}
	a, ok := s.assets[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &a, nil
}

func (s *fakeStore) ListAssets(_ context.Context, f store.AssetFilter) ([]model.Asset, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Asset
	for _, a := range s.assets {
		if a.RemovedAt != nil && !f.IncludeRemoved {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, len(out), nil
}

func (s *fakeStore) Edges(_ context.Context, id int64) ([]store.Edge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.edges[id], nil
}

func (s *fakeStore) GetBaseline(_ context.Context, id int64, c string) (*store.Baseline, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.baselines[ScanKey{id, c}]; ok {
		return b, nil
	}
	return nil, store.ErrNotFound
}

func (s *fakeStore) ListFindings(_ context.Context, f store.FindingFilter) ([]model.Finding, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findingsReqs = append(s.findingsReqs, f)
	if s.findingsErr != nil {
		return nil, 0, s.findingsErr
	}
	var out []model.Finding
	for _, x := range s.findings {
		if f.AssetID != 0 && x.AssetID != f.AssetID || f.Check != "" && x.Check != f.Check {
			continue
		}
		if len(f.Statuses) > 0 && !slices.Contains(f.Statuses, x.Status) {
			continue
		}
		out = append(out, x)
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, len(out), nil
}

// LastScans derives one row per (asset, check) from the recorded runs: a
// settled run (store.ScanRun.Settled) counts as a success.
func (s *fakeStore) LastScans(context.Context) ([]store.ScanLast, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[ScanKey]*store.ScanLast{}
	for _, r := range s.scans {
		k := ScanKey{r.AssetID, r.Check}
		l := m[k]
		if l == nil {
			l = &store.ScanLast{AssetID: r.AssetID, Check: r.Check}
			m[k] = l
		}
		if r.StartedAt.After(l.LastAttempt) {
			l.LastAttempt = r.StartedAt
		}
		if r.Settled() && r.StartedAt.After(l.LastSuccess) {
			l.LastSuccess = r.StartedAt
		}
	}
	var out []store.ScanLast
	for _, l := range m {
		out = append(out, *l)
	}
	return out, nil
}

func (s *fakeStore) PruneScans(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunedScans = append(s.prunedScans, olderThan)
	return 0, s.pruneErr
}

func (s *fakeStore) PruneRelations(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunedRels = append(s.prunedRels, olderThan)
	return 0, nil
}

func (s *fakeStore) RecordScan(_ context.Context, r store.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans = append(s.scans, r)
	return nil
}

func (s *fakeStore) ExpireSuppressions(context.Context, time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expired++
	return 0, nil
}

func (s *fakeStore) runs() []store.ScanRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.ScanRun(nil), s.scans...)
}

// ---- guard ----

type fakeGuard struct {
	mu      sync.Mutex
	classes map[string]model.ScopeClass // by key; default owned
	built   atomic.Int64                // dialer/resolver/http constructions
	tiers   []model.Tier
	gotCls  []model.ScopeClass
}

func (g *fakeGuard) Classify(_ model.AssetKind, key string) model.ScopeClass {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.classes[key]; ok {
		return c
	}
	return model.ScopeOwned
}

func (g *fakeGuard) note(t model.Tier, c model.ScopeClass) {
	g.built.Add(1)
	g.mu.Lock()
	g.tiers = append(g.tiers, t)
	g.gotCls = append(g.gotCls, c)
	g.mu.Unlock()
}

func (g *fakeGuard) Dialer(t model.Tier, c model.ScopeClass, _ scope.RateLimiter) check.Dialer {
	g.note(t, c)
	return nil
}
func (g *fakeGuard) Resolver(t model.Tier, c model.ScopeClass, _ scope.RateLimiter) check.Resolver {
	g.note(t, c)
	return nil
}
func (g *fakeGuard) HTTPClient(t model.Tier, c model.ScopeClass, _ scope.RateLimiter, _ ...scope.HTTPOption) *http.Client {
	g.note(t, c)
	return &http.Client{}
}

// ---- checks ----

// wantsCheck is a fakeCheck that asks for Target.OpenFindings.
type wantsCheck struct{ *fakeCheck }

func (wantsCheck) WantsOpenFindings() bool { return true }

type fakeCheck struct {
	name    string
	tier    model.Tier
	applies func(model.Asset) bool
	run     func(ctx context.Context, t check.Target) (*check.Result, error)

	calls   atomic.Int64
	mu      sync.Mutex
	targets []check.Target
}

func (c *fakeCheck) Name() string     { return c.name }
func (c *fakeCheck) Tier() model.Tier { return c.tier }
func (c *fakeCheck) Applies(a model.Asset) bool {
	if c.applies == nil {
		return true
	}
	return c.applies(a)
}
func (c *fakeCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	c.calls.Add(1)
	c.mu.Lock()
	c.targets = append(c.targets, t)
	c.mu.Unlock()
	if c.run != nil {
		return c.run(ctx, t)
	}
	return &check.Result{}, nil
}

// ---- inventory / findings / recorder ----

type fakeInv struct {
	mu        sync.Mutex
	syncDiff  store.InventoryDiff
	syncErr   error
	discDiff  store.InventoryDiff
	discErr   error
	synced    []string
	discOrig  []string
	discAsset [][]model.AssetInput
	repl      []replCall

	onDiscovered func()
}

// selectiveInv fails Sync for one named source.
type selectiveInv struct {
	*fakeInv
	failFor string
}

func (s *selectiveInv) Sync(ctx context.Context, src source.Source) (store.InventoryDiff, error) {
	if src.Name() == s.failFor {
		return store.InventoryDiff{}, errors.New("source down")
	}
	return s.fakeInv.Sync(ctx, src)
}

func (f *fakeInv) Sync(_ context.Context, s source.Source) (store.InventoryDiff, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced = append(f.synced, s.Name())
	return f.syncDiff, f.syncErr
}

func (f *fakeInv) AddDiscovered(_ context.Context, origin string, in []model.AssetInput, _ []model.RelationInput) (store.InventoryDiff, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discOrig = append(f.discOrig, origin)
	f.discAsset = append(f.discAsset, in)
	if f.onDiscovered != nil {
		f.onDiscovered()
	}
	return f.discDiff, f.discErr
}

// replCall is one Inventory.ReplaceDerived call.
type replCall struct {
	parent int64
	origin string
	assets []model.AssetInput
	rels   []model.RelationInput
}

func (f *fakeInv) ReplaceDerived(_ context.Context, parent int64, origin string, in []model.AssetInput, rels []model.RelationInput) (store.InventoryDiff, error) {
	f.mu.Lock()
	f.repl = append(f.repl, replCall{parent, origin, in, rels})
	cb := f.onDiscovered
	f.mu.Unlock()
	if cb != nil {
		cb()
	}
	return f.discDiff, f.discErr
}

func (f *fakeInv) replCalls() []replCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]replCall(nil), f.repl...)
}

type procCall struct {
	asset model.Asset
	check string
	res   *check.Result
}

type fakeProc struct {
	mu    sync.Mutex
	calls []procCall
	err   error
}

func (f *fakeProc) Process(_ context.Context, a model.Asset, c string, r *check.Result) (store.ReconcileResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, procCall{a, c, r})
	return store.ReconcileResult{}, f.err
}

type scanObs struct {
	check, tier string
	err         error
}

type fakeRec struct {
	mu      sync.Mutex
	scans   []scanObs
	skips   []string // check|tier|reason
	syncs   map[string][]bool
	changes map[string]int
	depth   map[string]int
	reclaim map[string]int
}

func newFakeRec() *fakeRec {
	return &fakeRec{syncs: map[string][]bool{}, changes: map[string]int{}, depth: map[string]int{}, reclaim: map[string]int{}}
}

func (r *fakeRec) ObserveScan(c, t string, _ time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scans = append(r.scans, scanObs{c, t, err})
}
func (r *fakeRec) ObserveSkip(c, t, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skips = append(r.skips, c+"|"+t+"|"+reason)
}
func (r *fakeRec) ObserveSync(s string, _ time.Duration, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncs[s] = append(r.syncs[s], ok)
}
func (r *fakeRec) InventoryChange(k string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes[k] += n
}
func (r *fakeRec) SetQueueDepth(q string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.depth[q] = n
}
func (r *fakeRec) JobsReclaimed(k string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reclaim[k] += n
}

// ---- sources ----

type fakeSource struct {
	name string
	disc *source.Discovery
	err  error
}

func (s *fakeSource) Name() string { return s.name }
func (s *fakeSource) Type() string { return "static" }
func (s *fakeSource) Discover(context.Context) (*source.Discovery, error) {
	return s.disc, s.err
}

// ---- recording queue ----

type recQueue struct {
	mu    sync.Mutex
	seen  map[string]bool
	scans []scanJob
	syncs []string
	zones []int64
}

func newRecQueue() *recQueue { return &recQueue{seen: map[string]bool{}} }

func (q *recQueue) enqueueScan(_ context.Context, j scanJob) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.seen[j.key()] {
		return false, nil
	}
	q.seen[j.key()] = true
	q.scans = append(q.scans, j)
	return true, nil
}

func (q *recQueue) enqueueSync(_ context.Context, s string) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.syncs = append(q.syncs, s)
	return true, nil
}

func (q *recQueue) enqueueExpand(_ context.Context, id int64, _ time.Duration) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	k := fmt.Sprintf("expand|%d", id)
	if q.seen[k] {
		return false, nil
	}
	q.seen[k] = true
	q.zones = append(q.zones, id)
	return true, nil
}

func (q *recQueue) keys() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []string
	for _, j := range q.scans {
		out = append(out, j.key())
	}
	sort.Strings(out)
	return out
}

// ---- harness ----

type testCfg struct {
	config.Config
	sources []source.Source
}

type harness struct {
	st   *fakeStore
	g    *fakeGuard
	inv  *fakeInv
	proc *fakeProc
	rec  *fakeRec
	q    *recQueue
	r    *runner
	now  time.Time
}

func newHarness(cfg func(*testCfg), assets []model.Asset, checks ...check.Check) *harness {
	h := &harness{
		st: newFakeStore(assets...), g: &fakeGuard{classes: map[string]model.ScopeClass{}},
		inv: &fakeInv{}, proc: &fakeProc{}, rec: newFakeRec(), q: newRecQueue(),
		now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC),
	}
	tc := &testCfg{Config: baseCfg()}
	if cfg != nil {
		cfg(tc)
	}
	d := Deps{Config: tc.Config, Store: h.st, Guard: h.g, Inventory: h.inv, Findings: h.proc,
		Recorder: h.rec, Checks: checks, Sources: tc.sources, Now: func() time.Time { return h.now }}
	h.r = newRunner(d).withQueue(h.q)
	return h
}

func groupWithInterval(name, zone, tier string, iv time.Duration) config.AssetGroup {
	return config.AssetGroup{Name: name, Match: config.GroupMatch{Zones: []string{zone}},
		Profiles: map[string]config.ProfileOverride{tier: {Interval: &iv}}}
}
