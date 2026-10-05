// Package inventory owns the asset inventory: it syncs sources into the store,
// keeps the scope classifier's zone and owned-IP state in step with what the
// sources report, and records what changed.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Classifier is the slice of scope.Guard the inventory needs.
type Classifier interface {
	Classify(kind model.AssetKind, key string) model.ScopeClass
	// ClassifyUnregistered classifies an IP ignoring the prefixes registered
	// through SetOwnedPrefixes.
	ClassifyUnregistered(ip string) model.ScopeClass
	SetZones(zones []string)
	SetOwnedPrefixes(p []netip.Prefix)
}

// ChangeRecorder receives inventory change counts (kind is one of added,
// changed, removed, revived, dropped). Implementations adapt this to metrics.
type ChangeRecorder interface {
	InventoryChange(kind string, n int)
}

// Option configures a Service.
type Option func(*Service)

// WithRecorder installs a ChangeRecorder (nil is allowed).
func WithRecorder(r ChangeRecorder) Option { return func(s *Service) { s.rec = r } }

// WithClock overrides time.Now (tests).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// WithShrinkGuard configures the suspicious-shrink guard: a complete (non
// partial) discovery that would remove more than fraction of a source's live
// assets AND more than minRemoved of them is not applied; its additions are
// kept, nothing is removed and the sync is recorded as an error. fraction <= 0
// disables the guard. The default is DefaultShrinkFraction/DefaultShrinkMin.
func WithShrinkGuard(fraction float64, minRemoved int) Option {
	return func(s *Service) { s.shrinkFrac, s.shrinkMin = fraction, minRemoved }
}

// Defaults for the shrink guard.
const (
	DefaultShrinkFraction = 0.5
	DefaultShrinkMin      = 10
)

// ErrSuspiciousShrink is returned (wrapped) by Sync when the removal step was
// refused by the shrink guard. The returned diff still holds what was added or
// changed.
var ErrSuspiciousShrink = errors.New("suspicious shrink")

// Service syncs sources into the store and maintains classification state.
type Service struct {
	st  store.Store
	cls Classifier
	log *slog.Logger
	rec ChangeRecorder
	now func() time.Time

	shrinkFrac float64
	shrinkMin  int

	// syncMu lets Syncs run concurrently (RLock) while Rehydrate, which
	// replaces every source's bookkeeping from the database, runs alone.
	syncMu sync.RWMutex

	mu       sync.Mutex
	zones    map[string][]string       // per-source zone sets
	prefixes map[string][]netip.Prefix // per-source owned-IP registrations
}

// New builds a Service.
func New(st store.Store, cls Classifier, log *slog.Logger, opts ...Option) *Service {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		st: st, cls: cls, log: log, now: time.Now,
		shrinkFrac: DefaultShrinkFraction, shrinkMin: DefaultShrinkMin,
		zones: map[string][]string{}, prefixes: map[string][]netip.Prefix{},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Sync discovers from one source, classifies, applies the snapshot, records
// SyncStatus and returns the diff. On any failure nothing is removed: the
// store is untouched and the previous classification state is restored.
//
// Removal of unseen assets is skipped (assets are still upserted) when the
// discovery is Partial, recorded as a SyncStatus warning, and when the
// shrink guard trips, recorded as a SyncStatus error and returned wrapped in
// ErrSuspiciousShrink together with the diff of what was applied. In both
// cases the classifier retains previous zones and unreported IP claims. A
// present IP's current ownership evidence replaces its previous claim.
func (s *Service) Sync(ctx context.Context, src source.Source) (store.InventoryDiff, error) {
	s.syncMu.RLock()
	defer s.syncMu.RUnlock()
	start := s.now()
	name := src.Name()
	fail := func(err error) (store.InventoryDiff, error) {
		if ctx.Err() != nil {
			// Shutting down: not a source failure, don't clobber last status.
			return store.InventoryDiff{}, err
		}
		rerr := s.st.RecordSync(ctx, store.SyncStatus{
			Source: name, Type: src.Type(), LastRun: start, Error: err.Error(),
			DurationMS: s.now().Sub(start).Milliseconds(),
		})
		if rerr != nil {
			s.log.Error("inventory: record sync failure", "source", name, "err", rerr)
		}
		s.log.Warn("inventory: sync failed; assets left untouched", "source", name, "err", err)
		return store.InventoryDiff{}, err
	}

	d, err := src.Discover(ctx)
	if err == nil && d == nil {
		err = errors.New("source returned no discovery")
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return fail(fmt.Errorf("discover %s: %w", name, err))
	}

	// Decide up front whether this snapshot may remove anything.
	removals, refused := true, ""
	if d.Partial {
		removals = false
	} else if s.shrinkFrac > 0 {
		var err error
		if refused, err = s.shrinkVerdict(ctx, name, d.Assets); err != nil {
			return fail(fmt.Errorf("shrink check %s: %w", name, err))
		}
		removals = refused == ""
	}

	// Update classification state first so ApplySnapshot sees final classes.
	zones := normZones(d.Zones)
	pfx := s.acceptPrefixes(src.Type(), d.Assets)
	s.mu.Lock()
	oldZones, hadZones := s.zones[name]
	oldPfx, hadPfx := s.prefixes[name]
	if !removals {
		zones = unionStrings(oldZones, zones)
		pfx = unionPrefixes(unreportedPrefixes(oldPfx, d.Assets), pfx)
	}
	s.zones[name] = zones
	s.cls.SetZones(s.zoneUnionLocked())
	s.prefixes[name] = pfx
	s.cls.SetOwnedPrefixes(s.prefixUnionLocked())
	s.mu.Unlock()

	rollback := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		restore(s.zones, name, oldZones, hadZones)
		restore(s.prefixes, name, oldPfx, hadPfx)
		s.cls.SetZones(s.zoneUnionLocked())
		s.cls.SetOwnedPrefixes(s.prefixUnionLocked())
	}

	ups := s.upserts(name, d.Assets)
	var diff store.InventoryDiff
	if removals {
		diff, err = s.st.ApplySnapshot(ctx, name, ups, d.Relations, s.now())
	} else {
		diff, err = s.st.UpsertSnapshot(ctx, name, ups, d.Relations, s.now())
	}
	if err != nil {
		rollback()
		return fail(fmt.Errorf("apply snapshot %s: %w", name, err))
	}
	s.record(diff)
	end := s.now()
	status := store.SyncStatus{
		Source: name, Type: src.Type(), LastRun: start, LastOK: end,
		AssetCount: len(ups), DurationMS: end.Sub(start).Milliseconds(),
	}
	var retErr error
	switch {
	case refused != "":
		status.LastOK = time.Time{} // keep the previous success time
		status.Error = "suspicious shrink: " + refused
		retErr = fmt.Errorf("%w: %s: %s", ErrSuspiciousShrink, name, refused)
		s.log.Error("inventory: suspicious shrink; removals refused", "source", name, "detail", refused)
	case d.Partial:
		status.Warning = "partial discovery, removals skipped: " + strings.Join(d.PartialReasons, "; ")
		s.log.Warn("inventory: partial discovery; removals skipped", "source", name, "reasons", d.PartialReasons)
	}
	if err := s.st.RecordSync(ctx, status); err != nil {
		s.log.Error("inventory: record sync", "source", name, "err", err)
	}
	return diff, retErr
}

// shrinkVerdict returns a non-empty explanation when applying a complete
// discovery would remove more than the configured share (and count) of the
// source's live assets.
func (s *Service) shrinkVerdict(ctx context.Context, name string, assets []model.AssetInput) (string, error) {
	existing, _, err := s.st.ListAssets(ctx, store.AssetFilter{Source: name})
	if err != nil {
		return "", err
	}
	type key struct {
		kind model.AssetKind
		key  string
	}
	seen := make(map[key]bool, len(assets))
	for _, a := range assets {
		seen[key{a.Kind, a.Key}] = true
	}
	missing := 0
	for _, a := range existing {
		if !seen[key{a.Kind, a.Key}] {
			missing++
		}
	}
	if missing > s.shrinkMin && float64(missing) > s.shrinkFrac*float64(len(existing)) {
		return fmt.Sprintf("discovery would remove %d of %d assets (more than %.0f%% and more than %d)",
			missing, len(existing), s.shrinkFrac*100, s.shrinkMin), nil
	}
	return "", nil
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, l := range [][]string{a, b} {
		for _, x := range l {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	sort.Strings(out)
	return out
}

func unionPrefixes(a, b []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, l := range [][]netip.Prefix{a, b} {
		for _, p := range l {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// unreportedPrefixes retains claims for identities absent from a partial
// result. A re-reported IP may explicitly retract its earlier owned flag.
func unreportedPrefixes(previous []netip.Prefix, assets []model.AssetInput) []netip.Prefix {
	reported := make(map[netip.Prefix]bool)
	for _, a := range assets {
		if a.Kind == model.KindIP {
			if prefix, ok := parsePrefix(a.Key); ok {
				reported[prefix] = true
			}
		}
	}
	var out []netip.Prefix
	for _, prefix := range previous {
		if !reported[prefix] {
			out = append(out, prefix)
		}
	}
	return out
}

// AddDiscovered adds assets/relations found by checks or expansion. Only
// assets that classify as owned (which includes scope.include matches) are
// added; everything else is dropped, counted and logged. It never removes.
func (s *Service) AddDiscovered(ctx context.Context, origin string, in []model.AssetInput, rels []model.RelationInput) (store.InventoryDiff, error) {
	if err := ctx.Err(); err != nil {
		return store.InventoryDiff{}, err
	}
	ups := s.scopeFilter(origin, in)
	if len(ups) == 0 {
		return store.InventoryDiff{}, nil
	}
	diff, err := s.st.AddDiscovered(ctx, ups, rels, s.now())
	if err != nil {
		return store.InventoryDiff{}, fmt.Errorf("add discovered (%s): %w", origin, err)
	}
	s.record(diff)
	return diff, nil
}

// ReplaceDerived records what check origin observed about the asset parentID
// (the asset that was scanned): in-scope assets/relations are upserted as with
// AddDiscovered, and children this (parent, origin) reported earlier but not
// now are garbage-collected (marked removed, relations deleted, findings
// resolved).
//
// The engine must call it, with parent = the scanned asset and origin = the
// check name, after every successful run of a check whose Result.Discovered
// are children of the scanned asset (net.ports, http.probe, ...), including
// runs that discovered nothing; AddDiscovered stays for parentless discovery
// such as expansion.
func (s *Service) ReplaceDerived(ctx context.Context, parentID int64, origin string, in []model.AssetInput, rels []model.RelationInput) (store.InventoryDiff, error) {
	if err := ctx.Err(); err != nil {
		return store.InventoryDiff{}, err
	}
	ups := s.scopeFilter(origin, in)
	diff, err := s.st.ReplaceDerived(ctx, parentID, origin, ups, rels, s.now())
	if err != nil {
		return store.InventoryDiff{}, fmt.Errorf("replace derived (%s): %w", origin, err)
	}
	s.record(diff)
	return diff, nil
}

// scopeFilter classifies discovered assets and keeps only owned ones; the
// rest are dropped, counted and logged.
func (s *Service) scopeFilter(origin string, in []model.AssetInput) []store.AssetUpsert {
	var ups []store.AssetUpsert
	dropped := 0
	for _, a := range in {
		if a.Source == "" {
			a.Source = origin
		}
		class := s.cls.Classify(a.Kind, a.Key)
		if class != model.ScopeOwned {
			dropped++
			s.log.Debug("inventory: dropping discovered asset outside scope",
				"origin", origin, "kind", a.Kind, "key", a.Key, "class", class)
			continue
		}
		ups = append(ups, store.AssetUpsert{AssetInput: a, Scope: class})
	}
	if dropped > 0 {
		s.log.Info("inventory: dropped out-of-scope discoveries", "origin", origin, "dropped", dropped)
		if s.rec != nil {
			s.rec.InventoryChange("dropped", dropped)
		}
	}
	return ups
}

// Rehydrate rebuilds the classifier's owned zones and owned IP prefixes from
// the database without calling any source: zones are the non-removed zone
// assets per authoritative reporter. IP claims use each reporter's own
// facts (owned attrs, or any IP of a kubernetes source), never another source's
// canonical attrs. Explicit ownership can override shared ranges but not
// exclusions. It seeds per-source bookkeeping so later Syncs shrink it
// correctly. Call it at startup and periodically
// (RunRefresh) so replicas that did not sync still follow dropped zones.
// It is idempotent and never writes to the store.
func (s *Service) Rehydrate(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	syncs, err := s.st.ListSyncs(ctx)
	if err != nil {
		return fmt.Errorf("rehydrate: list syncs: %w", err)
	}
	types := make(map[string]string, len(syncs))
	for _, ss := range syncs {
		types[ss.Source] = ss.Type
	}
	zoneAssets, _, err := s.st.ListAssets(ctx, store.AssetFilter{Kind: model.KindZone})
	if err != nil {
		return fmt.Errorf("rehydrate: list zones: %w", err)
	}
	ipAssets, _, err := s.st.ListAssets(ctx, store.AssetFilter{Kind: model.KindIP})
	if err != nil {
		return fmt.Errorf("rehydrate: list ips: %w", err)
	}

	bySourceZones := map[string][]source.Zone{}
	for _, a := range zoneAssets {
		for _, src := range authoritativeReporters(a) {
			bySourceZones[src] = append(bySourceZones[src], source.Zone{Name: a.Key, Source: src})
		}
	}
	zones := map[string][]string{}
	for src, zs := range bySourceZones {
		zones[src] = normZones(zs)
	}
	bySourceIPs := map[string][]model.AssetInput{}
	for _, a := range ipAssets {
		for _, src := range authoritativeReporters(a) {
			fact, ok := a.SourceFacts[src]
			if !ok && src == a.Source {
				// Legacy canonical metadata belongs only to that authority.
				// A missing secondary fact remains unknown, never copied.
				fact = model.SourceFact{Zone: a.Zone, Attrs: a.Attrs}
			}
			bySourceIPs[src] = append(bySourceIPs[src], model.AssetInput{Kind: a.Kind, Key: a.Key, Source: src, Zone: fact.Zone, Attrs: fact.Attrs})
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones = zones
	s.cls.SetZones(s.zoneUnionLocked())
	// Zones are in place; now classify IPs (shared/excluded checks need them).
	pfx := map[string][]netip.Prefix{}
	for src, as := range bySourceIPs {
		if ps := s.acceptPrefixes(types[src], as); len(ps) > 0 {
			pfx[src] = ps
		}
	}
	s.prefixes = pfx
	s.cls.SetOwnedPrefixes(s.prefixUnionLocked())
	return nil
}

// authoritativeReporters uses current membership, not arbitrary fact keys.
// Legacy rows have only a canonical source. Derived and external-scanner
// metadata cannot establish inventory ownership.
func authoritativeReporters(a model.Asset) []string {
	reporters := a.Reporters
	if len(reporters) == 0 {
		reporters = []string{a.Source}
	}
	seen := make(map[string]bool, len(reporters))
	var out []string
	for _, src := range reporters {
		if store.IsDerivedSource(src) || model.IsIngestSource(src) || seen[src] {
			continue
		}
		seen[src] = true
		out = append(out, src)
	}
	return out
}

// RunRefresh calls Rehydrate every interval (5 minutes when interval <= 0)
// until ctx is done. Errors and panics are logged, never propagated.
func (s *Service) RunRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshOnce(ctx)
		}
	}
}

func (s *Service) refreshOnce(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("inventory: rehydrate panicked", "panic", r)
		}
	}()
	if err := s.Rehydrate(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("inventory: rehydrate failed", "err", err)
	}
}

func (s *Service) record(d store.InventoryDiff) {
	if s.rec == nil {
		return
	}
	for kind, n := range map[string]int{"added": len(d.Added), "changed": len(d.Changed), "removed": len(d.Removed), "revived": len(d.Revived)} {
		if n > 0 {
			s.rec.InventoryChange(kind, n)
		}
	}
}

func (s *Service) upserts(source string, in []model.AssetInput) []store.AssetUpsert {
	out := make([]store.AssetUpsert, 0, len(in))
	for _, a := range in {
		if a.Source == "" {
			a.Source = source
		}
		out = append(out, store.AssetUpsert{AssetInput: a, Scope: s.cls.Classify(a.Kind, a.Key)})
	}
	return out
}

// acceptPrefixes returns the owned-IP registrations implied by one source's
// assets: IPs explicitly flagged owned by an inventory source or static config,
// and every IP a kubernetes source reports (its LoadBalancer and node external
// IPs). DNS and origin records are relationships, not ownership evidence.
// A shared-edge IP is not owned just because a record points at it. Explicit
// inventory evidence still wins over a provider range; only excluded space is
// refused here. ClassifyUnregistered ignores earlier registrations, which
// keeps origin-only records out of the owned set.
func (s *Service) acceptPrefixes(srcType string, assets []model.AssetInput) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, a := range assets {
		if a.Kind != model.KindIP || !ownedClaim(srcType, a.Attrs) {
			continue
		}
		p, ok := parsePrefix(a.Key)
		if !ok {
			continue
		}
		switch s.cls.ClassifyUnregistered(p.Masked().Addr().String()) {
		case model.ScopeExcluded:
			s.log.Info("inventory: not registering excluded IP as owned", "ip", a.Key)
			continue
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func ownedClaim(srcType string, attrs map[string]any) bool {
	if srcType == "kubernetes" {
		return true
	}
	return attrs["owned"] == true
}

func parsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap().WithZone("")
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func normZones(zs []source.Zone) []string {
	seen := map[string]bool{}
	var out []string
	for _, z := range zs {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(z.Name), "."))
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) zoneUnionLocked() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, zs := range s.zones {
		for _, z := range zs {
			if !seen[z] {
				seen[z] = true
				out = append(out, z)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) prefixUnionLocked() []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	out := []netip.Prefix{}
	for _, ps := range s.prefixes {
		for _, p := range ps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func restore[V any](m map[string]V, k string, v V, had bool) {
	if had {
		m[k] = v
	} else {
		delete(m, k)
	}
}
