// Package store defines deckard's persistence contract. The only production
// implementation is store/postgres; storetest provides a reusable contract
// suite any implementation must pass.
package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// AssetUpsert is an asset plus the scope class computed by scope.Guard.
type AssetUpsert struct {
	model.AssetInput
	Scope model.ScopeClass
}

// InventoryDiff reports what an inventory write changed.
type InventoryDiff struct {
	Added   []model.Asset
	Changed []model.Asset // attrs or scope class changed
	Removed []model.Asset
	Revived []model.Asset // previously removed, seen again
	// Ignored counts discoveries refused because the asset was removed by the
	// source that owns it: only that source's snapshot may revive it.
	Ignored int
}

// IsDerivedSource reports whether an asset source label marks a derived asset,
// one discovered by a check, port scan or expansion rather than reported by an
// inventory source (cloudflare, route53, gcpdns, aws, kubernetes, static). Derived
// assets may be claimed by a source snapshot, merge attrs per key and are
// garbage-collected by ReplaceDerived; source-owned assets are only changed
// or removed by their source's snapshot.
func IsDerivedSource(source string) bool {
	switch source {
	case "", "discovered":
		return true
	}
	for _, p := range []string{"check:", "net.", "expansion:"} {
		if strings.HasPrefix(source, p) {
			return true
		}
	}
	return false
}

// Empty reports whether nothing changed.
func (d InventoryDiff) Empty() bool {
	return len(d.Added)+len(d.Changed)+len(d.Removed)+len(d.Revived) == 0
}

// AssetFilter narrows ListAssets. Zero values mean "any".
type AssetFilter struct {
	Kind           model.AssetKind
	Source         string
	Scope          model.ScopeClass
	Zone           string
	Query          string // substring match on key
	IncludeRemoved bool
	Limit          int
	Offset         int
}

// Edge is a stored relation with its far-side asset resolved.
type Edge struct {
	Other    model.Asset
	Type     model.RelationType
	Outbound bool
}

// Baseline is the learned "normal" state for one (asset, check).
type Baseline struct {
	AssetID    int64          `json:"asset_id"`
	Check      string         `json:"check"`
	Data       map[string]any `json:"data"`
	Stable     bool           `json:"stable"`     // promoted after learning.stable_after consistent runs
	Consistent int            `json:"consistent"` // consecutive observations equal to Data
	UpdatedAt  time.Time      `json:"updated_at"`
}

// ReconcileInput is the result of one run of one check on one asset.
type ReconcileInput struct {
	AssetID      int64
	Check        string
	Findings     []model.FindingInput
	ResolveAfter int // consecutive misses before an open finding resolves (>=1)
	Now          time.Time
	// PartialRun marks a run that only observed a subset of what the check can
	// report (for example a delta scan of new nuclei templates). Findings in
	// the run are opened, reopened and refreshed as usual, but absent findings
	// never accrue misses and nothing is resolved.
	PartialRun bool
}

// ReconcileResult lists lifecycle transitions caused by a run.
type ReconcileResult struct {
	Opened   []model.Finding
	Reopened []model.Finding
	Updated  []model.Finding // still open, evidence/severity refreshed
	Resolved []model.Finding
}

// IngestItem is one externally reported finding of an IngestInput. The
// finding attaches to the asset (AssetKind, AssetKey): with Ref set the asset
// must already exist, be live and be owned, otherwise the item is rejected;
// without Ref the asset is used if it exists (a removed one is revived and
// claimed for IngestInput.Source) and created if it does not. Callers only
// ever pass non-probable kinds without Ref (the API allows cloud_resource).
type IngestItem struct {
	Index     int // position in the request, echoed in rejections
	AssetKind model.AssetKind
	AssetKey  string
	Ref       bool
	// Finding.Key is the producer's stable id for the item, unique within
	// one input; Finding.Check is ignored (IngestInput.Check applies).
	Finding model.FindingInput
}

// IngestInput is one accepted ingest request for one (Tool, Scope).
//
// Reconciliation set: every finding previously stored under (Check, Scope),
// whatever asset it is attached to. The fingerprint of an item is
// model.Fingerprint(Check, Scope, Finding.Key), so the same producer key is
// the same finding across runs even if its asset changes.
//
// Absence is applied (absent findings accrue a miss and resolve after
// ResolveAfter consecutive misses, exactly like a built-in check) only when
// all of these hold; otherwise the input can only open, reopen and refresh:
//   - Complete is true,
//   - no item was rejected,
//   - ObservedAt is strictly after every ObservedAt previously accepted for
//     (Tool, Scope) (an older or same-run delivery proves nothing new).
//
// An input whose Digest equals the last accepted Digest for (Tool, Scope) is
// a replay (a retried delivery of the same run) and changes nothing.
// Implementations serialise inputs per (Tool, Scope) and apply each one
// atomically.
type IngestInput struct {
	Tool       string
	Scope      string
	Check      string           // model.IngestCheck(Tool)
	Source     string           // model.IngestSource(Tool)
	AssetScope model.ScopeClass // class of assets this input creates or claims
	Complete   bool
	ObservedAt time.Time
	Digest     string
	Items      []IngestItem
	// ResolveAfter is findings.resolve_after (>= 1).
	ResolveAfter int
	Now          time.Time
}

// IngestRejection reports an item that was not applied.
type IngestRejection struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// IngestResult reports what an IngestInput changed. ReconcileResult.Updated
// lists still-open findings seen again; Refreshed counts every known finding
// seen again whatever its status (acknowledged and suppressed included).
type IngestResult struct {
	ReconcileResult
	Refreshed int
	// Pending counts absent findings that accrued a miss but are not resolved
	// yet (fewer than ResolveAfter consecutive misses).
	Pending  int
	Rejected []IngestRejection
	// Complete reports whether absence was applied (see IngestInput).
	Complete bool
	// NotCompleteReason says why a Complete input was not applied as complete.
	NotCompleteReason string
	// Replay is set when the input repeated the last accepted one.
	Replay bool
}

// IngestScope is the ingest state of one (Tool, Scope).
type IngestScope struct {
	Tool       string
	Scope      string
	CreatedAt  time.Time
	LastAt     time.Time // last accepted request (any kind)
	CompleteAt time.Time // last request applied as complete; zero if never
	ObservedAt time.Time // newest ObservedAt accepted
	Open       int       // open findings of (Tool, Scope) on live assets
}

// FindingFilter narrows ListFindings. Zero values mean "any".
type FindingFilter struct {
	Statuses    []model.FindingStatus
	MinSeverity model.Severity
	Check       string
	Zone        string
	Source      string
	AssetID     int64
	Query       string
	Limit       int
	Offset      int
	// IncludeRemovedAssets keeps unresolved findings (open, acknowledged,
	// suppressed, false_positive) of removed assets in the result. The zero
	// value hides them, so the dispatcher's open list never re-alerts on a
	// removed asset. Resolved findings (history) are always listed, and a
	// filter naming an AssetID is never narrowed.
	IncludeRemovedAssets bool
}

// StatusChange is an operator action on a finding.
type StatusChange struct {
	Status model.FindingStatus
	Until  *time.Time // for suppressed/acknowledged; nil = indefinite
	Note   string
	Actor  string
}

// Event is an entry in the inventory/finding change feed.
type Event struct {
	ID      int64          `json:"id"`
	Type    string         `json:"type"` // asset_added|asset_removed|asset_changed|asset_revived|finding_opened|finding_resolved|finding_reopened
	Subject string         `json:"subject"`
	Data    map[string]any `json:"data,omitempty"`
	At      time.Time      `json:"at"`
}

// SyncStatus is the last outcome of syncing one source.
type SyncStatus struct {
	Source  string    `json:"source"`
	Type    string    `json:"type"`
	LastRun time.Time `json:"last_run"`
	LastOK  time.Time `json:"last_ok"`
	Error   string    `json:"error,omitempty"`
	// Warning is set on a run that succeeded with caveats (partial discovery,
	// removals skipped); a clean run clears it.
	Warning    string `json:"warning,omitempty"`
	AssetCount int    `json:"asset_count"`
	DurationMS int64  `json:"duration_ms"`
}

// ScanRun is the record of one check execution.
type ScanRun struct {
	ID         int64     `json:"id"`
	AssetID    int64     `json:"asset_id"`
	Check      string    `json:"check"`
	Tier       string    `json:"tier"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
	Findings   int       `json:"findings"`
}

// SkippedPrefix starts the Error of a ScanRun that was skipped before it
// touched the network (scope, profile or destination refusal).
const SkippedPrefix = "skipped: "

// UnownedDestinationSkip starts the Error of a ScanRun skipped because the
// asset's owned name resolves to shared or third-party addresses that the
// check's tier may not reach. That state is expected to persist, so for
// scheduling it settles the run like a completed one (LastSuccess): the check
// is next attempted after its normal interval, not after
// scheduling.error_retry. It made no observation, so it never counts as a
// clean run for findings: nothing is refreshed, missed or resolved by it.
const UnownedDestinationSkip = SkippedPrefix + "unowned destination: "

// Settled reports whether the run settles scheduling (see ScanLast): it
// completed without error or was skipped with UnownedDestinationSkip.
func (r ScanRun) Settled() bool {
	return r.Error == "" || strings.HasPrefix(r.Error, UnownedDestinationSkip)
}

// ScanLast is the scheduling state of one (asset, check): when it was last
// attempted and when it last settled (completed without error, or was skipped
// with UnownedDestinationSkip; zero if never).
type ScanLast struct {
	AssetID     int64
	Check       string
	LastAttempt time.Time
	LastSuccess time.Time
}

// Stats is the dashboard/metrics summary.
type Stats struct {
	AssetsByKind    map[string]int `json:"assets_by_kind"`
	AssetsBySource  map[string]int `json:"assets_by_source"`
	AssetsByScope   map[string]int `json:"assets_by_scope"`
	FindingsBySev   map[string]int `json:"findings_by_severity"` // open only
	FindingsByCheck map[string]int `json:"findings_by_check"`    // open only
}

// Store is the persistence boundary.
type Store interface {
	Migrate(ctx context.Context) error
	Ping(ctx context.Context) error
	Close()

	// ApplySnapshot writes a complete, successful sync of one source: upserts
	// assets, replaces that source's reported relations, and removes unseen assets.
	ApplySnapshot(ctx context.Context, source string, assets []AssetUpsert, rels []model.RelationInput, now time.Time) (InventoryDiff, error)
	// UpsertSnapshot is ApplySnapshot without the removal step: it upserts the
	// source's assets and relations (same ownership rules, reporter sets kept
	// intact) but marks nothing removed. Used for partial or suspect syncs.
	UpsertSnapshot(ctx context.Context, source string, assets []AssetUpsert, rels []model.RelationInput, now time.Time) (InventoryDiff, error)
	// AddDiscovered adds assets found by checks/expansion. Never removes.
	AddDiscovered(ctx context.Context, assets []AssetUpsert, rels []model.RelationInput, now time.Time) (InventoryDiff, error)
	// ReplaceDerived records what one check just observed about one parent
	// asset: it upserts assets/rels exactly like AddDiscovered (same ownership
	// and per-key attr merge rules) and registers them as children of
	// (assetID, origin). Children previously registered for the same
	// (assetID, origin) that are absent now lose that registration; a derived
	// child no (parent, origin) observes any more is marked removed, its
	// relations are deleted and its findings resolved. Source-owned (claimed)
	// children are never removed here.
	// Relationships replace the (assetID, origin) set even when both endpoints
	// remain live through another reporter.
	// A removed parent is a no-op (a scan that finished after removal).
	// Engine contract: for checks whose
	// Result.Discovered are children of the scanned asset (net.ports,
	// http.probe, ...) call ReplaceDerived with assetID = the scanned asset and
	// origin = the check name on every successful run, even when nothing was
	// discovered; use AddDiscovered only for parentless discovery (expansion).
	ReplaceDerived(ctx context.Context, assetID int64, origin string, assets []AssetUpsert, rels []model.RelationInput, now time.Time) (InventoryDiff, error)
	// PruneRelations deletes relations with an endpoint removed before
	// olderThan and returns how many were deleted.
	PruneRelations(ctx context.Context, olderThan time.Time) (int, error)
	GetAsset(ctx context.Context, id int64) (*model.Asset, error)
	GetAssetByKey(ctx context.Context, kind model.AssetKind, key string) (*model.Asset, error)
	ListAssets(ctx context.Context, f AssetFilter) ([]model.Asset, int, error)
	Edges(ctx context.Context, assetID int64) ([]Edge, error)

	SaveObservation(ctx context.Context, assetID int64, o model.ObservationInput, now time.Time) error
	LatestObservations(ctx context.Context, assetID int64) ([]model.Observation, error)
	GetBaseline(ctx context.Context, assetID int64, check string) (*Baseline, error)
	SaveBaseline(ctx context.Context, b Baseline) error

	ReconcileFindings(ctx context.Context, in ReconcileInput) (ReconcileResult, error)
	// ResolveInapplicableFindings closes findings for a check that no longer
	// applies to a live owned asset. The asset snapshot must still match the
	// stored asset, so a concurrent inventory change cannot settle findings.
	ResolveInapplicableFindings(ctx context.Context, asset model.Asset, check string, now time.Time) (int, error)
	// IngestFindings applies one externally reported run for (Tool, Scope)
	// with the same lifecycle rules as ReconcileFindings; see IngestInput.
	IngestFindings(ctx context.Context, in IngestInput) (IngestResult, error)
	// ListIngestScopes returns the state of every (Tool, Scope) that has
	// ever had an accepted ingest, ordered by Tool then CreatedAt.
	ListIngestScopes(ctx context.Context) ([]IngestScope, error)
	GetFinding(ctx context.Context, id int64) (*model.Finding, error)
	ListFindings(ctx context.Context, f FindingFilter) ([]model.Finding, int, error)
	// ChangeFindingStatus applies an operator action. Expired suppressions are
	// returned to open by ExpireSuppressions.
	ChangeFindingStatus(ctx context.Context, id int64, c StatusChange, now time.Time) error
	ExpireSuppressions(ctx context.Context, now time.Time) (int, error)
	// ResolvedSince lists findings resolved at or after t (for notifier endsAt).
	ResolvedSince(ctx context.Context, t time.Time) ([]model.Finding, error)

	RecordSync(ctx context.Context, s SyncStatus) error
	ListSyncs(ctx context.Context) ([]SyncStatus, error)
	RecordScan(ctx context.Context, r ScanRun) error
	ListScans(ctx context.Context, limit int) ([]ScanRun, error)
	// LastScans returns one row per (asset, check) that has any recorded run,
	// from durable scan_state, independent of retained history. The scheduler
	// uses LastAttempt to pace retries and LastSuccess for due-ness.
	LastScans(ctx context.Context) ([]ScanLast, error)
	// PruneScans deletes runs that started before olderThan and returns how
	// many were deleted. Durable scheduling state survives pruning.
	PruneScans(ctx context.Context, olderThan time.Time) (int, error)
	ListEvents(ctx context.Context, since time.Time, limit int) ([]Event, error)
	// ListEventsAfter returns events at or after since with IDs greater than
	// afterID, ordered by ascending ID. The stream advances only the ID cursor.
	ListEventsAfter(ctx context.Context, since time.Time, afterID int64, limit int) ([]Event, error)
	Stats(ctx context.Context) (Stats, error)
}
