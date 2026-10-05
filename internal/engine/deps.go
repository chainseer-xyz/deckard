// Package engine runs deckard's background work: periodic source syncs, the
// per-tier scan scheduler, and the scan workers. Jobs ride on River
// (Postgres), so the queue, retries, leader election and graceful shutdown are
// River's. Every network-touching scan passes through the scope guard; see
// runScan for the safety invariant.
package engine

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Inventory is the slice of inventory.Service the engine uses.
type Inventory interface {
	Sync(ctx context.Context, src source.Source) (store.InventoryDiff, error)
	// AddDiscovered adds parentless discoveries (expansion). It never removes.
	AddDiscovered(ctx context.Context, origin string, in []model.AssetInput, rels []model.RelationInput) (store.InventoryDiff, error)
	// ReplaceDerived records what check origin observed about parent asset
	// parentID and garbage-collects derived children it no longer observes.
	// Called after every successful check run, even an empty one.
	ReplaceDerived(ctx context.Context, parentID int64, origin string, in []model.AssetInput, rels []model.RelationInput) (store.InventoryDiff, error)
}

// FindingProcessor is the slice of finding.Processor the engine uses. It is
// responsible for persisting observations, baselines and finding lifecycle.
type FindingProcessor interface {
	Process(ctx context.Context, asset model.Asset, checkName string, res *check.Result) (store.ReconcileResult, error)
}

// Recorder receives engine metrics. All methods must be safe for concurrent use.
type Recorder interface {
	ObserveScan(check, tier string, d time.Duration, err error)
	// ObserveSkip counts a check that was skipped before it touched the
	// network (reason is a short, bounded code). A skip is neither a run nor
	// an error.
	ObserveSkip(check, tier, reason string)
	ObserveSync(source string, d time.Duration, ok bool)
	InventoryChange(kind string, n int)
	SetQueueDepth(queue string, n int)
	// JobsReclaimed counts n running jobs of kind reclaimed from a dead
	// instance; n == 0 only creates the series.
	JobsReclaimed(kind string, n int)
}

type noopRecorder struct{}

func (noopRecorder) ObserveScan(string, string, time.Duration, error) {}
func (noopRecorder) ObserveSkip(string, string, string)               {}
func (noopRecorder) ObserveSync(string, time.Duration, bool)          {}
func (noopRecorder) InventoryChange(string, int)                      {}
func (noopRecorder) SetQueueDepth(string, int)                        {}
func (noopRecorder) JobsReclaimed(string, int)                        {}

// Guard is the subset of *scope.Guard the engine uses. If the implementation
// also has an AllowedFor method it is consulted in addition to (never instead
// of) scope.AllowedFor, so a permissive fake cannot widen the rules.
type Guard interface {
	Classify(kind model.AssetKind, key string) model.ScopeClass
	Dialer(tier model.Tier, class model.ScopeClass, rate scope.RateLimiter) check.Dialer
	Resolver(tier model.Tier, class model.ScopeClass, rate scope.RateLimiter) check.Resolver
	HTTPClient(tier model.Tier, class model.ScopeClass, rate scope.RateLimiter, opts ...scope.HTTPOption) *http.Client
}

var _ Guard = (*scope.Guard)(nil)

// Store is the slice of store.Store the engine uses; store.Store satisfies it.
type Store interface {
	GetAsset(ctx context.Context, id int64) (*model.Asset, error)
	ListAssets(ctx context.Context, f store.AssetFilter) ([]model.Asset, int, error)
	Edges(ctx context.Context, assetID int64) ([]store.Edge, error)
	GetBaseline(ctx context.Context, assetID int64, check string) (*store.Baseline, error)
	// ListFindings feeds Target.OpenFindings for checks that re-verify their
	// own unresolved findings (check.WantsOpenFindings).
	ListFindings(ctx context.Context, f store.FindingFilter) ([]model.Finding, int, error)
	ResolveInapplicableFindings(ctx context.Context, asset model.Asset, check string, now time.Time) (int, error)
	// LastScans returns one row per (asset, check) with its latest attempt
	// and latest success; the scheduler's due-computation reads it.
	LastScans(ctx context.Context) ([]store.ScanLast, error)
	RecordScan(ctx context.Context, r store.ScanRun) error
	PruneScans(ctx context.Context, olderThan time.Time) (int, error)
	PruneRelations(ctx context.Context, olderThan time.Time) (int, error)
	ExpireSuppressions(ctx context.Context, now time.Time) (int, error)
}

var _ Store = (store.Store)(nil)

// ScanKey identifies one (asset, check) pair.
type ScanKey struct {
	AssetID int64
	Check   string
}

// Roles an engine instance may take.
const (
	RoleAPI       = "api"
	RoleScheduler = "scheduler"
	RoleWorker    = "worker"
)

// Deps are the engine's collaborators. Pool may be nil when only RunOnce is
// used (no River).
type Deps struct {
	Config    config.Config
	Store     Store
	Guard     Guard
	Inventory Inventory
	Findings  FindingProcessor
	Recorder  Recorder
	Checks    []check.Check
	Sources   []source.Source
	Pool      *pgxpool.Pool
	// Expander performs discovery expansion (CT logs, DNS bruteforce). Nil
	// disables expansion.
	Expander Expander
	// Refdata refreshes the embedded reference datasets. Nil disables the
	// refresh_refdata job and the RunOnce refresh.
	Refdata Refresher
	// Templates is the nuclei template updater. Nil disables the
	// update_templates job and the catch-up loop.
	Templates TemplateManager
	// Delta runs template-limited nuclei scans (new templates, CVE-targeted).
	// Nil disables them.
	Delta DeltaScanner
	// Intel is the third-party metadata client handed to checks as
	// Target.Intel. Nil means not available (checks that need it skip).
	Intel check.Intel
	// Lookup is the DNS client for names the operator does not own, handed to
	// checks as Target.Lookup (domain.lookalike). Nil means not available.
	Lookup check.Lookup
	Logger *slog.Logger
	// Now overrides time.Now in tests.
	Now func() time.Time
}

// Typed errors returned by operator actions.
var (
	ErrUnknownSource = errors.New("unknown source")
	ErrNotScannable  = errors.New("asset has no applicable, in-scope, enabled checks")
	ErrNoQueue       = errors.New("engine has no job queue (no database pool)")
)

// UnknownSourceError names the source that was not found; it matches
// ErrUnknownSource with errors.Is.
type UnknownSourceError struct{ Name string }

func (e *UnknownSourceError) Error() string   { return "unknown source " + `"` + e.Name + `"` }
func (e *UnknownSourceError) Is(t error) bool { return t == ErrUnknownSource }
