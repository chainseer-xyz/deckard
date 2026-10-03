package engine

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// Queue names.
const (
	QueueSync      = "sync"
	QueuePassive   = "passive"
	QueueActive    = "active"
	QueueIntrusive = "intrusive"
	QueueExpand    = "expand"           // slow third-party lookups (crt.sh), isolated from scans
	QueueDefault   = river.QueueDefault // schedule ticks and housekeeping
)

// Job kinds.
const (
	KindSyncSource        = "sync_source"
	KindScanAsset         = "scan_asset"
	KindScheduleTier      = "schedule_tier"
	KindHousekeeping      = "housekeeping"
	KindExpandZone        = "expand_zone"
	KindScheduleExpansion = "schedule_expansion"
)

func queueForTier(t model.Tier) string {
	switch t {
	case model.TierActive:
		return QueueActive
	case model.TierIntrusive:
		return QueueIntrusive
	default:
		return QueuePassive
	}
}

// uniqueOpts dedupes by args across every live state. Completed is
// deliberately NOT in the set: River keeps completed jobs for 24h, and a
// completed scan must not block the next due scan.
func uniqueOpts() river.UniqueOpts {
	return river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable,
			rivertype.JobStatePending,
			rivertype.JobStateRunning,
			rivertype.JobStateRetryable,
			rivertype.JobStateScheduled,
		},
	}
}

// SyncSourceArgs syncs one configured source.
type SyncSourceArgs struct {
	Source string `json:"source"`
}

func (SyncSourceArgs) Kind() string { return KindSyncSource }
func (SyncSourceArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueSync, MaxAttempts: 5, UniqueOpts: uniqueOpts()}
}

// ScanAssetArgs runs the checks of one tier (or one named check) on one asset.
type ScanAssetArgs struct {
	AssetID int64      `json:"asset_id"`
	Tier    model.Tier `json:"tier"`
	Check   string     `json:"check,omitempty"`
}

func (ScanAssetArgs) Kind() string { return KindScanAsset }
func (ScanAssetArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 3, UniqueOpts: uniqueOpts()}
}

// ScheduleTierArgs is the periodic tick that enqueues due scans for a tier.
type ScheduleTierArgs struct {
	Tier model.Tier `json:"tier"`
}

func (ScheduleTierArgs) Kind() string { return KindScheduleTier }
func (ScheduleTierArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueDefault, MaxAttempts: 2, UniqueOpts: uniqueOpts()}
}

// HousekeepingArgs expires suppressions and other periodic upkeep.
type HousekeepingArgs struct{}

func (HousekeepingArgs) Kind() string { return KindHousekeeping }
func (HousekeepingArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueDefault, MaxAttempts: 2, UniqueOpts: uniqueOpts()}
}

// ExpandZoneArgs expands discovery for one owned zone asset (CT logs, DNS
// bruteforce). Unique per zone, so a slow or retrying expansion is never
// stacked.
type ExpandZoneArgs struct {
	AssetID int64 `json:"asset_id"`
}

func (ExpandZoneArgs) Kind() string { return KindExpandZone }
func (ExpandZoneArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueExpand, MaxAttempts: 5, UniqueOpts: uniqueOpts()}
}

// ScheduleExpansionArgs is the periodic tick that enqueues one expand_zone job
// per owned zone.
type ScheduleExpansionArgs struct{}

func (ScheduleExpansionArgs) Kind() string { return KindScheduleExpansion }
func (ScheduleExpansionArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueDefault, MaxAttempts: 2, UniqueOpts: uniqueOpts()}
}

type syncWorker struct {
	river.WorkerDefaults[SyncSourceArgs]
	r *runner
}

func (w *syncWorker) Work(ctx context.Context, j *river.Job[SyncSourceArgs]) error {
	err := w.r.runSync(ctx, j.Args.Source)
	if err != nil && permanentSyncError(err) {
		// A suspicious shrink is not a transient fault: retrying now would hit
		// the same guard. Cancel; the next periodic sync re-evaluates.
		return river.JobCancel(err)
	}
	return err
}
func (w *syncWorker) Timeout(*river.Job[SyncSourceArgs]) time.Duration { return 15 * time.Minute }

type scanWorker struct {
	river.WorkerDefaults[ScanAssetArgs]
	r *runner
}

func (w *scanWorker) Work(ctx context.Context, j *river.Job[ScanAssetArgs]) error {
	return w.r.runScan(ctx, scanJob{AssetID: j.Args.AssetID, Tier: j.Args.Tier, Check: j.Args.Check})
}

// Each check enforces its own timeout; the job timeout is a backstop that
// must exceed several of them (a job with no check name runs them in turn).
func (w *scanWorker) Timeout(*river.Job[ScanAssetArgs]) time.Duration { return 30 * time.Minute }

type scheduleWorker struct {
	river.WorkerDefaults[ScheduleTierArgs]
	r *runner
}

func (w *scheduleWorker) Work(ctx context.Context, j *river.Job[ScheduleTierArgs]) error {
	_, err := w.r.scheduleTier(ctx, j.Args.Tier)
	return err
}

// River's default job timeout is one minute, too short to enumerate a large
// inventory.
func (w *scheduleWorker) Timeout(*river.Job[ScheduleTierArgs]) time.Duration { return 10 * time.Minute }

type expandWorker struct {
	river.WorkerDefaults[ExpandZoneArgs]
	r *runner
}

func (w *expandWorker) Work(ctx context.Context, j *river.Job[ExpandZoneArgs]) error {
	err := w.r.runExpand(ctx, j.Args.AssetID)
	// Exactly a transient CT failure, not one joined with a real error (a
	// failed inventory write must still be retried and reported).
	if _, ok := err.(*transientExpandError); ok { //nolint:errorlint // deliberate: a joined error is not transient
		// The CT source is down: snooze (logged by River at debug, no attempt
		// used) instead of erroring, so a long crt.sh outage does not log
		// "Job errored; retrying" on every attempt. Uniqueness keeps it the
		// zone's only expansion job meanwhile.
		return river.JobSnooze(ctRetryDelay(snoozes(j.Metadata), w.r.Config.Expansion.Interval))
	}
	return err
}

// snoozes reads River's snooze counter from a job's metadata.
func snoozes(metadata []byte) int {
	var m struct {
		Snoozes int `json:"snoozes"`
	}
	if json.Unmarshal(metadata, &m) != nil {
		return 0
	}
	return m.Snoozes
}
func (w *expandWorker) Timeout(*river.Job[ExpandZoneArgs]) time.Duration { return 20 * time.Minute }

type scheduleExpansionWorker struct {
	river.WorkerDefaults[ScheduleExpansionArgs]
	r *runner
}

func (w *scheduleExpansionWorker) Work(ctx context.Context, _ *river.Job[ScheduleExpansionArgs]) error {
	_, err := w.r.scheduleExpansion(ctx, true)
	return err
}
func (w *scheduleExpansionWorker) Timeout(*river.Job[ScheduleExpansionArgs]) time.Duration {
	return 10 * time.Minute
}

type housekeepingWorker struct {
	river.WorkerDefaults[HousekeepingArgs]
	r *runner
}

func (w *housekeepingWorker) Work(ctx context.Context, _ *river.Job[HousekeepingArgs]) error {
	return w.r.housekeeping(ctx)
}
func (w *housekeepingWorker) Timeout(*river.Job[HousekeepingArgs]) time.Duration {
	return 10 * time.Minute
}

// jitterSchedule runs every interval +/- frac*interval so sources do not all
// sync in lockstep.
type jitterSchedule struct {
	interval time.Duration
	frac     float64
	rnd      func() float64 // [0,1)
}

func (s jitterSchedule) Next(t time.Time) time.Time {
	rnd := s.rnd
	if rnd == nil {
		rnd = rand.Float64
	}
	d := float64(s.interval) * (1 + (rnd()*2-1)*s.frac)
	if d < float64(time.Second) {
		d = float64(time.Second)
	}
	return t.Add(time.Duration(d))
}
