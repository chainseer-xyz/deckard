package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// queue is how the runner enqueues follow-up work. The River implementation
// persists jobs in Postgres; memQueue (RunOnce) keeps them in memory and runs
// them through the same handlers.
type queue interface {
	// enqueueScan reports whether a new job was queued (false = duplicate).
	enqueueScan(ctx context.Context, j scanJob) (bool, error)
	enqueueSync(ctx context.Context, source string) (bool, error)
	// enqueueExpand queues a discovery expansion of one zone asset, to run after
	// delay (jitter, so zones do not all hit crt.sh at once). Unique per zone.
	enqueueExpand(ctx context.Context, zoneAssetID int64, delay time.Duration) (bool, error)
}

type scanJob struct {
	AssetID int64
	Tier    model.Tier
	Check   string // empty = every applicable check of Tier
}

func (j scanJob) key() string { return fmt.Sprintf("%d|%s|%s", j.AssetID, j.Tier, j.Check) }

// riverQueue inserts jobs through a River client. River's unique-job options
// (see jobs.go) make a second insert for the same (asset, tier, check) a no-op
// while one is queued, scheduled, retrying or running.
type riverQueue struct{ c *river.Client[pgx.Tx] }

func (q riverQueue) enqueueScan(ctx context.Context, j scanJob) (bool, error) {
	res, err := q.c.Insert(ctx, ScanAssetArgs(j),
		&river.InsertOpts{Queue: queueForTier(j.Tier)})
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

func (q riverQueue) enqueueSync(ctx context.Context, src string) (bool, error) {
	res, err := q.c.Insert(ctx, SyncSourceArgs{Source: src}, nil)
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

func (q riverQueue) enqueueExpand(ctx context.Context, id int64, delay time.Duration) (bool, error) {
	opts := &river.InsertOpts{}
	if delay > 0 {
		opts.ScheduledAt = time.Now().Add(delay)
	}
	res, err := q.c.Insert(ctx, ExpandZoneArgs{AssetID: id}, opts)
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

// noQueue is used when the engine has no database pool.
type noQueue struct{}

func (noQueue) enqueueScan(context.Context, scanJob) (bool, error) { return false, ErrNoQueue }
func (noQueue) enqueueSync(context.Context, string) (bool, error)  { return false, ErrNoQueue }
func (noQueue) enqueueExpand(context.Context, int64, time.Duration) (bool, error) {
	return false, ErrNoQueue
}

// memQueue collects jobs in memory for synchronous execution. It remembers
// every job it has ever seen so a RunOnce pass never repeats work.
type memQueue struct {
	mu    sync.Mutex
	seen  map[string]bool
	scans []scanJob
	zones []int64
	// deltas are template-limited scan batches (see templates.go).
	deltas []deltaJob
}

func newMemQueue() *memQueue { return &memQueue{seen: map[string]bool{}} }

func (m *memQueue) enqueueScan(_ context.Context, j scanJob) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[j.key()] {
		return false, nil
	}
	m.seen[j.key()] = true
	m.scans = append(m.scans, j)
	return true, nil
}

// enqueueSync is a no-op for RunOnce: syncs are driven directly.
func (m *memQueue) enqueueSync(context.Context, string) (bool, error) { return false, nil }

func (m *memQueue) enqueueExpand(_ context.Context, id int64, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := fmt.Sprintf("expand|%d", id)
	if m.seen[k] {
		return false, nil
	}
	m.seen[k] = true
	m.zones = append(m.zones, id)
	return true, nil
}

func (m *memQueue) takeZones() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.zones
	m.zones = nil
	return out
}

func (m *memQueue) take() []scanJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.scans
	m.scans = nil
	return out
}
