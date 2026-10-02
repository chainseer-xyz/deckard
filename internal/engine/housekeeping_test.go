package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
)

func TestHousekeepingPrunesScansAndRelationsByRetention(t *testing.T) {
	h := newHarness(func(c *testCfg) {
		c.Retention.Scans = 48 * time.Hour
		c.Retention.Relations = 100 * time.Hour
	}, nil)
	if err := h.r.housekeeping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.st.prunedScans) != 1 || !h.st.prunedScans[0].Equal(h.now.Add(-48*time.Hour)) {
		t.Fatalf("PruneScans cutoffs: %v", h.st.prunedScans)
	}
	if len(h.st.prunedRels) != 1 || !h.st.prunedRels[0].Equal(h.now.Add(-100*time.Hour)) {
		t.Fatalf("PruneRelations cutoffs: %v", h.st.prunedRels)
	}
}

func TestHousekeepingDefaultsRetention(t *testing.T) {
	h := newHarness(nil, nil)
	if err := h.r.housekeeping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.st.prunedScans[0].Equal(h.now.Add(-168*time.Hour)) || !h.st.prunedRels[0].Equal(h.now.Add(-720*time.Hour)) {
		t.Fatalf("default cutoffs: %v %v", h.st.prunedScans, h.st.prunedRels)
	}
}

// One failing step must not stop the others, and the error is surfaced.
func TestHousekeepingContinuesAfterPruneFailure(t *testing.T) {
	h := newHarness(nil, nil)
	h.st.pruneErr = errors.New("db")
	if err := h.r.housekeeping(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if len(h.st.prunedRels) != 1 || h.st.expired != 1 {
		t.Fatalf("later steps skipped: rels=%v expired=%d", h.st.prunedRels, h.st.expired)
	}
}

// River's default job timeout is one minute; long jobs must set their own.
func TestWorkersDeclareExplicitTimeouts(t *testing.T) {
	got := map[string]time.Duration{
		"schedule":           (&scheduleWorker{}).Timeout(&river.Job[ScheduleTierArgs]{}),
		"housekeeping":       (&housekeepingWorker{}).Timeout(&river.Job[HousekeepingArgs]{}),
		"schedule_expansion": (&scheduleExpansionWorker{}).Timeout(&river.Job[ScheduleExpansionArgs]{}),
		"expand":             (&expandWorker{}).Timeout(&river.Job[ExpandZoneArgs]{}),
	}
	for name, d := range got {
		if d < 10*time.Minute {
			t.Errorf("%s timeout %v, want >= 10m", name, d)
		}
	}
	if d := (&syncWorker{}).Timeout(&river.Job[SyncSourceArgs]{}); d < 15*time.Minute {
		t.Errorf("sync timeout %v want >= 15m", d)
	}
}
