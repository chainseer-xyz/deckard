package storetest

import (
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/store"
)

// testScanHistory pins LastScans and PruneScans (review item C6, store part).
func testScanHistory(t *testing.T, f Factory) {
	type k struct {
		asset int64
		check string
	}
	record := func(e *env, asset int64, check string, started time.Time, errMsg string) {
		t.Helper()
		if err := e.s.RecordScan(e.ctx, store.ScanRun{AssetID: asset, Check: check, Tier: "passive", StartedAt: started, Error: errMsg}); err != nil {
			t.Fatal(err)
		}
	}
	last := func(e *env) map[k]store.ScanLast {
		t.Helper()
		ls, err := e.s.LastScans(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[k]store.ScanLast{}
		for _, l := range ls {
			if _, dup := out[k{l.AssetID, l.Check}]; dup {
				t.Fatalf("duplicate row for %d/%s", l.AssetID, l.Check)
			}
			out[k{l.AssetID, l.Check}] = l
		}
		return out
	}

	t.Run("empty", func(t *testing.T) {
		e := newEnv(t, f)
		if ls, err := e.s.LastScans(e.ctx); err != nil || len(ls) != 0 {
			t.Errorf("LastScans = %v, %v", ls, err)
		}
	})

	t.Run("last attempt and last success per asset and check", func(t *testing.T) {
		e := newEnv(t, f)
		a, b := e.seedHost("a.x.io", "cf", at(0)), e.seedHost("b.x.io", "cf", at(0))
		record(e, a.ID, "c1", at(1), "")
		record(e, a.ID, "c1", at(4), "timeout")
		record(e, a.ID, "c1", at(2), "")
		record(e, a.ID, "c2", at(2), "refused")
		record(e, b.ID, "c1", at(5), "")
		got := last(e)
		if len(got) != 3 {
			t.Fatalf("rows = %d, want 3: %+v", len(got), got)
		}
		if l := got[k{a.ID, "c1"}]; !l.LastAttempt.Equal(at(4)) || !l.LastSuccess.Equal(at(2)) {
			t.Errorf("a/c1 = %+v", l)
		}
		if l := got[k{a.ID, "c2"}]; !l.LastAttempt.Equal(at(2)) || !l.LastSuccess.IsZero() {
			t.Errorf("a/c2 = %+v", l)
		}
		if l := got[k{b.ID, "c1"}]; !l.LastAttempt.Equal(at(5)) || !l.LastSuccess.Equal(at(5)) {
			t.Errorf("b/c1 = %+v", l)
		}
	})

	t.Run("an unowned-destination skip settles scheduling, other skips do not", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		record(e, a.ID, "c1", at(1), "")
		record(e, a.ID, "c1", at(3), store.UnownedDestinationSkip+"a.x.io resolves to shared address(es) 104.16.1.1")
		record(e, a.ID, "c2", at(1), "")
		record(e, a.ID, "c2", at(3), store.SkippedPrefix+"profile: active tier disabled for this asset")
		got := last(e)
		if l := got[k{a.ID, "c1"}]; !l.LastAttempt.Equal(at(3)) || !l.LastSuccess.Equal(at(3)) {
			t.Errorf("c1 = %+v, want the destination skip to settle it", l)
		}
		if l := got[k{a.ID, "c2"}]; !l.LastAttempt.Equal(at(3)) || !l.LastSuccess.Equal(at(1)) {
			t.Errorf("c2 = %+v, want other skips to stay unsettled", l)
		}
	})

	t.Run("PruneScans deletes runs older than the cutoff", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		record(e, a.ID, "c1", at(1), "")
		record(e, a.ID, "c1", at(2), "x")
		record(e, a.ID, "c1", at(3), "")
		record(e, a.ID, "c2", at(1), "")
		n, err := e.s.PruneScans(e.ctx, at(3))
		if err != nil || n != 3 {
			t.Fatalf("PruneScans = %d, %v; want 3", n, err)
		}
		runs, _ := e.s.ListScans(e.ctx, 0)
		if len(runs) != 1 || !runs[0].StartedAt.Equal(at(3)) {
			t.Errorf("remaining runs = %+v", runs)
		}
		got := last(e)
		if len(got) != 2 || !got[k{a.ID, "c1"}].LastSuccess.Equal(at(3)) || !got[k{a.ID, "c2"}].LastSuccess.Equal(at(1)) {
			t.Errorf("LastScans after prune = %+v", got)
		}
		if n, err := e.s.PruneScans(e.ctx, at(3)); err != nil || n != 0 {
			t.Errorf("second prune = %d, %v", n, err)
		}
		if _, err := e.s.PruneScans(e.ctx, at(4)); err != nil {
			t.Fatal(err)
		}
		if runs, err := e.s.ListScans(e.ctx, 0); err != nil || len(runs) != 0 {
			t.Fatalf("all history pruned: runs=%v err=%v", runs, err)
		}
		if remaining := last(e); len(remaining) != 2 || !remaining[k{a.ID, "c1"}].LastAttempt.Equal(at(3)) {
			t.Errorf("scheduling state disappeared with history: %+v", remaining)
		}
	})
}
