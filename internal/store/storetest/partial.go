package storetest

import (
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func (e *env) reconcilePartial(assetID int64, check string, fs []model.FindingInput, resolveAfter int, now time.Time) store.ReconcileResult {
	e.t.Helper()
	r, err := e.s.ReconcileFindings(e.ctx, store.ReconcileInput{
		AssetID: assetID, Check: check, Findings: fs, ResolveAfter: resolveAfter, Now: now, PartialRun: true,
	})
	if err != nil {
		e.t.Fatalf("ReconcileFindings(partial): %v", err)
	}
	return r
}

// testReconcilePartial pins the partial-run contract: a run that observed only
// a subset of a check's findings (a delta scan) may open and refresh findings
// but must never count misses or resolve anything.
func testReconcilePartial(t *testing.T, f Factory) {
	const check = "cve.nuclei"
	t.Run("empty partial run leaves open findings open and MissedRuns unchanged", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		both := []model.FindingInput{fi(check, "old-cve", model.SeverityHigh), fi(check, "k2", model.SeverityLow)}
		e.reconcile(a.ID, check, both, 3, at(0))
		// A full run misses k2 once: MissedRuns = 1.
		e.reconcile(a.ID, check, both[:1], 3, at(1))
		if got := e.findingByTitle(a.ID, check, "k2").MissedRuns; got != 1 {
			t.Fatalf("setup: MissedRuns = %d, want 1", got)
		}
		for i := 2; i < 8; i++ {
			// ResolveAfter=1 would resolve instantly on a full run.
			r := e.reconcilePartial(a.ID, check, nil, 1, at(i))
			if n := len(r.Opened) + len(r.Reopened) + len(r.Updated) + len(r.Resolved); n != 0 {
				t.Fatalf("partial empty run transitions = %+v", r)
			}
		}
		for _, title := range []string{"old-cve", "k2"} {
			if fd := e.findingByTitle(a.ID, check, title); fd.Status != model.StatusOpen {
				t.Errorf("%s status = %s, want open", title, fd.Status)
			}
		}
		if got := e.findingByTitle(a.ID, check, "k2").MissedRuns; got != 1 {
			t.Errorf("k2 MissedRuns = %d, want unchanged 1", got)
		}
		if got := e.findingByTitle(a.ID, check, "old-cve").MissedRuns; got != 0 {
			t.Errorf("old-cve MissedRuns = %d, want 0", got)
		}
	})
	t.Run("partial run reporting a finding opens it and never resolves others", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		e.reconcile(a.ID, check, []model.FindingInput{fi(check, "known", model.SeverityMedium)}, 1, at(0))
		r := e.reconcilePartial(a.ID, check, []model.FindingInput{fi(check, "CVE-2025-55182", model.SeverityCritical)}, 1, at(1))
		if len(r.Opened) != 1 || len(r.Resolved) != 0 {
			t.Fatalf("opened/resolved = %d/%d, want 1/0", len(r.Opened), len(r.Resolved))
		}
		if fd := e.findingByTitle(a.ID, check, "known"); fd.Status != model.StatusOpen || fd.MissedRuns != 0 {
			t.Errorf("known = %s missed %d", fd.Status, fd.MissedRuns)
		}
		// Seen again in another partial run: refreshed, still one finding.
		r = e.reconcilePartial(a.ID, check, []model.FindingInput{fi(check, "CVE-2025-55182", model.SeverityCritical)}, 1, at(2))
		if len(r.Updated) != 1 || len(r.Opened) != 0 {
			t.Errorf("updated/opened = %d/%d, want 1/0", len(r.Updated), len(r.Opened))
		}
		fs, total, err := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: a.ID})
		if err != nil || total != 2 || len(fs) != 2 {
			t.Fatalf("findings = %d/%d err %v", len(fs), total, err)
		}
	})
	t.Run("a later full run still resolves normally", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		e.reconcile(a.ID, check, []model.FindingInput{fi(check, "k", model.SeverityMedium)}, 2, at(0))
		e.reconcilePartial(a.ID, check, nil, 2, at(1))
		e.reconcilePartial(a.ID, check, nil, 2, at(2))
		if fd := e.findingByTitle(a.ID, check, "k"); fd.Status != model.StatusOpen || fd.MissedRuns != 0 {
			t.Fatalf("after partial runs: %s missed %d", fd.Status, fd.MissedRuns)
		}
		e.reconcile(a.ID, check, nil, 2, at(3))
		r := e.reconcile(a.ID, check, nil, 2, at(4))
		if len(r.Resolved) != 1 {
			t.Fatalf("full run resolved = %d, want 1", len(r.Resolved))
		}
		if fd := e.findingByTitle(a.ID, check, "k"); fd.Status != model.StatusResolved {
			t.Errorf("status = %s, want resolved", fd.Status)
		}
	})
	t.Run("partial run reopens a resolved finding it reports", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		e.reconcile(a.ID, check, []model.FindingInput{fi(check, "k", model.SeverityMedium)}, 1, at(0))
		e.reconcile(a.ID, check, nil, 1, at(1))
		r := e.reconcilePartial(a.ID, check, []model.FindingInput{fi(check, "k", model.SeverityMedium)}, 1, at(2))
		if len(r.Reopened) != 1 {
			t.Fatalf("reopened = %d, want 1", len(r.Reopened))
		}
	})
}
