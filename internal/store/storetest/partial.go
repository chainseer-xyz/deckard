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

// testReconcileAcrossKinds pins that two assets sharing one key (a zone and
// its apex hostname both exist as assets, e.g. from an apex DNS record) can
// each hold the finding a kind-agnostic check reports under the same check
// and finding key. The fingerprint formula sees only (check, key, finding
// key), so the two findings collide on the fingerprint value; uniqueness is
// per asset and both reconciles must succeed independently.
func testReconcileAcrossKinds(t *testing.T, f Factory) {
	const check = "dns.dangling"
	e := newEnv(t, f)
	e.snapshot("cf", []store.AssetUpsert{
		au(model.KindZone, "x.io", "cf", model.ScopeOwned, nil),
		au(model.KindHostname, "x.io", "cf", model.ScopeOwned, nil),
	}, nil, at(0))
	zone := e.asset(model.KindZone, "x.io")
	apex := e.asset(model.KindHostname, "x.io")

	ns := fi(check, "ns:dead.ns.example", model.SeverityCritical)
	if r := e.reconcile(zone.ID, check, []model.FindingInput{ns}, 2, at(1)); len(r.Opened) != 1 {
		t.Fatalf("zone reconcile opened = %d, want 1", len(r.Opened))
	}
	r := e.reconcile(apex.ID, check, []model.FindingInput{ns}, 2, at(1))
	if len(r.Opened) != 1 {
		t.Fatalf("apex reconcile opened = %d, want 1 (same fingerprint on another asset)", len(r.Opened))
	}

	// Both findings live their own lifecycle: resolving one leaves the other.
	e.reconcile(apex.ID, check, nil, 2, at(2))
	r = e.reconcile(apex.ID, check, nil, 2, at(3))
	if len(r.Resolved) != 1 {
		t.Fatalf("apex resolve = %d, want 1", len(r.Resolved))
	}
	if fd := e.findingByTitle(zone.ID, check, ns.Title); fd.Status != model.StatusOpen {
		t.Errorf("zone finding status = %s, want open", fd.Status)
	}
	// And the apex finding can reopen after its sibling resolved it its way.
	if r := e.reconcile(apex.ID, check, []model.FindingInput{ns}, 2, at(4)); len(r.Reopened) != 1 {
		t.Errorf("apex reopen = %d, want 1", len(r.Reopened))
	}
}
