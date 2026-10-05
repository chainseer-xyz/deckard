package storetest

import (
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func testInapplicableFindings(t *testing.T, f Factory) {
	t.Run("retires unresolved findings with an explicit reason and preserves decisions", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		statuses := []model.FindingStatus{model.StatusOpen, model.StatusAcknowledged, model.StatusSuppressed, model.StatusFalsePositive}
		var inputs []model.FindingInput
		for _, status := range statuses {
			inputs = append(inputs, fi("retired", string(status), model.SeverityHigh))
		}
		r := e.reconcile(a.ID, "retired", inputs, 1, at(1))
		for i, status := range statuses {
			if err := e.s.ChangeFindingStatus(e.ctx, r.Opened[i].ID, store.StatusChange{Status: status, Note: "operator note", Actor: "operator"}, at(2)); err != nil {
				t.Fatal(err)
			}
		}
		e.reconcile(a.ID, "drift.retired", []model.FindingInput{fi("drift.retired", "drift", model.SeverityLow)}, 1, at(4))
		e.reconcile(a.ID, "other", []model.FindingInput{fi("other", "other", model.SeverityLow)}, 1, at(4))
		n, err := e.s.ResolveInapplicableFindings(e.ctx, *a, "retired", at(5))
		if err != nil || n != 5 {
			t.Fatalf("retired count=%d err=%v", n, err)
		}
		fs, _, err := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: a.ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range fs {
			if finding.Check == "other" {
				if finding.Status != model.StatusOpen {
					t.Error("unrelated finding resolved")
				}
				continue
			}
			if finding.Status != model.StatusResolved || finding.ResolvedAt == nil || !finding.ResolvedAt.Equal(at(5)) {
				t.Errorf("unretired finding: %+v", finding)
			}
		}
		events, err := e.s.ListEvents(e.ctx, at(5), 0)
		if err != nil || len(events) != 5 {
			t.Fatalf("retirement events=%v err=%v", events, err)
		}
		for _, event := range events {
			if event.Type != "finding_resolved" || event.Data["reason"] != "no_longer_applicable" {
				t.Errorf("missing explicit retirement reason: %+v", event)
			}
		}
		if n, err := e.s.ResolveInapplicableFindings(e.ctx, *a, "retired", at(6)); err != nil || n != 0 {
			t.Errorf("duplicate retirement: n=%d err=%v", n, err)
		}
	})
	t.Run("an intervening inventory change refuses stale retirement", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		e.reconcile(a.ID, "retired", []model.FindingInput{fi("retired", "k", model.SeverityHigh)}, 1, at(1))
		updated := host(a.Key, "cf")
		updated.Attrs = map[string]any{"origin": true}
		e.snapshot("cf", []store.AssetUpsert{updated}, nil, at(2))
		if n, err := e.s.ResolveInapplicableFindings(e.ctx, *a, "retired", at(3)); err != nil || n != 0 {
			t.Fatalf("stale decision retired findings: n=%d err=%v", n, err)
		}
		if fs, _, _ := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: a.ID, Check: "retired"}); len(fs) != 1 || fs[0].Status != model.StatusOpen {
			t.Errorf("stale retirement changed finding: %+v", fs)
		}
	})
	t.Run("non-owned and removed caller snapshots refuse retirement", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		e.reconcile(a.ID, "retired", []model.FindingInput{fi("retired", "k", model.SeverityHigh)}, 1, at(1))
		for _, change := range []func(*model.Asset){func(a *model.Asset) { a.Scope = model.ScopeShared }, func(a *model.Asset) { now := time.Now(); a.RemovedAt = &now }} {
			caller := *a
			change(&caller)
			if n, err := e.s.ResolveInapplicableFindings(e.ctx, caller, "retired", at(2)); err != nil || n != 0 {
				t.Errorf("unsafe caller retired findings: n=%d err=%v", n, err)
			}
		}
	})
}
