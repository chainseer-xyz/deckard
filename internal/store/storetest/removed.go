package storetest

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// testRemovedAssetFindings pins what happens to findings when their asset is
// removed from the inventory (review item C1).
func testRemovedAssetFindings(t *testing.T, f Factory) {
	const check = "http.headers"
	seed := func(e *env) (a *model.Asset, ids map[string]int64) {
		a = e.seedHost("a.x.io", "cf", at(0))
		e.reconcile(a.ID, check, []model.FindingInput{
			fi(check, "open", model.SeverityHigh), fi(check, "ack", model.SeverityHigh),
			fi(check, "sup", model.SeverityHigh), fi(check, "fp", model.SeverityHigh),
		}, 1, at(1))
		ids = map[string]int64{}
		for _, k := range []string{"open", "ack", "sup", "fp"} {
			ids[k] = e.findingByTitle(a.ID, check, k).ID
		}
		for k, st := range map[string]model.FindingStatus{"ack": model.StatusAcknowledged, "sup": model.StatusSuppressed, "fp": model.StatusFalsePositive} {
			if err := e.s.ChangeFindingStatus(e.ctx, ids[k], store.StatusChange{Status: st, Note: "n", Actor: "me"}, at(2)); err != nil {
				t.Fatal(err)
			}
		}
		return a, ids
	}

	t.Run("removal resolves open and acknowledged only", func(t *testing.T) {
		e := newEnv(t, f)
		a, ids := seed(e)
		e.snapshot("cf", nil, nil, at(10))

		for k, want := range map[string]model.FindingStatus{
			"open": model.StatusResolved, "ack": model.StatusResolved,
			"sup": model.StatusSuppressed, "fp": model.StatusFalsePositive,
		} {
			if got := e.finding(ids[k]).Status; got != want {
				t.Errorf("%s status = %s, want %s", k, got, want)
			}
		}
		if f := e.finding(ids["open"]); f.ResolvedAt == nil || !f.ResolvedAt.Equal(at(10)) {
			t.Errorf("ResolvedAt = %v, want %v", f.ResolvedAt, at(10))
		}
		rs, err := e.s.ResolvedSince(e.ctx, at(10))
		if err != nil || len(rs) != 2 {
			t.Fatalf("ResolvedSince = %d, %v; want 2", len(rs), err)
		}
		evs, _ := e.s.ListEvents(e.ctx, at(10), 0)
		n := 0
		for _, ev := range evs {
			if ev.Type == "finding_resolved" && ev.Subject == "a.x.io" {
				n++
			}
		}
		if n != 2 {
			t.Errorf("finding_resolved events = %d, want 2", n)
		}

		// Suppressed/false-positive findings of removed assets are hidden from
		// listings unless the caller asks for them (or names the asset).
		sf := []model.FindingStatus{model.StatusSuppressed, model.StatusFalsePositive}
		sup, _, _ := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: sf})
		if len(sup) != 0 {
			t.Errorf("default listing includes %d findings of removed asset", len(sup))
		}
		sup, _, _ = e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: sf, IncludeRemovedAssets: true})
		if len(sup) != 2 {
			t.Errorf("IncludeRemovedAssets listing = %d, want 2", len(sup))
		}
		byAsset, _, _ := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: a.ID})
		if len(byAsset) != 4 {
			t.Errorf("AssetID listing = %d, want 4", len(byAsset))
		}
		// Resolved history stays visible.
		res, _, _ := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusResolved}})
		if len(res) != 2 {
			t.Errorf("resolved listing = %d, want 2", len(res))
		}
	})

	t.Run("open listing excludes findings of removed assets", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		e.snapshot("cf", nil, nil, at(1))
		// A scan that raced the removal opens a finding on the removed asset.
		e.reconcile(a.ID, check, []model.FindingInput{fi(check, "late", model.SeverityHigh)}, 1, at(2))
		open, n, _ := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusOpen}})
		if len(open) != 0 || n != 0 {
			t.Errorf("open listing = %d (total %d), want 0", len(open), n)
		}
		open, _, _ = e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusOpen}, IncludeRemovedAssets: true})
		if len(open) != 1 {
			t.Errorf("IncludeRemovedAssets open listing = %d, want 1", len(open))
		}
		st, _ := e.s.Stats(e.ctx)
		if len(st.FindingsBySev) != 0 {
			t.Errorf("stats count findings of removed assets: %+v", st.FindingsBySev)
		}
	})

	t.Run("revival does not reopen; next detection does", func(t *testing.T) {
		e := newEnv(t, f)
		a, ids := seed(e)
		e.snapshot("cf", nil, nil, at(10))
		e.snapshot("cf", []store.AssetUpsert{host("a.x.io", "cf")}, nil, at(11))
		if got := e.finding(ids["open"]).Status; got != model.StatusResolved {
			t.Fatalf("status after revive = %s, want resolved", got)
		}
		open, _, _ := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusOpen}})
		if len(open) != 0 {
			t.Errorf("open after revive = %d", len(open))
		}
		r := e.reconcile(a.ID, check, []model.FindingInput{fi(check, "open", model.SeverityHigh)}, 1, at(12))
		if len(r.Reopened) != 1 || r.Reopened[0].ID != ids["open"] {
			t.Errorf("reconcile after revive = %+v", r)
		}
	})
}
