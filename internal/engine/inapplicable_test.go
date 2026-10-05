package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestInapplicableFindingsResolveWithoutRunningCheck(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		name := "rescan"
		if scheduled {
			name = "scheduler"
		}
		t.Run(name, func(t *testing.T) {
			a := hostAsset(1, "a.example.com")
			c := passiveCheck("origin.example")
			c.applies = func(a model.Asset) bool { owned, _ := a.Attrs["origin"].(bool); return owned }
			h := newHarness(nil, []model.Asset{a}, c)
			h.st.findings = []model.Finding{{ID: 1, AssetID: a.ID, Check: c.Name(), Status: model.StatusOpen},
				{ID: 2, AssetID: a.ID, Check: "drift." + c.Name(), Status: model.StatusAcknowledged},
				{ID: 3, AssetID: a.ID, Check: "other", Status: model.StatusOpen}}
			if scheduled {
				h.st.scans = []store.ScanRun{{AssetID: a.ID, Check: c.Name(), StartedAt: h.now.Add(-time.Hour)}}
				if _, err := h.r.scheduleTier(context.Background(), model.TierPassive); err != nil {
					t.Fatal(err)
				}
			} else if err := h.r.runScan(context.Background(), scanJob{AssetID: a.ID, Tier: model.TierPassive, Check: c.Name()}); err != nil {
				t.Fatal(err)
			}
			if h.st.findings[0].Status != model.StatusResolved || h.st.findings[1].Status != model.StatusResolved || h.st.findings[2].Status != model.StatusOpen {
				t.Fatalf("retired findings: %+v", h.st.findings)
			}
			if c.calls.Load() != 0 || len(h.proc.calls) != 0 || h.g.built.Load() != 0 || len(h.st.scans) > 1 {
				t.Fatal("applicability retirement ran a check, processed a clean result or built network handles")
			}
		})
	}
}

func TestInapplicableRetirementKeepsRefusedAndDisabledFindings(t *testing.T) {
	for name, mutate := range map[string]func(*harness, *model.Asset){
		"disabled tier": func(h *harness, _ *model.Asset) { h.r.Config.Profiles.Passive.Enabled = false },
		"disabled check": func(h *harness, _ *model.Asset) {
			h.r.Config.Checks = map[string]map[string]any{"retired": {"enabled": false}}
		},
		"fresh excluded scope": func(h *harness, a *model.Asset) { h.g.classes[a.Key] = model.ScopeExcluded },
		"fresh shared scope":   func(h *harness, a *model.Asset) { h.g.classes[a.Key] = model.ScopeShared },
		"stored shared scope":  func(_ *harness, a *model.Asset) { a.Scope = model.ScopeShared },
		"ingested asset":       func(_ *harness, a *model.Asset) { a.Source = "ingest:prowler" },
		"removed asset":        func(h *harness, a *model.Asset) { a.RemovedAt = &h.now },
	} {
		t.Run(name, func(t *testing.T) {
			a := hostAsset(1, "a.example.com")
			c := passiveCheck("retired")
			c.applies = func(model.Asset) bool { return false }
			h := newHarness(nil, []model.Asset{a}, c)
			mutate(h, &a)
			h.st.assets[a.ID] = a
			h.st.findings = []model.Finding{{ID: 1, AssetID: a.ID, Check: c.Name(), Status: model.StatusOpen}}
			if err := h.r.runScan(context.Background(), scanJob{AssetID: a.ID, Tier: model.TierPassive, Check: c.Name()}); err != nil {
				t.Fatal(err)
			}
			if got := h.st.findings[0].Status; got != model.StatusOpen {
				t.Fatalf("refused/disabled finding resolved: %s", got)
			}
		})
	}
}

func TestInapplicableRetirementReturnsStoreFailure(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	c := passiveCheck("retired")
	c.applies = func(model.Asset) bool { return false }
	h := newHarness(nil, []model.Asset{a}, c)
	h.st.findingsErr = errors.New("database unavailable")
	if err := h.r.runScan(context.Background(), scanJob{AssetID: a.ID, Tier: model.TierPassive, Check: c.Name()}); err == nil {
		t.Fatal("retirement failure must retry the job")
	}
}

func TestInapplicableRetirementKeepsUnownedDestinationFindings(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	c := &fakeCheck{name: "retired", tier: model.TierActive, applies: func(model.Asset) bool { return false }}
	h, _ := newSkipHarness(nil, []model.Asset{a}, map[string]string{a.Key: scope.SkipSharedDestination}, c)
	h.st.findings = []model.Finding{{ID: 1, AssetID: a.ID, Check: c.Name(), Status: model.StatusOpen}}
	if err := h.r.runScan(context.Background(), scanJob{AssetID: a.ID, Tier: c.Tier(), Check: c.Name()}); err != nil {
		t.Fatal(err)
	}
	if h.st.findings[0].Status != model.StatusOpen {
		t.Fatal("destination refusal retired findings")
	}
}
