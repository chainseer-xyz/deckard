package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// A successful run that discovers nothing must still call ReplaceDerived, so
// that closed ports / removed SANs are garbage-collected (C3, C5).
func TestRunScanSuccessWithNothingDiscoveredStillReplacesDerived(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	c := &fakeCheck{name: "net.ports", tier: model.TierPassive}
	h := newHarness(nil, []model.Asset{a}, c)
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	rc := h.inv.replCalls()
	if len(rc) != 1 || rc[0].parent != 1 || rc[0].origin != "net.ports" || len(rc[0].assets) != 0 || len(rc[0].rels) != 0 {
		t.Fatalf("ReplaceDerived calls: %+v", rc)
	}
	if len(h.inv.discOrig) != 0 {
		t.Fatalf("AddDiscovered must not be used for check results: %v", h.inv.discOrig)
	}
}

func TestRunScanPassesRelationsToReplaceDerived(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	rel := model.RelationInput{}
	c := &fakeCheck{name: "net.ports", tier: model.TierPassive,
		run: func(context.Context, check.Target) (*check.Result, error) {
			return &check.Result{
				Discovered: []model.AssetInput{{Kind: model.KindService, Key: "a.example.com:80/tcp"}},
				Relations:  []model.RelationInput{rel},
			}, nil
		}}
	h := newHarness(nil, []model.Asset{a}, c)
	_ = h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive})
	rc := h.inv.replCalls()
	if len(rc) != 1 || len(rc[0].assets) != 1 || len(rc[0].rels) != 1 {
		t.Fatalf("ReplaceDerived calls: %+v", rc)
	}
}

// A partial run proves nothing absent, so it must not garbage-collect the
// derived children it did not see: removing them would also resolve their
// findings, which a partial run must never do.
func TestRunScanPartialNeverReplacesDerived(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	c := &fakeCheck{name: "dns.dangling", tier: model.TierPassive,
		run: func(context.Context, check.Target) (*check.Result, error) {
			return &check.Result{Partial: true}, nil
		}}
	h := newHarness(nil, []model.Asset{a}, c)

	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}

	if rc := h.inv.replCalls(); len(rc) != 0 {
		t.Fatalf("partial run called ReplaceDerived: %+v", rc)
	}
	if runs := h.st.runs(); len(runs) != 1 || runs[0].Error != "" {
		t.Fatalf("expected one successful run: %+v", runs)
	}
}

// A failed scan must never garbage-collect anything.
func TestRunScanFailureNeverReplacesDerived(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	for name, tc := range map[string]struct {
		run     func(context.Context, check.Target) (*check.Result, error)
		procErr error
		timeout bool
	}{
		"error": {run: func(context.Context, check.Target) (*check.Result, error) { return nil, errors.New("boom") }},
		"panic": {run: func(context.Context, check.Target) (*check.Result, error) { panic("kaboom") }},
		"timeout": {timeout: true, run: func(ctx context.Context, _ check.Target) (*check.Result, error) {
			<-ctx.Done()
			return &check.Result{}, nil
		}},
		"process error": {procErr: errors.New("db"), run: func(context.Context, check.Target) (*check.Result, error) {
			return &check.Result{}, nil
		}},
	} {
		t.Run(name, func(t *testing.T) {
			c := &fakeCheck{name: "net.ports", tier: model.TierPassive, run: tc.run}
			h := newHarness(func(cfg *testCfg) {
				if tc.timeout {
					cfg.Checks = map[string]map[string]any{"net.ports": {"timeout": "50ms"}}
				}
			}, []model.Asset{a}, c)
			h.proc.err = tc.procErr
			_ = h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive})
			if rc := h.inv.replCalls(); len(rc) != 0 {
				t.Fatalf("failed scan called ReplaceDerived: %+v", rc)
			}
			runs := h.st.runs()
			if len(runs) != 1 || runs[0].Error == "" {
				t.Fatalf("expected one failed run: %+v", runs)
			}
		})
	}
}

func TestRunScanReplaceDerivedErrorIsRecordedAsFailure(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	c := &fakeCheck{name: "net.ports", tier: model.TierPassive}
	h := newHarness(nil, []model.Asset{a}, c)
	h.inv.discErr = errors.New("db down")
	_ = h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive})
	runs := h.st.runs()
	if len(runs) != 1 || !strings.Contains(runs[0].Error, "db down") {
		t.Fatalf("runs: %+v", runs)
	}
	// A failed bookkeeping step counts as a failed attempt, not a success.
	ls, _ := h.st.LastScans(context.Background())
	if len(ls) != 1 || !ls[0].LastSuccess.IsZero() {
		t.Fatalf("LastScans: %+v", ls)
	}
}
