package engine

import (
	"context"
	"strconv"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestRunScanOpenFindingsTruncationIsExplicit(t *testing.T) {
	for _, n := range []int{check.MaxOpenFindings, check.MaxOpenFindings + 1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			a := hostAsset(1, "a.example.com")
			wants := wantsCheck{passiveCheck("c.wants")}
			h := newHarness(nil, []model.Asset{a}, wants)
			for i := 0; i < n; i++ {
				h.st.findings = append(h.st.findings, unresolvedFinding(int64(i+1), 1, wants.Name(), model.StatusOpen))
			}
			if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
				t.Fatal(err)
			}
			if len(wants.targets) != 1 {
				t.Fatalf("targets = %d, want 1", len(wants.targets))
			}
			got := wants.targets[0]
			if len(got.OpenFindings) != check.MaxOpenFindings || got.OpenFindingsTruncated != (n > check.MaxOpenFindings) {
				t.Fatalf("findings = %d, truncated = %v for total %d", len(got.OpenFindings), got.OpenFindingsTruncated, n)
			}
		})
	}
}
