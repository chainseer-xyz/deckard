package nuclei

import (
	"context"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
)

// The engine caps the view before handing it to Nuclei. The template planner
// cannot infer that omitted findings exist from the bounded slice alone.
func TestReverifyTruncatedEngineViewIsPartial(t *testing.T) {
	for _, tc := range []struct {
		name      string
		n         int
		truncated bool
	}{
		{"truncated", check.MaxOpenFindings, true},
		{"short_truncated_view", 1, true},
		{"exact_cap_complete", check.MaxOpenFindings, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := reverifyTree(t)
			fr := &fakeRunner{}
			c := New(config.NucleiConfig{TemplatesDir: root}, verifyOnly("app.example.com"), fr, false, nil)
			open := make([]check.OpenFinding, tc.n)
			for i := range open {
				open[i] = openOf("git-config")[0]
			}
			res, err := c.Run(context.Background(), check.Target{
				Asset: urlAsset("https://app.example.com/"), OpenFindings: open, OpenFindingsTruncated: tc.truncated,
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Partial != tc.truncated {
				t.Fatalf("partial = %v, want %v: only omitted findings prevent resolution", res.Partial, tc.truncated)
			}
			if len(fr.calls) != 1 {
				t.Fatalf("calls = %d, want only the tech scan for an already-covered template", len(fr.calls))
			}
		})
	}
}
