//go:build live

package nuclei

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Run with: DECKARD_NUCLEI_LIVE_TARGET=https://your-owned-host go test -tags live ./internal/nuclei
// The target must be infrastructure you own.
func TestLiveNuclei(t *testing.T) {
	target := os.Getenv("DECKARD_NUCLEI_LIVE_TARGET")
	if _, err := exec.LookPath("nuclei"); err != nil || target == "" {
		t.Skip("needs the nuclei binary and DECKARD_NUCLEI_LIVE_TARGET")
	}
	c := New(config.NucleiConfig{Enabled: true, SeverityMin: "high"}, func(context.Context, string) bool { return true }, ExecRunner{}, false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := c.Run(ctx, check.Target{Asset: model.Asset{Kind: model.KindURL, Key: target, Scope: model.ScopeOwned}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d findings", len(res.Findings))
}
