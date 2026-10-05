//go:build live

package nuclei

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// Set DECKARD_NUCLEI_LIVE_TARGET and DECKARD_NUCLEI_LIVE_OWNED_IPS (comma-separated
// owned IPs/CIDRs), then run go test -tags live ./internal/nuclei.
// The operator must own both the hostname and its explicitly declared addresses.
func TestLiveNuclei(t *testing.T) {
	target := os.Getenv("DECKARD_NUCLEI_LIVE_TARGET")
	ips := os.Getenv("DECKARD_NUCLEI_LIVE_OWNED_IPS")
	if _, err := exec.LookPath("nuclei"); err != nil || target == "" || ips == "" {
		t.Skip("needs nuclei, DECKARD_NUCLEI_LIVE_TARGET and DECKARD_NUCLEI_LIVE_OWNED_IPS")
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		t.Fatal("invalid live target URL")
	}
	guard, err := scope.NewGuard(config.ScopeConfig{Include: append(strings.Split(ips, ","), u.Hostname())})
	if err != nil {
		t.Fatal(err)
	}
	c := New(config.NucleiConfig{Enabled: true, SeverityMin: "high"}, guard.VerifyOwnedTarget,
		ExecRunner{Policy: guard.DestinationDenylist}, false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := c.Run(ctx, check.Target{Asset: model.Asset{Kind: model.KindURL, Key: target, Scope: model.ScopeOwned}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d findings", len(res.Findings))
}
