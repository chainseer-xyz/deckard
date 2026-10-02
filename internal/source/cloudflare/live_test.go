//go:build live

package cloudflare

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
)

// Run with: CF_API_TOKEN=... go test -tags live -run Live -v ./internal/source/cloudflare
// Read-only; logs counts only (no names or IDs).
func TestLiveDiscover(t *testing.T) {
	if os.Getenv("CF_API_TOKEN") == "" {
		t.Skip("CF_API_TOKEN not set")
	}
	s, err := New(config.SourceConfig{Name: "live", Type: "cloudflare", TokenEnv: "CF_API_TOKEN", AccountID: os.Getenv("CF_ACCOUNT_ID")},
		os.Getenv, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	d, err := s.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	kinds := map[string]int{}
	for _, a := range d.Assets {
		kinds[string(a.Kind)]++
	}
	t.Logf("zones=%d assets=%d relations=%d kinds=%v", len(d.Zones), len(d.Assets), len(d.Relations), kinds)
}
