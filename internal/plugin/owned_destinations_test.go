package plugin

import (
	"context"
	"net/http"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestPluginsRequireOwnedDestinationsAtEveryConfiguredTier(t *testing.T) {
	for _, tier := range []model.Tier{model.TierPassive, model.TierActive, model.TierIntrusive} {
		c := New(config.PluginConfig{Name: "test", Tier: string(tier)}, nil)
		boundary, ok := c.(check.RequiresOwnedDestinations)
		if !ok || !boundary.RequiresOwnedDestinations() || c.Tier() != tier {
			t.Fatalf("plugin tier %s lacks owned-at-dial policy or changed tier", tier)
		}
	}
}

func TestPassivePluginBrokerRejectsRebindingWithOwnedClients(t *testing.T) {
	target, guard, dialer := brokerTarget(t, [][]string{{"198.51.100.7"}, {"198.51.100.7"}, {"93.184.216.34"}},
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("rebound destination received traffic") }))
	target.Neighbours = nil
	cfg := cfgFor("broker-network", map[string]any{"request": networkRequest{Operation: "http", URL: "http://app.example.com/"}})
	cfg.Tier = "passive"
	c := New(cfg, guard.VerifyOwnedTarget)
	res, err := c.Run(context.Background(), target)
	if err == nil || res != nil || dialer.calls.Load() != 0 || c.Tier() != model.TierPassive {
		t.Fatalf("passive plugin escaped owned clients: result = %+v, err = %v, dials = %d", res, err, dialer.calls.Load())
	}
}
