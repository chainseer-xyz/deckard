package all

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/registry"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestRegisterAllPassive(t *testing.T) {
	r := registry.New()
	if err := Register(r, map[string]map[string]any{"tls.cert": {"warn_days": 30}}); err != nil {
		t.Fatal(err)
	}
	want := []string{"cloud.bucket", "dns.dangling", "dns.hygiene", "dns.takeover", "domain.expiry", "domain.lookalike", "http.headers", "http.probe", "intel.internetdb", "mail.policy", "origin.correlation", "origin.exposed", "tls.cert", "web.history"}
	all := r.All()
	if len(all) != len(want) {
		t.Fatalf("got %d checks", len(all))
	}
	for i, c := range all {
		if c.Name() != want[i] || c.Tier() != model.TierPassive {
			t.Errorf("%d: %s %s", i, c.Name(), c.Tier())
		}
	}
	if got := len(r.ForTier(model.TierPassive)); got != len(want) {
		t.Errorf("ForTier passive = %d", got)
	}
}
