package all

import (
	"slices"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
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

// TestSlowLookupChecks pins which built-in checks run in the intel queue. The
// fast local DNS checks (the takeover signal) must never be among them; adding
// a check that waits on a remote service means adding it here on purpose.
func TestSlowLookupChecks(t *testing.T) {
	want := []string{"cloud.bucket", "domain.expiry", "domain.lookalike", "intel.internetdb", "web.history"}
	var got []string
	for _, c := range Checks(nil) {
		if s, ok := c.(check.SlowLookups); ok && s.SlowLookups() {
			got = append(got, c.Name())
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("slow-lookup checks = %v, want %v", got, want)
	}
}
