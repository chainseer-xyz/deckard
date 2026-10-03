package scope

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestDestinationSkip(t *testing.T) {
	res := newFakeResolver(map[string][][]string{
		"cdn.example.com":       {{"104.16.1.1", "104.16.1.2"}},      // Cloudflare edge: shared
		"paas.example.com":      {{"93.184.216.99"}},                 // third party: external
		"own.example.com":       {{"93.184.216.34"}},                 // registered owned IP
		"mixed.example.com":     {{"93.184.216.34", "104.16.1.1"}},   // one bad answer poisons all
		"mixedext.example.com":  {{"93.184.216.99", "104.16.1.1"}},   // shared wins the label
		"priv.example.com":      {{"10.1.2.3", "fd12::5"}},           // split horizon: private
		"mixedpriv.example.com": {{"10.1.2.3", "93.184.216.99"}},     // external wins over private
		"loop.example.com":      {{"127.0.0.1"}},                     // anomaly: guard must refuse loudly
		"meta.example.com":      {{"104.16.1.1", "169.254.169.254"}}, // anomaly even next to a CDN answer
		"excl.example.com":      {{"10.9.9.9"}},                      // excluded IP: anomaly
		"junk.example.com":      {{"not-an-ip"}},                     // unparseable: anomaly
		"empty.example.com":     {{}},                                // no answer: no verdict
		"other.org":             {{"104.16.1.1"}},                    // not an owned name: engine's job
	})
	rec := &recordingDialer{}
	g := netGuard(t, res, rec)
	g.SetOwnedPrefixes([]netip.Prefix{netip.MustParsePrefix("93.184.216.34/32")})

	cases := []struct {
		tier model.Tier
		host string
		want string
	}{
		{model.TierActive, "cdn.example.com", SkipSharedDestination},
		{model.TierIntrusive, "cdn.example.com", SkipSharedDestination},
		{model.TierActive, "CDN.Example.com.", SkipSharedDestination},
		{model.TierActive, "paas.example.com", SkipExternalDestination},
		{model.TierActive, "mixed.example.com", SkipSharedDestination},
		{model.TierActive, "mixedext.example.com", SkipSharedDestination},
		{model.TierActive, "priv.example.com", SkipPrivateDestination},
		{model.TierActive, "mixedpriv.example.com", SkipExternalDestination},
		{model.TierPassive, "cdn.example.com", ""},
		{model.TierActive, "own.example.com", ""},
		{model.TierActive, "loop.example.com", ""},
		{model.TierActive, "meta.example.com", ""},
		{model.TierActive, "excl.example.com", ""},
		{model.TierActive, "junk.example.com", ""},
		{model.TierActive, "empty.example.com", ""},
		{model.TierActive, "nxdomain.example.com", ""},
		{model.TierActive, "secret.example.com", ""}, // excluded name
		{model.TierActive, "other.org", ""},
		{model.TierActive, "104.16.1.1", ""},
		{model.Tier("bogus"), "cdn.example.com", ""},
	}
	for _, tc := range cases {
		reason, detail := g.DestinationSkip(context.Background(), tc.tier, tc.host)
		if reason != tc.want {
			t.Errorf("%s %s: reason %q, want %q (detail %q)", tc.tier, tc.host, reason, tc.want, detail)
			continue
		}
		if reason == "" {
			if detail != "" {
				t.Errorf("%s %s: detail %q without a reason", tc.tier, tc.host, detail)
			}
			continue
		}
		if !strings.Contains(detail, "owned destination") || !strings.Contains(detail, string(tc.tier)) {
			t.Errorf("%s %s: detail %q", tc.tier, tc.host, detail)
		}
		// A skip only ever names what the guard refuses anyway: the guarded
		// dialer must refuse the same destination without dialling.
		_, err := g.Dialer(tc.tier, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", tc.host+":443")
		if !errors.Is(err, ErrOutOfScope) {
			t.Errorf("%s %s: skipped, but the dialer did not refuse it: %v", tc.tier, tc.host, err)
		}
	}
	if calls := rec.Calls(); len(calls) != 0 {
		t.Fatalf("a refused destination reached the network: %v", calls)
	}
}
