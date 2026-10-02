package scope

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

type regressResolver struct{ answers map[string][]string }

func (f regressResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	return f.answers[h], nil
}
func (regressResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (regressResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (regressResolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

type regressDialer struct{ dialed []string }

func (r *regressDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	r.dialed = append(r.dialed, address)
	return nil, errors.New("test dialer: not connecting")
}

func TestDialerNeverDialsNonOwnedHostnames(t *testing.T) {
	for _, tier := range []model.Tier{model.TierPassive, model.TierActive} {
		for _, class := range []model.ScopeClass{model.ScopeOwned, model.ScopeExternal} {
			rec := &regressDialer{}
			g, err := NewGuard(config.ScopeConfig{MaxCIDRHosts: 1024},
				WithDialer(rec), WithResolver(regressResolver{map[string][]string{"evil.org": {"93.184.216.34"}, "16843009": {"1.1.1.1"}}}))
			if err != nil {
				t.Fatal(err)
			}
			g.SetZones([]string{"example.com"})
			for _, target := range []string{"evil.org:80", "16843009:80"} {
				if _, err := g.Dialer(tier, class, nil).DialContext(context.Background(), "tcp", target); err == nil {
					t.Errorf("tier=%s class=%s: dial to %s must be refused", tier, class, target)
				}
			}
			if len(rec.dialed) != 0 {
				t.Errorf("tier=%s class=%s: underlying dialer was invoked for %v", tier, class, rec.dialed)
			}
		}
	}
}

func TestOwnedHostnameStillDialsPassivelyToThirdPartyIP(t *testing.T) {
	rec := &regressDialer{}
	g, _ := NewGuard(config.ScopeConfig{MaxCIDRHosts: 1024},
		WithDialer(rec), WithResolver(regressResolver{map[string][]string{"www.example.com": {"93.184.216.34"}}}))
	g.SetZones([]string{"example.com"})
	_, _ = g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "www.example.com:443")
	if len(rec.dialed) != 1 || rec.dialed[0] != "93.184.216.34:443" {
		t.Fatalf("owned hostname must be reachable passively via its vetted IP, dialed=%v", rec.dialed)
	}
}

func TestSetOwnedPrefixesRejectsDangerousRanges(t *testing.T) {
	g, _ := NewGuard(config.ScopeConfig{MaxCIDRHosts: 1024})
	g.SetOwnedPrefixes([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("8.8.8.0/24"), // 256 hosts: allowed
		netip.MustParsePrefix("8.8.0.0/16"), // 65k hosts: over cap
		netip.MustParsePrefix("169.254.169.254/32"),
		netip.MustParsePrefix("10.1.2.3/32"),            // private LAN/cluster IPs stay ownable
		netip.MustParsePrefix("127.0.0.1/32"),           // loopback never registrable by discovery
		netip.MustParsePrefix("64:ff9b::a9fe:a9fe/128"), // NAT64 form of the metadata IP
	})
	tests := []struct {
		ip   string
		want model.ScopeClass
	}{
		{"8.8.8.8", model.ScopeOwned},
		{"8.8.4.4", model.ScopeExternal},
		{"1.1.1.1", model.ScopeExternal},
		{"169.254.169.254", model.ScopeExternal},
		{"10.1.2.3", model.ScopeOwned},
		{"127.0.0.1", model.ScopeExternal},
		{"64:ff9b::a9fe:a9fe", model.ScopeExternal},
	}
	for _, tc := range tests {
		if got := g.Classify(model.KindIP, tc.ip); got != tc.want && !(tc.want == model.ScopeExternal && got == model.ScopeShared) {
			t.Errorf("%s: got %s want %s", tc.ip, got, tc.want)
		}
	}
}

func TestPublicSuffixGuards(t *testing.T) {
	g, _ := NewGuard(config.ScopeConfig{})
	g.SetZones([]string{"co.uk", "github.io", "example.com"})
	if g.Classify(model.KindHostname, "bank.co.uk") == model.ScopeOwned {
		t.Error("co.uk zone must not own bank.co.uk")
	}
	if g.Classify(model.KindHostname, "victim.github.io") == model.ScopeOwned {
		t.Error("github.io zone must not own victim.github.io")
	}
	if g.Classify(model.KindHostname, "www.example.com") != model.ScopeOwned {
		t.Error("example.com should still be owned")
	}
	for _, bad := range []string{"*.co.uk", "foo.*.com", "*.github.io", "*.com"} {
		if _, err := NewGuard(config.ScopeConfig{Include: []string{bad}}); err == nil {
			t.Errorf("include %q must be rejected", bad)
		}
	}
	for _, good := range []string{"*.example.com", "www.example.co.uk", "*.home.example.com"} {
		if _, err := NewGuard(config.ScopeConfig{Include: []string{good}}); err != nil {
			t.Errorf("include %q must be accepted: %v", good, err)
		}
	}
}
