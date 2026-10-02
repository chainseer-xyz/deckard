package nuclei

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// stubResolver answers LookupHost from a table; absent names error.
type stubResolver struct {
	answers map[string][]string
	err     error
}

func (s stubResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	a, ok := s.answers[h]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
	}
	return a, nil
}
func (stubResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (stubResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (stubResolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

// TestNucleiNeverReceivesTargetsResolvingOutOfScope proves, with the real
// guard as verifier, that a recording runner only ever sees owned targets.
func TestNucleiNeverReceivesTargetsResolvingOutOfScope(t *testing.T) {
	res := stubResolver{answers: map[string][]string{
		"good.example.com":   {"198.51.100.7"},
		"hijack.example.com": {"93.184.216.34"},
		"mixed.example.com":  {"198.51.100.7", "93.184.216.34"},
		"excl.example.com":   {"192.0.2.9"},
	}}
	g, err := scope.NewGuard(config.ScopeConfig{MaxCIDRHosts: 1024, Include: []string{"198.51.100.0/24"}, Exclude: []string{"192.0.2.0/24"}}, scope.WithResolver(res))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	g.SetOwnedPrefixes([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})

	tests := []struct {
		host string
		ok   bool
	}{
		{"good.example.com", true},
		{"hijack.example.com", false},
		{"mixed.example.com", false},
		{"excl.example.com", false},
		{"nxdomain.example.com", false},
	}
	for _, tc := range tests {
		fr := &fakeRunner{}
		c := New(config.NucleiConfig{}, g.VerifyOwnedTarget, fr, false, nil)
		_, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://" + tc.host + "/")})
		if tc.ok {
			if err != nil || len(fr.calls) != 1 {
				t.Errorf("%s: want one run, err=%v calls=%d", tc.host, err, len(fr.calls))
			}
			continue
		}
		if !errors.Is(err, ErrOutOfScope) || len(fr.calls) != 0 {
			t.Errorf("%s: want ErrOutOfScope and no run, err=%v calls=%d", tc.host, err, len(fr.calls))
		}
	}

	// A failing resolver also fails closed.
	g2, _ := scope.NewGuard(config.ScopeConfig{MaxCIDRHosts: 1024}, scope.WithResolver(stubResolver{err: errors.New("servfail")}))
	g2.SetZones([]string{"example.com"})
	fr := &fakeRunner{}
	c := New(config.NucleiConfig{}, g2.VerifyOwnedTarget, fr, false, nil)
	if _, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://good.example.com/")}); !errors.Is(err, ErrOutOfScope) || len(fr.calls) != 0 {
		t.Errorf("resolver error: err=%v calls=%d", err, len(fr.calls))
	}
}
