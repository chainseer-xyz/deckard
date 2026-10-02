package plugin

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	scopepkg "github.com/chainseer-xyz/deckard/internal/scope"
)

type stubResolver map[string][]string

func (s stubResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	a, ok := s[h]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
	}
	return a, nil
}
func (stubResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (stubResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (stubResolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

// A plugin must never be started for an owned name whose DNS points at a
// third party, and must not be told about such neighbours either.
func TestPluginNotInvokedForNamesResolvingOutOfScope(t *testing.T) {
	g, err := scopepkg.NewGuard(config.ScopeConfig{MaxCIDRHosts: 1024, Include: []string{"198.51.100.0/24"}},
		scopepkg.WithResolver(stubResolver{
			"hijack.example.com": {"93.184.216.34"},
			"mixed.example.com":  {"198.51.100.7", "93.184.216.34"},
		}))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	cfg := cfgFor("echo", nil)
	cfg.Exec = []string{"/nonexistent/should-never-run"}
	for _, h := range []string{"hijack.example.com", "mixed.example.com", "nxdomain.example.com"} {
		tg := check.Target{Asset: model.Asset{Kind: model.KindHostname, Key: h, Scope: model.ScopeOwned}}
		_, err := New(cfg, g.VerifyOwnedTarget).Run(context.Background(), tg)
		if err == nil || !strings.Contains(err.Error(), "not in scope") {
			t.Errorf("%s: want refusal before exec, got %v", h, err)
		}
	}
}
