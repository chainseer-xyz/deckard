package registry

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/source"
)

type fakeSrc struct{ name string }

func (f fakeSrc) Name() string { return f.name }
func (f fakeSrc) Type() string { return "fake" }
func (f fakeSrc) Discover(context.Context) (*source.Discovery, error) {
	return &source.Discovery{}, nil
}

func TestBuild(t *testing.T) {
	scope := config.ScopeConfig{MaxCIDRHosts: 8}
	env := func(k string) string {
		if k == "T" {
			return "tok"
		}
		return ""
	}

	s, err := Build(config.SourceConfig{Name: "cf", Type: "cloudflare", TokenEnv: "T"}, scope, env, slog.Default())
	if err != nil || s.Type() != "cloudflare" || s.Name() != "cf" {
		t.Fatalf("cloudflare: %v %v", s, err)
	}
	if _, err := Build(config.SourceConfig{Name: "cf", Type: "cloudflare"}, scope, env, nil); err == nil {
		t.Fatal("want missing token error")
	}

	s, err = Build(config.SourceConfig{Name: "st", Type: "static", IPs: []string{"192.0.2.1"}}, scope, env, nil)
	if err != nil || s.Type() != "static" {
		t.Fatalf("static: %v %v", s, err)
	}
	if _, err := Build(config.SourceConfig{Name: "st", Type: "static", CIDRs: []string{"192.0.2.0/24"}}, scope, env, nil); err == nil {
		t.Fatal("scope.max_cidr_hosts must be enforced")
	}

	_, err = Build(config.SourceConfig{Name: "r", Type: "route53"}, scope, env, nil)
	if err == nil || !strings.Contains(err.Error(), "route53") {
		t.Fatalf("unknown type: %v", err)
	}

	Register("route53", func(cfg config.SourceConfig, _ config.ScopeConfig, _ func(string) string, _ *slog.Logger) (source.Source, error) {
		return fakeSrc{cfg.Name}, nil
	})
	t.Cleanup(func() { mu.Lock(); delete(ctors, "route53"); mu.Unlock() })
	s, err = Build(config.SourceConfig{Name: "r", Type: "route53"}, scope, env, nil)
	if err != nil || s.Name() != "r" {
		t.Fatalf("registered ctor: %v %v", s, err)
	}
}
