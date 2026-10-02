package static

import (
	"context"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func keys(d []model.AssetInput, kind model.AssetKind) []string {
	var out []string
	for _, a := range d {
		if a.Kind == kind {
			out = append(out, a.Key)
		}
	}
	return out
}

func TestDiscover(t *testing.T) {
	s, err := New(config.SourceConfig{
		Name:      "ops",
		Type:      "static",
		Hostnames: []string{"Www.Example.com.", " api.example.net "},
		IPs:       []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"},
		CIDRs:     []string{"198.51.100.0/30", "2001:db8::/126", "192.0.2.1/32"},
		URLs:      []string{"HTTPS://Portal.Example.com:8443/Login#frag", "http://203.0.113.5/x", "https://www.example.com/"},
	}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "ops" || s.Type() != "static" {
		t.Fatal("identity")
	}
	d, err := s.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(keys(d.Assets, model.KindHostname), ","); got != "www.example.com,api.example.net,portal.example.com" {
		t.Fatalf("hostnames %s", got)
	}
	ips := keys(d.Assets, model.KindIP)
	// Duplicates merge: 2001:db8::1 is also inside the /126.
	if len(ips) != 2+4+3+1 {
		t.Fatalf("ips %d: %v", len(ips), ips)
	}
	for _, a := range d.Assets {
		if a.Source != "ops" {
			t.Fatalf("source %+v", a)
		}
		if a.Kind == model.KindIP && a.Attrs["owned"] != true {
			t.Fatalf("static ip not owned: %+v", a)
		}
		if a.Kind != model.KindIP && a.Attrs["owned"] != nil {
			t.Fatalf("only ips are owned: %+v", a)
		}
	}
	urls := keys(d.Assets, model.KindURL)
	want := []string{"https://portal.example.com:8443/Login", "http://203.0.113.5/x", "https://www.example.com/"}
	if strings.Join(urls, "|") != strings.Join(want, "|") {
		t.Fatalf("urls %v", urls)
	}
	found := false
	for _, r := range d.Relations {
		if r.FromKey == "portal.example.com" && r.ToKey == want[0] && r.Type == model.RelServes {
			found = true
		}
	}
	if !found {
		t.Fatalf("relations %+v", d.Relations)
	}
}

func TestRejects(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.SourceConfig
		max     int
		wantErr string
	}{
		{"cidr too large", config.SourceConfig{Name: "s", CIDRs: []string{"192.0.2.0/24"}}, 128, "exceeds scope.max_cidr_hosts=128"},
		{"huge v6", config.SourceConfig{Name: "s", CIDRs: []string{"2001:db8::/32"}}, 1024, "exceeds"},
		{"bad cidr", config.SourceConfig{Name: "s", CIDRs: []string{"nope"}}, 1024, "invalid cidr"},
		{"bad ip", config.SourceConfig{Name: "s", IPs: []string{"300.1.1.1"}}, 1024, "invalid ip"},
		{"bad url scheme", config.SourceConfig{Name: "s", URLs: []string{"ftp://example.com"}}, 1024, "invalid url"},
		{"url no host", config.SourceConfig{Name: "s", URLs: []string{"https:///x"}}, 1024, "invalid url"},
		{"bad hostname", config.SourceConfig{Name: "s", Hostnames: []string{"a b.example.com"}}, 1024, "invalid hostname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, tc.max)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCIDRAtLimitAllowed(t *testing.T) {
	s, err := New(config.SourceConfig{Name: "s", CIDRs: []string{"192.0.2.0/30"}}, 4)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := s.Discover(context.Background())
	if len(d.Assets) != 4 {
		t.Fatalf("%d", len(d.Assets))
	}
}

func TestDiscoverHonoursCancelledContext(t *testing.T) {
	s, _ := New(config.SourceConfig{Name: "s"}, 4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Discover(ctx); err == nil {
		t.Fatal("want error")
	}
}
