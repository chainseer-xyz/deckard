package scope

import (
	"net/netip"
	"os"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustGuard(t *testing.T, cfg config.ScopeConfig, zones []string, prefixes ...string) *Guard {
	t.Helper()
	g, err := NewGuard(cfg)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	g.SetZones(zones)
	var ps []netip.Prefix
	for _, p := range prefixes {
		ps = append(ps, netip.MustParsePrefix(p))
	}
	g.SetOwnedPrefixes(ps)
	return g
}

func TestClassify(t *testing.T) {
	cfg := config.ScopeConfig{
		Include: []string{"*.partner-owned.org", "exact.included.net", "192.0.2.0/28", "203.0.113.7"},
		Exclude: []string{"secret.example.com", "*.legacy.example.com", "gone.org", "198.51.100.0/24", "10.9.9.9", "bücher-ex.de"},
	}
	g := mustGuard(t, cfg, []string{"example.com", "Bücher.DE.", "owned.test", "gone.org"},
		"203.0.114.0/24", "2001:db8:1::/120", "10.0.0.0/24", "198.51.100.5/32")

	h, ip := model.KindHostname, model.KindIP
	tests := []struct {
		name string
		kind model.AssetKind
		key  string
		want model.ScopeClass
	}{
		// owned hostnames
		{"zone apex", h, "example.com", model.ScopeOwned},
		{"subdomain", h, "www.example.com", model.ScopeOwned},
		{"deep subdomain", h, "a.b.c.example.com", model.ScopeOwned},
		{"zone kind", model.KindZone, "example.com", model.ScopeOwned},
		{"upper case", h, "WWW.Example.COM", model.ScopeOwned},
		{"trailing dot", h, "www.example.com.", model.ScopeOwned},
		{"surrounding space", h, " www.example.com ", model.ScopeOwned},
		{"underscore label", h, "_dmarc.example.com", model.ScopeOwned},
		{"punycode form of IDN zone", h, "www.xn--bcher-kva.de", model.ScopeOwned},
		{"unicode form of IDN zone", h, "www.bücher.de", model.ScopeOwned},
		{"unicode upper", h, "WWW.BÜCHER.DE", model.ScopeOwned},
		// lookalikes
		{"prefix lookalike", h, "evil-example.com", model.ScopeExternal},
		{"suffix lookalike", h, "example.com.evil.net", model.ScopeExternal},
		{"no dot boundary", h, "notexample.com", model.ScopeExternal},
		{"different tld", h, "example.org", model.ScopeExternal},
		{"parent of zone", h, "com", model.ScopeExternal},
		{"empty", h, "", model.ScopeExternal},
		{"dot only", h, ".", model.ScopeExternal},
		{"slash injection", h, "evil.net/.example.com", model.ScopeExternal},
		{"at injection", h, "example.com@evil.net", model.ScopeExternal},
		{"port in hostname", h, "evil.net:80.example.com", model.ScopeExternal},
		{"nul byte", h, "a\x00.example.com", model.ScopeExternal},
		{"empty label", h, "a..example.com", model.ScopeExternal},
		// include globs
		{"include wildcard", h, "x.partner-owned.org", model.ScopeOwned},
		{"include wildcard deep", h, "x.y.partner-owned.org", model.ScopeOwned},
		{"include wildcard not apex", h, "partner-owned.org", model.ScopeExternal},
		{"include wildcard lookalike", h, "evilpartner-owned.org", model.ScopeExternal},
		{"include exact", h, "exact.included.net", model.ScopeOwned},
		{"include exact not sub", h, "sub.exact.included.net", model.ScopeExternal},
		{"include exact not parent", h, "included.net", model.ScopeExternal},
		// exclude beats include/owned
		{"exclude exact", h, "secret.example.com", model.ScopeExcluded},
		{"exclude exact subtree", h, "a.secret.example.com", model.ScopeExcluded},
		{"exclude exact case/dot", h, "SECRET.example.com.", model.ScopeExcluded},
		{"exclude wildcard", h, "x.legacy.example.com", model.ScopeExcluded},
		{"exclude wildcard deep", h, "x.y.legacy.example.com", model.ScopeExcluded},
		{"exclude wildcard apex not matched", h, "legacy.example.com", model.ScopeOwned},
		{"exclude vs owned zone conflict", h, "gone.org", model.ScopeExcluded},
		{"exclude IDN pattern, unicode host", h, "www.bücher-ex.de", model.ScopeExcluded},
		{"sibling of excluded stays owned", h, "other.example.com", model.ScopeOwned},
		// IPs
		{"ip in owned prefix", ip, "203.0.114.9", model.ScopeOwned},
		{"ip outside owned prefix", ip, "203.0.115.1", model.ScopeExternal},
		{"ip prefix first", ip, "203.0.114.0", model.ScopeOwned},
		{"ip prefix last", ip, "203.0.114.255", model.ScopeOwned},
		{"ip just below prefix", ip, "203.0.113.255", model.ScopeExternal},
		{"ip just above prefix", ip, "203.0.115.0", model.ScopeExternal},
		{"include single ip", ip, "203.0.113.7", model.ScopeOwned},
		{"include single ip neighbour", ip, "203.0.113.8", model.ScopeExternal},
		{"include cidr", ip, "192.0.2.15", model.ScopeOwned},
		{"include cidr beyond", ip, "192.0.2.16", model.ScopeExternal},
		{"owned v6", ip, "2001:db8:1::1", model.ScopeOwned},
		{"owned v6 expanded", ip, "2001:0db8:0001:0000:0000:0000:0000:0001", model.ScopeOwned},
		{"owned v6 outside", ip, "2001:db8:2::1", model.ScopeExternal},
		{"v4-mapped owned", ip, "::ffff:203.0.114.9", model.ScopeOwned},
		{"v4-mapped external", ip, "::ffff:8.8.8.8", model.ScopeExternal},
		{"private owned when registered", ip, "10.0.0.5", model.ScopeOwned},
		{"private not registered", ip, "10.0.1.5", model.ScopeExternal},
		{"bracketed v6", ip, "[2001:db8:1::1]", model.ScopeOwned},
		{"v6 zone stripped", ip, "2001:db8:1::1%eth0", model.ScopeOwned},
		{"garbage ip", ip, "999.1.1.1", model.ScopeExternal},
		{"empty ip", ip, "", model.ScopeExternal},
		// excluded IPs beat owned prefixes
		{"exclude cidr", ip, "198.51.100.77", model.ScopeExcluded},
		{"exclude cidr beats owned /32", ip, "198.51.100.5", model.ScopeExcluded},
		{"exclude single ip", ip, "10.9.9.9", model.ScopeExcluded},
		{"exclude v4-mapped", ip, "::ffff:10.9.9.9", model.ScopeExcluded},
		{"exclude cidr edge below", ip, "198.51.99.255", model.ScopeExternal},
		{"exclude cidr edge above", ip, "198.51.101.0", model.ScopeExternal},
		// shared infra
		{"cloudflare v4", ip, "104.16.1.1", model.ScopeShared},
		{"cloudflare v4 /20 edge", ip, "173.245.63.255", model.ScopeShared},
		{"cloudflare v4 beyond", ip, "173.245.64.0", model.ScopeExternal},
		{"cloudflare v6", ip, "2606:4700::1111", model.ScopeShared},
		{"cloudflare v4-mapped", ip, "::ffff:104.16.1.1", model.ScopeShared},
		{"cloudflare 162.158/15", ip, "162.159.255.255", model.ScopeShared},
		{"cloudflare 131.0.72/22", ip, "131.0.75.255", model.ScopeShared},
		{"cloudflare 131.0.72/22 beyond", ip, "131.0.76.0", model.ScopeExternal},
		// hostnames given as IP literals are classified as IPs
		{"host-kind ip literal owned", h, "203.0.114.9", model.ScopeOwned},
		{"host-kind ip literal external", h, "8.8.8.8", model.ScopeExternal},
		{"host-kind ip literal excluded", h, "10.9.9.9", model.ScopeExcluded},
		// other kinds
		{"url owned", model.KindURL, "https://www.example.com/x?y=1", model.ScopeOwned},
		{"url external", model.KindURL, "https://evil.net/www.example.com", model.ScopeExternal},
		{"url userinfo trick", model.KindURL, "https://www.example.com@evil.net/", model.ScopeExternal},
		{"url excluded", model.KindURL, "https://secret.example.com/", model.ScopeExcluded},
		{"url ip owned", model.KindURL, "http://203.0.114.9:8080/", model.ScopeOwned},
		{"url garbage", model.KindURL, "://", model.ScopeExternal},
		{"service host:port owned", model.KindService, "www.example.com:443", model.ScopeOwned},
		{"service ip:port owned", model.KindService, "203.0.114.9:22", model.ScopeOwned},
		{"service v6:port owned", model.KindService, "[2001:db8:1::1]:22", model.ScopeOwned},
		{"service ip:port excluded", model.KindService, "10.9.9.9:22", model.ScopeExcluded},
		{"certificate never owned", model.KindCertificate, "www.example.com", model.ScopeExternal},
		{"cloud resource never owned", model.KindCloudResource, "arn:aws:s3:::example.com", model.ScopeExternal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.Classify(tc.kind, tc.key); got != tc.want {
				t.Errorf("Classify(%s, %q) = %s, want %s", tc.kind, tc.key, got, tc.want)
			}
		})
	}
}

func TestOwnedIPNeverInferredFromHostname(t *testing.T) {
	g := mustGuard(t, config.ScopeConfig{}, []string{"example.com"})
	if got := g.Classify(model.KindIP, "93.184.216.34"); got != model.ScopeExternal {
		t.Fatalf("IP must not be owned merely because an owned host may resolve to it, got %s", got)
	}
}

func TestExcludeBeatsOwnedZoneAndInclude(t *testing.T) {
	cfg := config.ScopeConfig{Include: []string{"*.example.com"}, Exclude: []string{"example.com"}}
	g := mustGuard(t, cfg, []string{"example.com"})
	for _, k := range []string{"example.com", "www.example.com", "a.b.example.com"} {
		if got := g.Classify(model.KindHostname, k); got != model.ScopeExcluded {
			t.Errorf("%s = %s, want excluded", k, got)
		}
	}
}

func TestSetZonesAndPrefixesReplace(t *testing.T) {
	g, _ := NewGuard(config.ScopeConfig{})
	if g.Classify(model.KindHostname, "a.example.com") != model.ScopeExternal {
		t.Fatal("no zones: must be external")
	}
	g.SetZones([]string{"example.com", "", "  "})
	if g.Classify(model.KindHostname, "a.example.com") != model.ScopeOwned {
		t.Fatal("zone not applied")
	}
	g.SetZones([]string{"other.com"})
	if g.Classify(model.KindHostname, "a.example.com") != model.ScopeExternal {
		t.Fatal("SetZones must replace, not append")
	}
	g.SetOwnedPrefixes([]netip.Prefix{netip.MustParsePrefix("::ffff:192.0.2.0/120"), {}})
	if g.Classify(model.KindIP, "192.0.2.9") != model.ScopeOwned {
		t.Fatal("v4-mapped prefix not normalised")
	}
	g.SetOwnedPrefixes(nil)
	if g.Classify(model.KindIP, "192.0.2.9") != model.ScopeExternal {
		t.Fatal("SetOwnedPrefixes must replace")
	}
}

func TestOwnedZoneCannotBeBareTLDOrWildcard(t *testing.T) {
	// A zone entry that is a single label (TLD) or a wildcard would own the internet.
	g, _ := NewGuard(config.ScopeConfig{})
	g.SetZones([]string{"com", "*", "*.com", "com."})
	if got := g.Classify(model.KindHostname, "evil.com"); got != model.ScopeExternal {
		t.Fatalf("bare-TLD zone must be ignored, got %s", got)
	}
}

func TestNewGuardRejectsDangerousOrInvalidConfig(t *testing.T) {
	for _, inc := range []string{"*", "*.com", "*.*", "?", "a[", "bad host", "http://x.com", ""} {
		if _, err := NewGuard(config.ScopeConfig{Include: []string{inc}}); err == nil {
			t.Errorf("include %q should be rejected", inc)
		}
	}
	for _, exc := range []string{"a[", "bad host", ""} {
		if _, err := NewGuard(config.ScopeConfig{Exclude: []string{exc}}); err == nil {
			t.Errorf("exclude %q should be rejected", exc)
		}
	}
	if _, err := NewGuard(config.ScopeConfig{Exclude: []string{"*"}}); err != nil {
		t.Errorf("exclude * is safe and allowed: %v", err)
	}
}

func TestIncludeCIDRTooLarge(t *testing.T) {
	if _, err := NewGuard(config.ScopeConfig{Include: []string{"10.0.0.0/8"}, MaxCIDRHosts: 1024}); err == nil {
		t.Fatal("include CIDR exceeding max_cidr_hosts must be rejected")
	}
	if _, err := NewGuard(config.ScopeConfig{Include: []string{"10.0.0.0/24"}, MaxCIDRHosts: 1024}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestSharedList(t *testing.T) {
	g, _ := NewGuard(config.ScopeConfig{})
	if len(g.SharedPrefixes()) < 20 {
		t.Fatalf("embedded list too small: %d", len(g.SharedPrefixes()))
	}
	for _, c := range []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
		"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",
		"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32",
		"2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"} {
		p := netip.MustParsePrefix(c)
		if got := g.Classify(model.KindIP, p.Addr().String()); got != model.ScopeShared {
			t.Errorf("%s first addr = %s, want shared", c, got)
		}
	}
}

func TestOwnedBeatsShared(t *testing.T) {
	g := mustGuard(t, config.ScopeConfig{}, nil, "104.16.5.0/24")
	if got := g.Classify(model.KindIP, "104.16.5.1"); got != model.ScopeOwned {
		t.Fatalf("explicitly owned IP in shared range must be owned, got %s", got)
	}
	if got := g.Classify(model.KindIP, "104.16.6.1"); got != model.ScopeShared {
		t.Fatalf("got %s", got)
	}
}

func TestExcludeBeatsShared(t *testing.T) {
	g := mustGuard(t, config.ScopeConfig{Exclude: []string{"104.16.0.0/16"}}, nil)
	if got := g.Classify(model.KindIP, "104.16.5.1"); got != model.ScopeExcluded {
		t.Fatalf("got %s", got)
	}
}

func TestLoadSharedFile(t *testing.T) {
	path := t.TempDir() + "/shared.txt"
	writeFile(t, path, "# comment\n\n192.0.2.0/24 acme\n2001:db8::/32\n")
	g, err := NewGuard(config.ScopeConfig{}, WithSharedFile(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Classify(model.KindIP, "192.0.2.1"); got != model.ScopeShared {
		t.Errorf("file range: %s", got)
	}
	if got := g.Classify(model.KindIP, "104.16.0.1"); got != model.ScopeShared {
		t.Errorf("embedded list must be kept alongside file: %s", got)
	}
	writeFile(t, path, "198.18.0.0/24\n")
	if err := g.ReloadShared(path); err != nil {
		t.Fatal(err)
	}
	if got := g.Classify(model.KindIP, "192.0.2.1"); got != model.ScopeExternal {
		t.Errorf("reload must replace file ranges: %s", got)
	}
	writeFile(t, path, "not-a-cidr\n")
	if err := g.ReloadShared(path); err == nil {
		t.Error("bad file must error")
	}
	if got := g.Classify(model.KindIP, "198.18.0.1"); got != model.ScopeShared {
		t.Errorf("failed reload must keep previous list: %s", got)
	}
}

func TestAllowed(t *testing.T) {
	tiers := []model.Tier{model.TierPassive, model.TierActive, model.TierIntrusive}
	want := map[model.ScopeClass][3]bool{
		model.ScopeOwned:    {true, true, true},
		model.ScopeShared:   {true, false, false},
		model.ScopeExternal: {true, false, false},
		model.ScopeExcluded: {false, false, false},
	}
	for class, w := range want {
		for i, tier := range tiers {
			if got := Allowed(tier, class); got != w[i] {
				t.Errorf("Allowed(%s,%s)=%v want %v", tier, class, got, w[i])
			}
		}
	}
	for _, bad := range []model.Tier{"", "bogus"} {
		if Allowed(bad, model.ScopeOwned) {
			t.Errorf("unknown tier %q must be denied", bad)
		}
	}
	if Allowed(model.TierPassive, "") || Allowed(model.TierPassive, "weird") {
		t.Error("unknown class must be denied")
	}
}

func TestAllowedFor(t *testing.T) {
	cases := []struct {
		kind  model.AssetKind
		tier  model.Tier
		class model.ScopeClass
		want  bool
	}{
		{model.KindHostname, model.TierPassive, model.ScopeShared, true},
		{model.KindHostname, model.TierPassive, model.ScopeExternal, true},
		{model.KindHostname, model.TierActive, model.ScopeExternal, false},
		{model.KindIP, model.TierPassive, model.ScopeShared, false},
		{model.KindIP, model.TierPassive, model.ScopeExternal, false},
		{model.KindIP, model.TierActive, model.ScopeExternal, false},
		{model.KindIP, model.TierPassive, model.ScopeOwned, true},
		{model.KindIP, model.TierIntrusive, model.ScopeOwned, true},
		{model.KindService, model.TierPassive, model.ScopeShared, false},
		{model.KindService, model.TierActive, model.ScopeOwned, true},
		{model.KindIP, model.TierPassive, model.ScopeExcluded, false},
		{model.KindHostname, model.TierPassive, model.ScopeExcluded, false},
		{model.KindCertificate, model.TierPassive, model.ScopeExternal, false},
	}
	for _, c := range cases {
		if got := AllowedFor(c.kind, c.tier, c.class); got != c.want {
			t.Errorf("AllowedFor(%s,%s,%s)=%v want %v", c.kind, c.tier, c.class, got, c.want)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	g := mustGuard(t, config.ScopeConfig{}, []string{"example.com"})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			g.SetZones([]string{"example.com"})
			g.SetOwnedPrefixes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
		}
	}()
	for i := 0; i < 500; i++ {
		g.Classify(model.KindHostname, "a.example.com")
		g.Classify(model.KindIP, "10.0.0.1")
	}
	<-done
}
