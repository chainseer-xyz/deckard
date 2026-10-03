package scope

import (
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func fixtureBodies(t *testing.T) map[string][]byte {
	t.Helper()
	read := func(n string) []byte {
		b, err := os.ReadFile("testdata/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return map[string][]byte{
		URLCloudflareV4: read("cloudflare-ips-v4.txt"),
		URLCloudflareV6: read("cloudflare-ips-v6.txt"),
		URLAWS:          read("aws-ip-ranges.json"),
		URLFastly:       read("fastly-public-ip-list.json"),
		URLGitHub:       read("github-meta.json"),
	}
}

func labels(ls []LabeledPrefix) map[string][]string {
	m := map[string][]string{}
	for _, l := range ls {
		m[l.Label] = append(m[l.Label], l.Prefix.String())
	}
	return m
}

func TestParseSharedSourcesFixtures(t *testing.T) {
	ls, err := ParseSharedSources(fixtureBodies(t))
	if err != nil {
		t.Fatal(err)
	}
	m := labels(ls)
	for _, label := range []string{"cloudflare", "aws-cloudfront", "aws-globalaccelerator", "aws-s3", "fastly", "github-pages"} {
		if len(m[label]) == 0 {
			t.Errorf("no %s ranges: %v", label, m)
		}
	}
	has := func(label, p string) bool {
		for _, x := range m[label] {
			if x == p {
				return true
			}
		}
		return false
	}
	if !has("aws-cloudfront", "120.52.22.96/27") || !has("aws-globalaccelerator", "3.2.58.0/24") ||
		!has("aws-s3", "52.219.170.0/23") || !has("aws-s3", "2a05:d07a:a000::/40") ||
		!has("fastly", "151.101.0.0/16") || !has("cloudflare", "2606:4700::/32") ||
		!has("github-pages", "185.199.108.153/32") {
		t.Errorf("missing expected ranges: %v", m)
	}
	// Never taken: EC2/AMAZON/ROUTE53 and CLOUDFRONT_ORIGIN_FACING.
	var all []string
	for _, v := range m {
		all = append(all, v...)
	}
	joined := strings.Join(all, " ")
	for _, never := range []string{"35.180.0.0/16", "51.85.0.0/16", "23.254.120.0/21", "2600:f0f0:2::/48", "15.190.244.0/22", "15.177.0.0/18", "130.176.88.0/21", "2600:9000:1000::/36"} {
		if strings.Contains(joined+" ", never+" ") {
			t.Errorf("%s must never be treated as shared", never)
		}
	}
}

func TestParseSharedSourcesSkipsMissingSources(t *testing.T) {
	b := fixtureBodies(t)
	only := map[string][]byte{URLFastly: b[URLFastly]}
	ls, err := ParseSharedSources(only)
	if err != nil || len(labels(ls)) != 1 {
		t.Fatalf("%v %v", ls, err)
	}
}

func TestParseSharedSourcesRejectsBadSources(t *testing.T) {
	good := fixtureBodies(t)
	cases := map[string]struct {
		url  string
		body string
	}{
		"cf html error page": {URLCloudflareV4, "<html>rate limited</html>"},
		"cf empty":           {URLCloudflareV4, ""},
		"cf half garbage":    {URLCloudflareV4, "173.245.48.0/20\nnot-a-cidr\n103.21.244.0/22\nzzz\n"},
		"aws invalid json":   {URLAWS, `{"prefixes": [`},
		"aws empty":          {URLAWS, `{}`},
		"aws only EC2":       {URLAWS, `{"prefixes":[{"ip_prefix":"35.180.0.0/16","service":"EC2"}]}`},
		"aws all garbage":    {URLAWS, `{"prefixes":[{"ip_prefix":"nope","service":"S3"},{"ip_prefix":"also","service":"S3"}]}`},
		"fastly wrong shape": {URLFastly, `[1,2,3]`},
		"fastly empty":       {URLFastly, `{"addresses":[],"ipv6_addresses":[]}`},
		"github no pages":    {URLGitHub, `{"hooks":["192.30.252.0/22"]}`},
		"github null":        {URLGitHub, `null`},
		"binary":             {URLGitHub, "\x00\xff\xfe"},
		"only absurd":        {URLCloudflareV4, "0.0.0.0/0\n1.0.0.0/4\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b := map[string][]byte{}
			for k, v := range good {
				b[k] = v
			}
			b[tc.url] = []byte(tc.body)
			if ls, err := ParseSharedSources(b); err == nil {
				t.Fatalf("want error, got %d ranges", len(ls))
			}
		})
	}
}

func TestSanitizeSharedPrefix(t *testing.T) {
	drop := []string{"0.0.0.0/0", "::/0", "1.0.0.0/4", "8.0.0.0/7", "2000::/12", "127.0.0.0/8", "127.0.0.1/32", "10.0.0.0/8",
		"10.1.0.0/16", "169.254.0.0/16", "169.254.169.254/32", "192.168.1.0/24", "172.16.0.0/12", "100.100.100.200/32",
		"224.0.0.0/4", "fe80::/10", "fd00:ec2::254/128", "::1/128", "0.0.0.0/8",
	}
	for _, s := range drop {
		if _, ok := SanitizeSharedPrefix(netip.MustParsePrefix(s)); ok {
			t.Errorf("%s must be dropped", s)
		}
	}
	// A broad prefix that CONTAINS special space is dropped too (overlap).
	if _, ok := SanitizeSharedPrefix(netip.MustParsePrefix("128.0.0.0/1")); ok {
		t.Error("/1 must be dropped")
	}
	keep := []string{"104.16.0.0/13", "8.0.0.0/8", "151.101.0.0/16", "2606:4700::/32", "185.199.108.153/32", "2a06:98c0::/29", "2400::/16"}
	for _, s := range keep {
		if _, ok := SanitizeSharedPrefix(netip.MustParsePrefix(s)); !ok {
			t.Errorf("%s must be kept", s)
		}
	}
	if p, ok := SanitizeSharedPrefix(netip.MustParsePrefix("104.16.5.7/13")); !ok || p.String() != "104.16.0.0/13" {
		t.Errorf("must mask: %v", p)
	}
	if _, ok := SanitizeSharedPrefix(netip.Prefix{}); ok {
		t.Error("zero prefix")
	}
}

func TestSetSharedRangesRefreshedRangeClassifiesShared(t *testing.T) {
	g, _ := NewGuard(config.ScopeConfig{})
	ip := "45.45.45.9" // synthetic S3 range in the fixture, never in the embedded list
	if got := g.Classify(model.KindIP, ip); got != model.ScopeExternal {
		t.Fatalf("precondition: %s", got)
	}
	ls, err := ParseSharedSources(fixtureBodies(t))
	if err != nil {
		t.Fatal(err)
	}
	emb, _ := EmbeddedSharedPrefixes()
	g.SetSharedRanges(MergeShared(emb, Prefixes(ls)))
	if got := g.Classify(model.KindIP, ip); got != model.ScopeShared {
		t.Errorf("refreshed S3 range: %s, want shared", got)
	}
	if got := g.Classify(model.KindIP, "104.16.0.1"); got != model.ScopeShared {
		t.Errorf("embedded range must stay: %s", got)
	}
	if got := g.Classify(model.KindIP, "2a05:d07a:a000::1"); got != model.ScopeShared {
		t.Errorf("refreshed v6 range: %s", got)
	}
}

func TestEC2RangesNeverShared(t *testing.T) {
	g, _ := NewGuard(config.ScopeConfig{})
	ls, err := ParseSharedSources(fixtureBodies(t))
	if err != nil {
		t.Fatal(err)
	}
	g.SetSharedRanges(Prefixes(ls))
	for _, ip := range []string{"35.180.1.1", "51.85.3.4", "23.254.120.5", "2600:f0f0:2::1", "15.190.244.9"} {
		if got := g.Classify(model.KindIP, ip); got != model.ScopeExternal {
			t.Errorf("EC2/AMAZON-only address %s classified %s, must stay external (ownable)", ip, got)
		}
	}
	// A customer who registers their EC2 address as owned keeps it owned.
	g2 := mustGuard(t, config.ScopeConfig{}, nil, "35.180.1.1/32")
	g2.SetSharedRanges(Prefixes(ls))
	if got := g2.Classify(model.KindIP, "35.180.1.1"); got != model.ScopeOwned {
		t.Errorf("owned EC2 ip: %s", got)
	}
}

func TestClassifyUnregisteredIgnoresRegisteredPrefixes(t *testing.T) {
	g := mustGuard(t, config.ScopeConfig{Include: []string{"198.22.0.0/24"}}, nil, "198.20.0.0/24", "198.23.0.0/24")
	g.SetSharedRanges([]netip.Prefix{
		netip.MustParsePrefix("198.20.0.0/24"),
		netip.MustParsePrefix("198.22.0.0/24"),
	})
	want := map[string]model.ScopeClass{
		"198.20.0.5": model.ScopeShared,   // registered, but its range is shared
		"198.22.0.5": model.ScopeOwned,    // scope.include still wins
		"198.23.0.5": model.ScopeExternal, // registered only
		"not-an-ip":  model.ScopeExternal,
	}
	for ip, w := range want {
		if got := g.ClassifyUnregistered(ip); got != w {
			t.Errorf("ClassifyUnregistered(%s) = %s, want %s", ip, got, w)
		}
	}
	if got := g.Classify(model.KindIP, "198.20.0.5"); got != model.ScopeOwned {
		t.Errorf("Classify precedence changed: %s", got)
	}
}

func TestSetSharedRangesPrecedenceAndSafety(t *testing.T) {
	g := mustGuard(t, config.ScopeConfig{Exclude: []string{"203.0.114.0/24"}}, nil, "198.20.0.0/24")
	g.SetSharedRanges([]netip.Prefix{
		netip.MustParsePrefix("198.20.0.0/24"),  // owned wins
		netip.MustParsePrefix("203.0.114.0/24"), // excluded wins
		netip.MustParsePrefix("198.21.0.0/24"),
		netip.MustParsePrefix("0.0.0.0/0"),      // absurd: dropped
		netip.MustParsePrefix("10.0.0.0/8"),     // private: dropped
		netip.MustParsePrefix("169.254.0.0/16"), // metadata: dropped
		netip.MustParsePrefix("127.0.0.0/8"),    // loopback: dropped
	})
	want := map[string]model.ScopeClass{
		"198.20.0.5": model.ScopeOwned, "203.0.114.5": model.ScopeExcluded, "198.21.0.5": model.ScopeShared,
		"8.8.8.8": model.ScopeExternal, "10.1.1.1": model.ScopeExternal,
	}
	for ip, w := range want {
		if got := g.Classify(model.KindIP, ip); got != w {
			t.Errorf("%s = %s, want %s", ip, got, w)
		}
	}
	for _, p := range g.SharedPrefixes() {
		if p.Bits() < 8 || p.Contains(netip.MustParseAddr("127.0.0.1")) {
			t.Errorf("unsafe prefix kept: %s", p)
		}
	}
	// Replacement semantics and independence from ReloadShared.
	path := t.TempDir() + "/s.txt"
	writeFile(t, path, "198.22.0.0/24\n")
	if err := g.ReloadShared(path); err != nil {
		t.Fatal(err)
	}
	if got := g.Classify(model.KindIP, "198.21.0.5"); got != model.ScopeShared {
		t.Errorf("ReloadShared must not clobber SetSharedRanges: %s", got)
	}
	g.SetSharedRanges(nil)
	if got := g.Classify(model.KindIP, "198.21.0.5"); got != model.ScopeExternal {
		t.Errorf("nil clears live ranges: %s", got)
	}
	if got := g.Classify(model.KindIP, "198.22.0.5"); got != model.ScopeShared {
		t.Errorf("SetSharedRanges must not clobber file ranges: %s", got)
	}
	if got := g.Classify(model.KindIP, "104.16.0.1"); got != model.ScopeShared {
		t.Errorf("embedded must remain: %s", got)
	}
}

func TestSetSharedRangesConcurrent(t *testing.T) {
	g, _ := NewGuard(config.ScopeConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				g.SetSharedRanges([]netip.Prefix{netip.MustParsePrefix("198.21.0.0/24")})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				g.Classify(model.KindIP, "198.21.0.5")
				g.SharedPrefixes()
			}
		}()
	}
	wg.Wait()
}

func TestEmbeddedSnapshotParsesAndRoundTrips(t *testing.T) {
	if _, err := EmbeddedSharedPrefixes(); err != nil {
		t.Fatal(err)
	}
	ls, err := ParseSharedSources(fixtureBodies(t))
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseCIDRList(string(FormatSharedSnapshot(ls)))
	if err != nil || len(back) != len(ls) {
		t.Fatalf("round trip: %v %d != %d", err, len(back), len(ls))
	}
	for _, p := range back {
		if _, ok := SanitizeSharedPrefix(p); !ok {
			t.Errorf("snapshot contains unsafe prefix %s", p)
		}
	}
}
