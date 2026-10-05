package scope

import (
	"context"
	"errors"
	"math/big"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
)

func policyGuard(t *testing.T, res *fakeResolver) *Guard {
	t.Helper()
	g, err := NewGuard(config.ScopeConfig{MaxCIDRHosts: 1024}, WithResolver(res))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	g.SetOwnedPrefixes([]netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:1::/120"),
	})
	return g
}

func parsePolicy(t *testing.T, denied []string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, value := range denied {
		p, err := netip.ParsePrefix(value)
		if err != nil || p != p.Masked() {
			t.Fatalf("invalid or unmasked policy prefix %q: %v", value, err)
		}
		out = append(out, p)
	}
	return out
}

func policyAllows(denied []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range denied {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// Non-overlapping CIDRs with the exact complement's cardinality, containing
// none of the approved addresses, prove no unintended destination is allowed.
func assertExactComplement(t *testing.T, denied []netip.Prefix, approved []netip.Addr) {
	t.Helper()
	counts := map[int]*big.Int{32: new(big.Int), 128: new(big.Int)}
	approvedCounts := map[int]int{}
	for _, addr := range approved {
		if !policyAllows(denied, addr) {
			t.Errorf("approved address %s was denied", addr)
		}
		approvedCounts[addr.BitLen()]++
	}
	for i, p := range denied {
		for _, q := range denied[:i] {
			if p.Overlaps(q) {
				t.Fatalf("denied prefixes overlap: %s and %s", p, q)
			}
		}
		cardinality := new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
		counts[p.Addr().BitLen()].Add(counts[p.Addr().BitLen()], cardinality)
	}
	for bits, count := range counts {
		want := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		want.Sub(want, big.NewInt(int64(approvedCounts[bits])))
		if count.Cmp(want) != 0 {
			t.Errorf("IPv%d denied count = %s, want %s", bits, count, want)
		}
	}
}

func TestDestinationDenylistExactDualStackComplement(t *testing.T) {
	answers := []string{
		"198.51.100.0", "198.51.100.1", "198.51.100.2", "198.51.100.127", "198.51.100.255",
		"2001:db8:1::", "2001:db8:1::1", "2001:db8:1::2", "2001:db8:1::7f", "2001:db8:1::ff",
	}
	res := newFakeResolver(map[string][][]string{"app.example.com": {answers}})
	g := policyGuard(t, res)
	denied, err := g.DestinationDenylist(context.Background(), []string{"app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	prefixes := parsePolicy(t, denied)
	var approved []netip.Addr
	for _, answer := range answers {
		approved = append(approved, netip.MustParseAddr(answer))
	}
	assertExactComplement(t, prefixes, approved)
	for _, base := range []netip.Addr{netip.MustParseAddr("198.51.100.0"), netip.MustParseAddr("2001:db8:1::")} {
		for i, addr := 0, base; i < 256; i, addr = i+1, addr.Next() {
			if got, want := policyAllows(prefixes, addr), slices.Contains(approved, addr); got != want {
				t.Errorf("allowed(%s) = %v, want %v", addr, got, want)
			}
		}
	}
	for _, address := range []string{"0.0.0.0", "127.0.0.1", "169.254.169.254", "93.184.216.34", "255.255.255.255", "::", "::1", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if policyAllows(prefixes, netip.MustParseAddr(address)) {
			t.Errorf("unapproved address %s was allowed", address)
		}
	}
}

func TestDestinationDenylistDeduplicatesMappedAndLiteralTargets(t *testing.T) {
	res := newFakeResolver(map[string][][]string{
		"app.example.com": {{"198.51.100.7", "::ffff:198.51.100.7", "198.51.100.7"}},
	})
	g := policyGuard(t, res)
	got, err := g.DestinationDenylist(context.Background(), []string{"APP.example.com.", "198.51.100.7", "::ffff:198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := g.DestinationDenylist(context.Background(), []string{"198.51.100.7"})
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("duplicate destinations changed the policy: err = %v", err)
	}
	assertExactComplement(t, parsePolicy(t, got), []netip.Addr{netip.MustParseAddr("198.51.100.7")})
}

func TestDestinationDenylistRechecksDNSAndOwnership(t *testing.T) {
	t.Run("DNS_rebinding", func(t *testing.T) {
		res := newFakeResolver(map[string][][]string{"app.example.com": {{"198.51.100.7"}, {"93.184.216.34"}}})
		g := policyGuard(t, res)
		if _, err := g.DestinationDenylist(context.Background(), []string{"app.example.com"}); err != nil {
			t.Fatal(err)
		}
		if denied, err := g.DestinationDenylist(context.Background(), []string{"app.example.com"}); err == nil || denied != nil {
			t.Fatalf("rebound destination was authorized: denied = %v, err = %v", denied, err)
		}
		if n := res.calls("app.example.com"); n != 2 {
			t.Fatalf("lookups = %d, want two fresh lookups", n)
		}
	})
	for _, which := range []string{"zone", "prefix"} {
		t.Run(which+"_revoked", func(t *testing.T) {
			res := newFakeResolver(map[string][][]string{"app.example.com": {{"198.51.100.7"}}})
			g := policyGuard(t, res)
			if _, err := g.DestinationDenylist(context.Background(), []string{"app.example.com"}); err != nil {
				t.Fatal(err)
			}
			if which == "zone" {
				g.SetZones(nil)
			} else {
				g.SetOwnedPrefixes(nil)
			}
			if denied, err := g.DestinationDenylist(context.Background(), []string{"app.example.com"}); err == nil || denied != nil {
				t.Fatalf("revoked ownership was authorized: denied = %v, err = %v", denied, err)
			}
		})
	}
}

func TestDestinationDenylistFailsClosed(t *testing.T) {
	tooMany := make([]string, 1025)
	for i := range tooMany {
		tooMany[i] = "198.51.100.7"
	}
	for _, tc := range []struct {
		name    string
		hosts   []string
		answers []string
		err     error
		cancel  bool
	}{
		{"empty_targets", nil, nil, nil, false},
		{"no_answers", []string{"app.example.com"}, nil, nil, false},
		{"invalid_answer", []string{"app.example.com"}, []string{"not-an-address"}, nil, false},
		{"mixed_ownership", []string{"app.example.com"}, []string{"198.51.100.7", "93.184.216.34"}, nil, false},
		{"shared", []string{"app.example.com"}, []string{"104.16.0.1"}, nil, false},
		{"unowned_name", []string{"app.other.org"}, []string{"198.51.100.7"}, nil, false},
		{"resolver_error", []string{"app.example.com"}, nil, errors.New("SERVFAIL"), false},
		{"cancelled", []string{"app.example.com"}, []string{"198.51.100.7"}, nil, true},
		{"address_limit", []string{"app.example.com"}, tooMany, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := newFakeResolver(map[string][][]string{"app.example.com": {tc.answers}, "app.other.org": {tc.answers}})
			res.err = tc.err
			g := policyGuard(t, res)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			if denied, err := g.DestinationDenylist(ctx, tc.hosts); err == nil || denied != nil {
				t.Fatalf("invalid targets were authorized: denied = %v, err = %v", denied, err)
			}
		})
	}
}

func TestDestinationDenylistConcurrent(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"app.example.com": {{"198.51.100.7", "2001:db8:1::1"}}})
	g := policyGuard(t, res)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			denied, err := g.DestinationDenylist(context.Background(), []string{"app.example.com"})
			if err != nil || len(denied) == 0 {
				t.Errorf("concurrent policy = %v, err = %v", denied, err)
			}
		}()
	}
	wg.Wait()
	if n := res.calls("app.example.com"); n != 16 {
		t.Fatalf("lookups = %d, want 16 fresh lookups", n)
	}
}
