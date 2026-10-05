package scope

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
)

func verifyGuard(t *testing.T, res *fakeResolver) *Guard {
	t.Helper()
	g, err := NewGuard(config.ScopeConfig{MaxCIDRHosts: 1024, Exclude: []string{"192.0.2.0/24"}}, WithResolver(res))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	g.SetOwnedPrefixes(nil)
	g.staticOwned = append(g.staticOwned, mustPrefix("198.51.100.0/24"))
	return g
}

func TestVerifyOwnedTarget(t *testing.T) {
	res := newFakeResolver(map[string][][]string{
		"owned.example.com":    {{"198.51.100.7"}},
		"hijack.example.com":   {{"93.184.216.34"}},
		"mixed.example.com":    {{"198.51.100.7", "93.184.216.34"}},
		"excl.example.com":     {{"192.0.2.9"}},
		"private.example.com":  {{"10.0.0.1"}},
		"empty.example.com":    {{}},
		"garbage.example.com":  {{"not-an-ip"}},
		"v6.example.com":       {{"2001:db8::1"}},
		"outside.other.org":    {{"198.51.100.7"}},
		"owned2.example.com":   {{"198.51.100.8", "198.51.100.9"}},
		"mapped.example.com":   {{"::ffff:198.51.100.7"}},
		"shared.example.com":   {{"104.16.0.1"}},
		"loopback.example.com": {{"127.0.0.1"}},
	})
	g := verifyGuard(t, res)
	tests := []struct {
		host string
		want bool
	}{
		{"owned.example.com", true},
		{"owned2.example.com", true},
		{"mapped.example.com", true},
		{"hijack.example.com", false},
		{"mixed.example.com", false},
		{"excl.example.com", false},
		{"private.example.com", false},
		{"empty.example.com", false},
		{"garbage.example.com", false},
		{"v6.example.com", false},
		{"shared.example.com", false},
		{"loopback.example.com", false},
		{"outside.other.org", false}, // not an owned name at all
		{"nxdomain.example.com", false},
		{"198.51.100.7", true},
		{"93.184.216.34", false},
		{"192.0.2.9", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := g.VerifyOwnedTarget(context.Background(), tc.host); got != tc.want {
			t.Errorf("VerifyOwnedTarget(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestVerifyOwnedTargetResolverError(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"owned.example.com": {{"198.51.100.7"}}})
	res.err = errors.New("servfail")
	g := verifyGuard(t, res)
	if g.VerifyOwnedTarget(context.Background(), "owned.example.com") {
		t.Fatal("resolver error must fail closed")
	}
}

func TestVerifyOwnedTargetRechecksEveryCall(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"owned.example.com": {{"198.51.100.7"}, {"93.184.216.34"}}})
	g := verifyGuard(t, res)
	ctx := context.Background()
	if !g.VerifyOwnedTarget(ctx, "owned.example.com") {
		t.Fatal("first answer is owned")
	}
	if g.VerifyOwnedTarget(ctx, "OWNED.example.com.") {
		t.Fatal("a rebound answer must be refused immediately")
	}
	if res.count["owned.example.com"] != 2 {
		t.Fatalf("expected two lookups, got %d", res.count["owned.example.com"])
	}
}

func TestVerifyOwnedTargetCancelledNotCached(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"owned.example.com": {{"198.51.100.7"}}})
	g := verifyGuard(t, res)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if g.VerifyOwnedTarget(ctx, "owned.example.com") {
		t.Fatal("cancelled lookup must fail closed")
	}
}

func TestVerifyOwnedTargetConcurrent(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"owned.example.com": {{"198.51.100.7"}}})
	g := verifyGuard(t, res)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !g.VerifyOwnedTarget(context.Background(), "owned.example.com") {
				t.Error("want true")
			}
		}()
	}
	wg.Wait()
}
