package scope

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// fakeUpstream answers from a table of zone-file lines and records every
// query that actually reaches the "recursive resolver".
type fakeUpstream struct {
	mu      sync.Mutex
	rrs     map[string][]dns.RR
	queries []string
}

func newUpstream(t *testing.T, lines ...string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{rrs: map[string][]dns.RR{}}
	for _, l := range lines {
		r, err := dns.NewRR(l)
		if err != nil {
			t.Fatal(err)
		}
		n := dnsx.Norm(r.Header().Name)
		u.rrs[n] = append(u.rrs[n], r)
	}
	return u
}

func (u *fakeUpstream) Query(_ context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := dnsx.Norm(name)
	u.queries = append(u.queries, dns.TypeToString[qtype]+" "+n)
	m := new(dns.Msg)
	cur := n
	for i := 0; i < 20; i++ {
		rrs, ok := u.rrs[cur]
		if !ok {
			m.Rcode = dns.RcodeNameError
			break
		}
		next := ""
		for _, r := range rrs {
			if c, ok := r.(*dns.CNAME); ok && qtype != dns.TypeCNAME {
				m.Answer = append(m.Answer, r)
				next = dnsx.Norm(c.Target)
			}
		}
		if next == "" {
			for _, r := range rrs {
				if r.Header().Rrtype == qtype {
					m.Answer = append(m.Answer, r)
				}
			}
			break
		}
		cur = next
	}
	return dnsx.ParseMsg(m, n, qtype, "fake", false), nil
}

func (u *fakeUpstream) asked() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return strings.Join(u.queries, ",")
}

func dnsGuard(t *testing.T, cfg config.ScopeConfig, u dnsx.Querier, opts ...Option) *Guard {
	t.Helper()
	g, err := NewGuard(cfg, append([]Option{WithDNSClient(u)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	return g
}

func TestDNSProvenanceCNAMETargets(t *testing.T) {
	u := newUpstream(t,
		"blog.example.com. 60 IN CNAME mid.vendor.net.",
		"mid.vendor.net. 60 IN CNAME edge.cdn.org.",
		"edge.cdn.org. 60 IN A 192.0.2.1",
		"unrelated.vendor.net. 60 IN A 192.0.2.2",
	)
	g := dnsGuard(t, config.ScopeConfig{}, u)
	q := g.DNS(model.TierPassive, model.ScopeOwned, nil)
	ctx := context.Background()

	// Before any owned query, a third-party name is refused and never sent.
	if _, err := q.Query(ctx, "mid.vendor.net", dns.TypeA); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected refusal, got %v", err)
	}
	if u.asked() != "" {
		t.Fatalf("refused query reached the resolver: %s", u.asked())
	}
	// Owned start: chain is followed through third-party hops.
	ch, err := q.ResolveChain(ctx, "blog.example.com")
	if err != nil || ch.State != dnsx.StateResolved || ch.End != "edge.cdn.org" || ch.Len() != 2 {
		t.Fatalf("%+v %v", ch, err)
	}
	// Hops are now legitimate subjects (provenance recorded)...
	if _, err := q.Query(ctx, "edge.cdn.org", dns.TypeAAAA); err != nil {
		t.Fatalf("hop must be allowed: %v", err)
	}
	// ...but a sibling of a hop, never reached from an owned name, is not.
	for _, n := range []string{"unrelated.vendor.net", "vendor.net", "cdn.org", "192.0.2.2"} {
		if _, err := q.Query(ctx, n, dns.TypeA); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("%s: want ErrOutOfScope, got %v", n, err)
		}
	}
	if strings.Contains(u.asked(), "unrelated") {
		t.Fatalf("unrelated name reached the resolver: %s", u.asked())
	}
}

func TestDNSProvenanceIsPerQuerier(t *testing.T) {
	u := newUpstream(t, "blog.example.com. 60 IN CNAME mid.vendor.net.", "mid.vendor.net. 60 IN A 192.0.2.1")
	g := dnsGuard(t, config.ScopeConfig{}, u)
	a := g.DNS(model.TierPassive, model.ScopeOwned, nil)
	b := g.DNS(model.TierPassive, model.ScopeOwned, nil)
	if _, err := a.ResolveChain(context.Background(), "blog.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Query(context.Background(), "mid.vendor.net", dns.TypeA); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("provenance leaked between queriers: %v", err)
	}
}

func TestDNSProvenanceNSTargetsAndTransitive(t *testing.T) {
	u := newUpstream(t,
		"sub.example.com. 60 IN NS ns1.dnshost.net.",
		"ns1.dnshost.net. 60 IN CNAME real.dnshost.org.",
		"real.dnshost.org. 60 IN A 192.0.2.9",
	)
	q := dnsGuard(t, config.ScopeConfig{}, u).DNS(model.TierPassive, model.ScopeOwned, nil)
	ctx := context.Background()
	if _, err := q.Query(ctx, "ns1.dnshost.net", dns.TypeA); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("NS target must not be queryable before its NS record was seen: %v", err)
	}
	if _, err := q.Query(ctx, "sub.example.com", dns.TypeNS); err != nil {
		t.Fatal(err)
	}
	ch, err := q.ResolveChain(ctx, "ns1.dnshost.net")
	if err != nil || ch.State != dnsx.StateResolved || ch.End != "real.dnshost.org" {
		t.Fatalf("%+v %v", ch, err)
	}
}

func TestDNSProvenanceDepthCap(t *testing.T) {
	var lines []string
	prev := "start.example.com"
	for i := 0; i <= maxProvDepth+2; i++ {
		n := "h" + string(rune('a'+i)) + ".vendor.net"
		lines = append(lines, prev+". 60 IN CNAME "+n+".")
		prev = n
	}
	u := newUpstream(t, lines...)
	q := dnsGuard(t, config.ScopeConfig{}, u).DNS(model.TierPassive, model.ScopeOwned, nil)
	ch, _ := q.ResolveChain(context.Background(), "start.example.com")
	// The chain stops being followable once provenance depth is exhausted:
	// the over-deep hop is refused (unknown), not queried.
	if ch.State == dnsx.StateResolved || ch.Len() > maxProvDepth+1 {
		t.Fatalf("%+v", ch)
	}
	if strings.Contains(u.asked(), "A h"+string(rune('a'+maxProvDepth+1))) {
		t.Fatalf("over-deep hop queried: %s", u.asked())
	}
}

func TestDNSRefusesExcludedIPAndTransferTypes(t *testing.T) {
	u := newUpstream(t,
		"a.example.com. 60 IN CNAME secret.example.com.",
		"secret.example.com. 60 IN A 192.0.2.1",
	)
	g := dnsGuard(t, config.ScopeConfig{Exclude: []string{"secret.example.com"}}, u)
	q := g.DNS(model.TierPassive, model.ScopeOwned, nil)
	ctx := context.Background()
	if _, err := q.Query(ctx, "secret.example.com", dns.TypeA); !errors.Is(err, ErrExcluded) {
		t.Fatalf("%v", err)
	}
	if _, err := q.Query(ctx, "192.0.2.1", dns.TypeA); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("%v", err)
	}
	if _, err := q.Query(ctx, "a.example.com", dns.TypeAXFR); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("%v", err)
	}
	// The recursive resolver may resolve an excluded CNAME target inside the
	// answer for an owned name, but deckard never asks for it itself, and an
	// explicit follow-up query for it is refused (see above).
	if _, err := q.ResolveChain(ctx, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.asked(), "secret") {
		t.Fatalf("excluded name reached the resolver: %s", u.asked())
	}
	if _, err := q.ResolveChain(ctx, "secret.example.com"); !errors.Is(err, ErrExcluded) {
		t.Fatalf("refused start must be an error: %v", err)
	}
}

func TestDNSTierAndClassGate(t *testing.T) {
	u := newUpstream(t, "a.example.com. 60 IN A 192.0.2.1")
	g := dnsGuard(t, config.ScopeConfig{}, u)
	// External assets are only passive.
	q := g.DNS(model.TierActive, model.ScopeExternal, nil)
	if _, err := q.Query(context.Background(), "a.example.com", dns.TypeA); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("%v", err)
	}
	if _, err := g.DNS(model.TierPassive, model.ScopeExcluded, nil).Query(context.Background(), "a.example.com", dns.TypeA); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("%v", err)
	}
	if u.asked() != "" {
		t.Fatal("queries leaked")
	}
}

type dnsHostLimiter struct {
	mu    sync.Mutex
	hosts []string
}

func (c *dnsHostLimiter) Wait(_ context.Context, h string) error {
	c.mu.Lock()
	c.hosts = append(c.hosts, h)
	c.mu.Unlock()
	return nil
}

func TestDNSRateLimited(t *testing.T) {
	u := newUpstream(t, "a.example.com. 60 IN A 192.0.2.1")
	rl := &dnsHostLimiter{}
	q := dnsGuard(t, config.ScopeConfig{}, u).DNS(model.TierPassive, model.ScopeOwned, rl)
	_, _ = q.Query(context.Background(), "a.example.com", dns.TypeA)
	_, _ = q.Query(context.Background(), "evil.org", dns.TypeA) // refused: must not consume budget
	if len(rl.hosts) != 1 || rl.hosts[0] != "a.example.com" {
		t.Fatalf("%v", rl.hosts)
	}
}

type axfrDialer struct {
	mu     sync.Mutex
	dialed []string
}

func (r *axfrDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	r.mu.Lock()
	r.dialed = append(r.dialed, address)
	r.mu.Unlock()
	return nil, errors.New("connection refused")
}

func TestDNSAXFRDialsOnlyOwnedNameserverIPs(t *testing.T) {
	u := newUpstream(t,
		"example.com. 60 IN NS ns1.example.com.",
		"example.com. 60 IN NS ns2.vendor.net.",
		"ns1.example.com. 60 IN A 198.51.100.7",
		"ns2.vendor.net. 60 IN A 203.0.113.9",
	)
	rd := &axfrDialer{}
	g := dnsGuard(t, config.ScopeConfig{}, u, WithDialer(rd))
	g.SetOwnedPrefixes([]netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")})
	q := g.DNS(model.TierPassive, model.ScopeOwned, nil)

	rep, err := q.AXFR(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(rd.dialed) != 1 || rd.dialed[0] != "198.51.100.7:53" {
		t.Fatalf("dialed %v", rd.dialed)
	}
	var skipped, tried int
	for _, a := range rep.Attempts {
		if a.Outcome != dnsx.AXFRSkipped {
			t.Errorf("%+v", a)
		}
		if strings.Contains(a.Note, "not an owned IP") {
			skipped++
		} else {
			tried++
		}
	}
	if skipped != 1 || tried != 1 {
		t.Fatalf("%+v", rep)
	}
	// Only configured-resolver queries happened (no direct auth queries).
	for _, s := range strings.Split(u.asked(), ",") {
		if !strings.HasSuffix(s, "example.com") && !strings.HasSuffix(s, "vendor.net") {
			t.Errorf("unexpected query %s", s)
		}
	}
}

func TestDNSAXFRRefusesNonOwnedZone(t *testing.T) {
	u := newUpstream(t, "vendor.net. 60 IN NS ns.vendor.net.")
	rd := &axfrDialer{}
	q := dnsGuard(t, config.ScopeConfig{}, u, WithDialer(rd)).DNS(model.TierPassive, model.ScopeOwned, nil)
	if _, err := q.AXFR(context.Background(), "vendor.net"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("%v", err)
	}
	if len(rd.dialed) != 0 || u.asked() != "" {
		t.Fatal("must not touch the network")
	}
}
