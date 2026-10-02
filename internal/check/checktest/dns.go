package checktest

import (
	"context"
	"fmt"
	"sync"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
)

// DNS is a scripted check.DNSQuerier. Records are added as zone-file lines;
// queries behave like a recursive resolver that follows CNAMEs inside the
// script: unscripted names answer NXDOMAIN (with the CNAME chain so far when a
// chain dangles), names marked Exists answer NODATA, Servfail names answer
// SERVFAIL, and Timeout names fail with dnsx.ErrUnavailable.
type DNS struct {
	mu       sync.Mutex
	rrs      map[string][]dns.RR
	exists   map[string]bool
	servfail map[string]bool
	timeout  map[string]bool
	ad       map[string]bool
	axfr     map[string]dnsx.AXFRReport
	// Calls records "<TYPE> <name>" for every Query.
	Calls []string
}

// NewDNS returns an empty scripted querier.
func NewDNS() *DNS {
	return &DNS{rrs: map[string][]dns.RR{}, exists: map[string]bool{}, servfail: map[string]bool{},
		timeout: map[string]bool{}, ad: map[string]bool{}, axfr: map[string]dnsx.AXFRReport{}}
}

// Add parses zone-file lines ("www.example.com. 60 IN CNAME x.example.net.")
// and panics on a malformed line (test bug).
func (d *DNS) Add(lines ...string) *DNS {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, l := range lines {
		r, err := dns.NewRR(l)
		if err != nil || r == nil {
			panic(fmt.Sprintf("checktest.DNS.Add(%q): %v", l, err))
		}
		n := dnsx.Norm(r.Header().Name)
		d.rrs[n] = append(d.rrs[n], r)
	}
	return d
}

// Exists marks names as existing with no data (NODATA for every type).
func (d *DNS) Exists(names ...string) *DNS {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, n := range names {
		d.exists[dnsx.Norm(n)] = true
	}
	return d
}

// Servfail makes every query for name answer SERVFAIL.
func (d *DNS) Servfail(names ...string) *DNS {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, n := range names {
		d.servfail[dnsx.Norm(n)] = true
	}
	return d
}

// Timeout makes every query for name fail like an unanswered query.
func (d *DNS) Timeout(names ...string) *DNS {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, n := range names {
		d.timeout[dnsx.Norm(n)] = true
	}
	return d
}

// Authenticated sets the AD flag on answers for the names.
func (d *DNS) Authenticated(names ...string) *DNS {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, n := range names {
		d.ad[dnsx.Norm(n)] = true
	}
	return d
}

// SetAXFR scripts the zone-transfer report for zone.
func (d *DNS) SetAXFR(zone string, rep dnsx.AXFRReport) *DNS {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.axfr[dnsx.Norm(zone)] = rep
	return d
}

func (d *DNS) known(n string) bool { return d.exists[n] || len(d.rrs[n]) > 0 }

// Query implements check.DNSQuerier.
func (d *DNS) Query(_ context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := dnsx.Norm(name)
	d.Calls = append(d.Calls, dns.TypeToString[qtype]+" "+n)
	m := new(dns.Msg)
	cur := n
	seen := map[string]bool{}
	for {
		if d.timeout[cur] {
			return nil, fmt.Errorf("%w: scripted timeout for %s", dnsx.ErrUnavailable, cur)
		}
		if d.servfail[cur] {
			m.Answer = nil
			m.Rcode = dns.RcodeServerFailure
			break
		}
		if !d.known(cur) {
			m.Rcode = dns.RcodeNameError
			break
		}
		var next string
		for _, r := range d.rrs[cur] {
			if c, ok := r.(*dns.CNAME); ok && qtype != dns.TypeCNAME {
				m.Answer = append(m.Answer, r)
				next = dnsx.Norm(c.Target)
			}
		}
		if next != "" && !seen[next] {
			seen[cur] = true
			cur = next
			continue
		}
		if next == "" {
			for _, r := range d.rrs[cur] {
				if r.Header().Rrtype == qtype {
					m.Answer = append(m.Answer, r)
				}
			}
		}
		break
	}
	m.AuthenticatedData = d.ad[n]
	return dnsx.ParseMsg(m, n, qtype, "fake", false), nil
}

// ResolveChain implements check.DNSQuerier using the real chain algorithm.
func (d *DNS) ResolveChain(ctx context.Context, name string) (dnsx.Chain, error) {
	return dnsx.ResolveChain(ctx, d, name)
}

// AXFR implements check.DNSQuerier; unscripted zones report no attempts.
func (d *DNS) AXFR(_ context.Context, zone string) (dnsx.AXFRReport, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r, ok := d.axfr[dnsx.Norm(zone)]; ok {
		return r, nil
	}
	return dnsx.AXFRReport{Zone: dnsx.Norm(zone), Note: "axfr not scripted"}, nil
}

// WithDNS sets the target's DNS querier.
func WithDNS(q check.DNSQuerier) Option { return func(t *check.Target) { t.DNS = q } }
