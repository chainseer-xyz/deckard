package scope

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Provenance limits: a chain of owned name -> CNAME/NS target -> its own
// CNAME/NS target ... may be followed this deep and this wide per querier.
const (
	maxProvDepth = 12
	maxProvNames = 512
)

// DNS returns a check.DNSQuerier for an asset of class assetClass at tier.
//
// Name policy. A query is made only for names that are
//   - owned (and not excluded), or
//   - provably downstream of an owned name: a CNAME target or NS target
//     returned in an answer to a query for an owned name, or transitively for
//     such a target. The querier records that provenance itself (name ->
//     owned starting name, hop depth) from the answers it received, so a check
//     cannot launder an arbitrary third-party name through it. Provenance is
//     per querier instance, so it never leaks between checks.
//
// Everything else (unrelated third-party names, IP literals, excluded names)
// is refused with ErrOutOfScope/ErrExcluded.
//
// Server policy. Queries are sent only by the configured dnsx client, i.e. to
// the configured recursive resolvers; no query is ever sent to an arbitrary
// authoritative server. The one exception is AXFR, a TCP connection to a
// nameserver address, which goes through the guarded Dialer and is therefore
// only made to owned IPs; any other nameserver is reported as skipped with the
// reason. rate may be nil.
func (g *Guard) DNS(tier model.Tier, assetClass model.ScopeClass, rate RateLimiter) check.DNSQuerier {
	g.dnsOnce.Do(func() {
		if g.dnsq == nil {
			g.dnsq = dnsx.New()
		}
	})
	return &guardedDNS{g: g, tier: tier, class: assetClass, rate: rate, q: g.dnsq,
		dialer: g.Dialer(tier, assetClass, rate), prov: map[string]provenance{}}
}

type provenance struct {
	origin string // the owned name the chain started at
	depth  int
}

type guardedDNS struct {
	g      *Guard
	tier   model.Tier
	class  model.ScopeClass
	rate   RateLimiter
	q      dnsx.Querier
	dialer check.Dialer

	mu   sync.Mutex
	prov map[string]provenance
}

// gate validates name and returns its normalised form and provenance depth.
func (d *guardedDNS) gate(op, name string) (string, int, error) {
	g := d.g
	if !Allowed(d.tier, d.class) {
		return "", 0, g.classRefusal(op, d.tier, name, d.class, "tier not permitted for asset class")
	}
	if isIPLiteral(strings.TrimSpace(name)) {
		return "", 0, g.refuse(ErrOutOfScope, op, d.tier, name, d.class, "DNS queries are made for names, not IP literals")
	}
	n, ok := normHost(name)
	if !ok {
		return "", 0, fmt.Errorf("scope: %s %q: invalid hostname", op, name)
	}
	switch c := g.classifyName(n); c {
	case model.ScopeExcluded:
		return "", 0, g.refuse(ErrExcluded, op, d.tier, n, c, "name is excluded")
	case model.ScopeOwned:
		return n, 0, nil
	default:
		d.mu.Lock()
		p, ok := d.prov[n]
		d.mu.Unlock()
		if ok {
			return n, p.depth, nil
		}
		return "", 0, g.refuse(ErrOutOfScope, op, d.tier, n, c, "name is neither owned nor a CNAME/NS target reached from an owned name")
	}
}

// origin returns the owned name a (gated) name's provenance starts at.
func (d *guardedDNS) origin(n string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.prov[n]; ok {
		return p.origin
	}
	return n
}

// record remembers names a gated query's answer pointed at.
func (d *guardedDNS) record(qname string, depth int, resp *dnsx.Response) {
	origin := d.origin(qname)
	var targets []string
	for _, h := range resp.Chain {
		targets = append(targets, h.Target)
	}
	if resp.Type == dns.TypeNS {
		for _, rr := range resp.Answer {
			if ns, ok := rr.(*dns.NS); ok && dnsx.Norm(ns.Hdr.Name) == resp.Final {
				targets = append(targets, dnsx.Norm(ns.Ns))
			}
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, t := range targets {
		n, ok := normHost(t)
		if !ok || isIPLiteral(n) || depth+1 > maxProvDepth || len(d.prov) >= maxProvNames {
			continue
		}
		if _, have := d.prov[n]; !have {
			d.prov[n] = provenance{origin: origin, depth: depth + 1}
		}
	}
}

// Query implements check.DNSQuerier.
func (d *guardedDNS) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	switch qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeOPT:
		return nil, d.g.refuseAnomaly(ErrOutOfScope, "resolve", d.tier, name+" ("+dns.TypeToString[qtype]+")", d.class, "query type is not permitted")
	}
	n, depth, err := d.gate("resolve", name)
	if err != nil {
		return nil, err
	}
	if d.rate != nil {
		if err := d.rate.Wait(ctx, n); err != nil {
			return nil, err
		}
	}
	resp, err := d.q.Query(ctx, n, qtype)
	if err != nil {
		return nil, err
	}
	d.record(n, depth, resp)
	return resp, nil
}

// ResolveChain implements check.DNSQuerier. The start name is gated up front
// so a refusal is an error, not an "unknown" chain; every later hop goes
// through Query and is therefore subject to the provenance rule.
func (d *guardedDNS) ResolveChain(ctx context.Context, name string) (dnsx.Chain, error) {
	n, _, err := d.gate("resolve", name)
	if err != nil {
		return dnsx.Chain{Start: dnsx.Norm(name), End: dnsx.Norm(name)}, err
	}
	return dnsx.ResolveChain(ctx, d, n)
}

// AXFR implements check.DNSQuerier: zone must be owned; every nameserver
// address is dialled through the guarded Dialer, and addresses that are not
// owned IPs are skipped with a note rather than contacted.
func (d *guardedDNS) AXFR(ctx context.Context, zone string) (dnsx.AXFRReport, error) {
	n, depth, err := d.gate("axfr", zone)
	if err != nil {
		return dnsx.AXFRReport{Zone: dnsx.Norm(zone)}, err
	}
	if depth != 0 || d.g.classifyName(n) != model.ScopeOwned {
		return dnsx.AXFRReport{Zone: n}, d.g.refuse(ErrOutOfScope, "axfr", d.tier, n, d.class, "zone transfers are only attempted for owned zones")
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip, ok := parseIP(host)
		if !ok {
			return nil, fmt.Errorf("nameserver address %q is not an IP", host)
		}
		if d.g.classifyIP(ip) != model.ScopeOwned {
			return nil, fmt.Errorf("nameserver address %s is not an owned IP; zone transfer skipped", ip)
		}
		return d.dialer.DialContext(ctx, network, address)
	}
	return dnsx.AttemptAXFR(ctx, d, n, dial)
}
