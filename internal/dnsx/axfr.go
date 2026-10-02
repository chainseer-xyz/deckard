package dnsx

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DialFunc opens a connection; scope's guarded Dialer satisfies it.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// AXFROutcome is the result of one zone-transfer attempt.
type AXFROutcome string

const (
	AXFROpen    AXFROutcome = "open"    // the server handed over the zone
	AXFRRefused AXFROutcome = "refused" // the server answered but refused
	AXFRSkipped AXFROutcome = "skipped" // the dial was not made/permitted (see Note)
	AXFRError   AXFROutcome = "error"   // transport or protocol failure
)

// AXFRAttempt is one (nameserver, address) attempt.
type AXFRAttempt struct {
	NS      string
	Addr    string
	Outcome AXFROutcome
	Records int // RRs received (open only); the zone itself is not retained
	Note    string
}

// AXFRReport lists every attempt made for a zone.
type AXFRReport struct {
	Zone     string
	Attempts []AXFRAttempt
	Note     string // set when no attempt could be made (NS lookup failed, ...)
}

// Open returns the attempts that succeeded in transferring the zone.
func (r AXFRReport) Open() []AXFRAttempt {
	var out []AXFRAttempt
	for _, a := range r.Attempts {
		if a.Outcome == AXFROpen {
			out = append(out, a)
		}
	}
	return out
}

const (
	maxAXFRNS    = 8
	maxAXFRAddrs = 4
	axfrTimeout  = 30 * time.Second
)

// AttemptAXFR tries a zone transfer against each of zone's nameservers. NS
// and address lookups go through q (the configured recursive resolvers); the
// TCP connection to each nameserver address goes through dial, so a guarded
// dialer refuses addresses the operator does not own, which is reported as a
// skipped attempt with the reason in Note. Only the record count of an open
// transfer is kept.
func AttemptAXFR(ctx context.Context, q Querier, zone string, dial DialFunc) (AXFRReport, error) {
	zone = Norm(zone)
	rep := AXFRReport{Zone: zone}
	nsResp, err := q.Query(ctx, zone, dns.TypeNS)
	if err != nil {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		rep.Note = "NS lookup failed: " + err.Error()
		return rep, nil
	}
	rrs := nsResp.Records(dns.TypeNS)
	if len(rrs) == 0 {
		rep.Note = "no NS records (" + nsResp.State().String() + ")"
		return rep, nil
	}
	var names []string
	for _, rr := range rrs {
		names = append(names, Norm(rr.(*dns.NS).Ns))
		if len(names) == maxAXFRNS {
			break
		}
	}
	for _, ns := range names {
		var addrs []string
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r, err := q.Query(ctx, ns, t)
			if err != nil {
				if ctx.Err() != nil {
					return rep, ctx.Err()
				}
				continue
			}
			for _, rr := range r.Records(t) {
				switch v := rr.(type) {
				case *dns.A:
					addrs = append(addrs, v.A.String())
				case *dns.AAAA:
					addrs = append(addrs, v.AAAA.String())
				}
			}
		}
		if len(addrs) > maxAXFRAddrs {
			addrs = addrs[:maxAXFRAddrs]
		}
		if len(addrs) == 0 {
			rep.Attempts = append(rep.Attempts, AXFRAttempt{NS: ns, Outcome: AXFRSkipped, Note: "nameserver has no addresses"})
			continue
		}
		for _, a := range addrs {
			rep.Attempts = append(rep.Attempts, transfer(ctx, zone, ns, net.JoinHostPort(a, "53"), dial))
			if err := ctx.Err(); err != nil {
				return rep, err
			}
		}
	}
	return rep, nil
}

func transfer(ctx context.Context, zone, ns, addr string, dial DialFunc) AXFRAttempt {
	at := AXFRAttempt{NS: ns, Addr: addr}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		at.Outcome, at.Note = AXFRSkipped, err.Error()
		return at
	}
	defer conn.Close()
	dl := time.Now().Add(axfrTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = conn.SetDeadline(dl)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))
	tr := &dns.Transfer{Conn: &dns.Conn{Conn: conn}}
	ch, err := tr.In(m, addr)
	if err != nil {
		at.Outcome, at.Note = AXFRError, err.Error()
		return at
	}
	var firstErr error
	for env := range ch { // always drain so the reader goroutine ends
		if env.Error != nil {
			if firstErr == nil {
				firstErr = env.Error
			}
			continue
		}
		at.Records += len(env.RR)
	}
	switch {
	case firstErr != nil && strings.Contains(firstErr.Error(), "rcode"):
		at.Outcome, at.Note, at.Records = AXFRRefused, firstErr.Error(), 0
	case firstErr != nil:
		at.Outcome, at.Note, at.Records = AXFRError, firstErr.Error(), 0
	case at.Records >= 2:
		at.Outcome = AXFROpen
	default:
		at.Outcome, at.Note = AXFRRefused, "empty transfer"
	}
	return at
}
