// Package dnsx is deckard's DNS query client (github.com/miekg/dns). Unlike
// net.Resolver it exposes the rcode, the full CNAME chain and the AD flag, and
// it models "I could not find out" (SERVFAIL, timeouts) as StateUnknown so a
// transient resolver failure is never mistaken for NXDOMAIN.
//
// A Client only ever talks to its configured recursive resolvers. It makes no
// decisions about which names may be queried: that policy lives in
// internal/scope, which wraps a Querier.
package dnsx

import (
	"strings"

	"github.com/miekg/dns"
)

// State is the outcome of resolving a name.
type State int

const (
	// StateUnknown means the resolution could not be completed (SERVFAIL,
	// REFUSED, timeouts, network errors). It is the zero value so that a
	// forgotten assignment can never read as NXDOMAIN.
	StateUnknown State = iota
	// StateResolved means the name has data of the queried type.
	StateResolved
	// StateNoData means the name exists but has no data of the queried type.
	StateNoData
	// StateNXDomain means the name does not exist.
	StateNXDomain
	// StateLoop means the CNAME chain loops.
	StateLoop
	// StateTooDeep means the CNAME chain exceeded MaxChainDepth.
	StateTooDeep
)

func (s State) String() string {
	switch s {
	case StateResolved:
		return "resolved"
	case StateNoData:
		return "nodata"
	case StateNXDomain:
		return "nxdomain"
	case StateLoop:
		return "loop"
	case StateTooDeep:
		return "too-deep"
	}
	return "unknown"
}

// Hop is one CNAME link: Name is an alias for Target.
type Hop struct{ Name, Target string }

// Response is a parsed DNS reply.
type Response struct {
	Name    string   // normalised query name
	Type    uint16   // query type
	Rcode   int      // dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeServerFailure, ...
	Answer  []dns.RR // answer section, typed
	Chain   []Hop    // CNAME hops present in Answer, in order from Name
	Final   string   // name at the end of Chain (== Name when there is none)
	Loop    bool     // the in-message chain loops
	AD      bool     // resolver set the Authenticated Data flag
	UsedTCP bool     // the answer came over TCP (UDP reply was truncated)
	Server  string   // resolver that produced the answer
}

// Records returns the answer RRs of qtype owned by Final (the end of the
// CNAME chain), i.e. the data the question actually asked for.
func (r *Response) Records(qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == qtype && Norm(rr.Header().Name) == r.Final {
			out = append(out, rr)
		}
	}
	return out
}

// State classifies the response for the queried type. SERVFAIL, REFUSED and
// every other non-success rcode are StateUnknown, never StateNXDomain.
func (r *Response) State() State {
	switch r.Rcode {
	case dns.RcodeNameError:
		return StateNXDomain
	case dns.RcodeSuccess:
		if r.Loop {
			return StateLoop
		}
		if len(r.Records(r.Type)) > 0 {
			return StateResolved
		}
		return StateNoData
	}
	return StateUnknown
}

// Norm lowercases and strips the trailing dot ("Example.COM." -> "example.com").
func Norm(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// ParseMsg builds a Response from a wire message (exported for fakes).
func ParseMsg(m *dns.Msg, name string, qtype uint16, server string, tcp bool) *Response {
	name = Norm(name)
	r := &Response{Name: name, Type: qtype, Rcode: m.Rcode, Answer: m.Answer, AD: m.AuthenticatedData, UsedTCP: tcp, Server: server, Final: name}
	next := map[string]string{}
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			o := Norm(c.Hdr.Name)
			if _, dup := next[o]; !dup {
				next[o] = Norm(c.Target)
			}
		}
	}
	seen := map[string]bool{name: true}
	cur := name
	for {
		t, ok := next[cur]
		if !ok {
			break
		}
		r.Chain = append(r.Chain, Hop{Name: cur, Target: t})
		cur = t
		if seen[t] {
			r.Loop = true
			break
		}
		seen[t] = true
	}
	r.Final = cur
	return r
}
