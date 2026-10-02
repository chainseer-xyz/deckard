package dnsx

import (
	"context"

	"github.com/miekg/dns"
)

// MaxChainDepth is the maximum number of CNAME hops ResolveChain follows.
const MaxChainDepth = 10

// Querier is the minimal query surface; *Client implements it, and scope's
// guarded wrapper and test fakes layer on top.
type Querier interface {
	Query(ctx context.Context, name string, qtype uint16) (*Response, error)
}

// Chain is the explicit result of following CNAMEs from Start.
type Chain struct {
	Start string
	Hops  []Hop  // CNAME links in order
	End   string // last name reached: where the chain stopped
	State State  // what happened at End
	Rcode int    // rcode of the final answer
	Err   error  // set when State is StateUnknown because of a transport error
}

// Len is the number of CNAME hops followed; the chain ended at hop Len().
func (c Chain) Len() int { return len(c.Hops) }

// Names returns Start followed by each hop target.
func (c Chain) Names() []string {
	out := []string{c.Start}
	for _, h := range c.Hops {
		out = append(out, h.Target)
	}
	return out
}

// ResolveChain follows the CNAME chain of name explicitly, querying A at each
// name. It tolerates resolvers that follow the whole chain in one answer and
// ones that return one hop at a time, and detects loops and over-long chains.
// The final State is StateNXDomain only when a server answered NXDOMAIN;
// SERVFAIL, timeouts and the like yield StateUnknown. The returned error is
// non-nil only when ctx is done.
func ResolveChain(ctx context.Context, q Querier, name string) (Chain, error) {
	start := Norm(name)
	ch := Chain{Start: start, End: start}
	seen := map[string]bool{start: true}
	cur := start
	for {
		resp, err := q.Query(ctx, cur, dns.TypeA)
		if err != nil {
			if ctx.Err() != nil {
				return ch, ctx.Err()
			}
			ch.State, ch.Err = StateUnknown, err
			return ch, nil
		}
		ch.Rcode = resp.Rcode
		progressed := false
		for _, h := range resp.Chain {
			ch.Hops = append(ch.Hops, h)
			ch.End = h.Target
			progressed = true
			if seen[h.Target] {
				ch.State = StateLoop
				return ch, nil
			}
			seen[h.Target] = true
			if len(ch.Hops) > MaxChainDepth {
				ch.State = StateTooDeep
				return ch, nil
			}
		}
		st := resp.State()
		if st == StateNoData && progressed {
			// The resolver may have stopped mid-chain; ask the target
			// directly (a genuine NODATA there terminates the chain).
			cur = ch.End
			continue
		}
		ch.State = st
		return ch, nil
	}
}
