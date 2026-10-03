package app

import (
	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/domain/lookalike"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
)

// buildLookup creates the DNS client checks use for names the operator does
// not own (domain.lookalike), handed to them as Target.Lookup. It is the only
// place such a client is built, so its use is auditable here: it sends plain
// DNS queries to the configured recursive resolvers (scope.resolvers when set,
// otherwise the system's) and nowhere else, behind one process-wide rate
// ceiling (checks.domain.lookalike.rate_per_second) shared by every run.
func (a *App) buildLookup() check.Lookup {
	var opts []dnsx.Option
	if rs := a.cfg.Scope.Resolvers; len(rs) > 0 {
		opts = append(opts, dnsx.WithServers(rs...))
	}
	rate := lookalike.RatePerSecond(a.cfg.Checks[lookalike.Name])
	return dnsx.NewLimited(dnsx.New(opts...), rate)
}
