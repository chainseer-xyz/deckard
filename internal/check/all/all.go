// Package all builds every built-in passive check from the global per-check
// config map, for the wiring code to register.
//
// cloud.bucket is deliberately NOT implemented yet (deferred): it needs bucket
// existence/ACL probing against third-party cloud APIs, which does not fit the
// owned-hostname-only passive contract without further design.
package all

import (
	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/dns/dangling"
	"github.com/chainseer-xyz/deckard/internal/check/dns/hygiene"
	"github.com/chainseer-xyz/deckard/internal/check/dns/takeover"
	"github.com/chainseer-xyz/deckard/internal/check/domain/expiry"
	"github.com/chainseer-xyz/deckard/internal/check/domain/lookalike"
	"github.com/chainseer-xyz/deckard/internal/check/http/headers"
	"github.com/chainseer-xyz/deckard/internal/check/http/probe"
	"github.com/chainseer-xyz/deckard/internal/check/intel/internetdb"
	"github.com/chainseer-xyz/deckard/internal/check/mail/policy"
	"github.com/chainseer-xyz/deckard/internal/check/origin/correlation"
	"github.com/chainseer-xyz/deckard/internal/check/origin/exposed"
	"github.com/chainseer-xyz/deckard/internal/check/registry"
	"github.com/chainseer-xyz/deckard/internal/check/tls/cert"
)

// Checks returns every built-in passive check, configured from cfg (keyed by
// check name).
func Checks(cfg map[string]map[string]any) []check.Check {
	var out []check.Check
	for _, ctor := range []func(map[string]map[string]any) []check.Check{
		dangling.Checks, takeover.Checks, hygiene.Checks, cert.Checks,
		probe.Checks, headers.Checks, exposed.Checks, correlation.Checks, expiry.Checks, lookalike.Checks, internetdb.Checks, policy.Checks,
	} {
		out = append(out, ctor(cfg)...)
	}
	return out
}

// Register adds every built-in check to r.
func Register(r *registry.Registry, cfg map[string]map[string]any) error {
	for _, c := range Checks(cfg) {
		if err := r.Register(c); err != nil {
			return err
		}
	}
	return nil
}
