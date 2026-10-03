// Package all builds every built-in passive check from the global per-check
// config map, for the wiring code to register.
package all

import (
	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/cloud/bucket"
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
	"github.com/chainseer-xyz/deckard/internal/check/web/history"
)

// Checks returns every built-in passive check, configured from cfg (keyed by
// check name).
func Checks(cfg map[string]map[string]any) []check.Check {
	var out []check.Check
	for _, ctor := range []func(map[string]map[string]any) []check.Check{
		dangling.Checks, takeover.Checks, hygiene.Checks, cert.Checks,
		probe.Checks, headers.Checks, exposed.Checks, correlation.Checks, expiry.Checks, lookalike.Checks, internetdb.Checks, policy.Checks, history.Checks, bucket.Checks,
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
