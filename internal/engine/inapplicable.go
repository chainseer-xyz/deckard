package engine

import (
	"context"
	"fmt"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// resolveInapplicable retires findings only for enabled checks on live, freshly
// owned assets. A disabled check/profile, removed asset or scope/destination
// refusal never proves that its findings ceased to apply.
func (r *runner) resolveInapplicable(ctx context.Context, a model.Asset, tier model.Tier, name string) error {
	class, _, why := r.scannable(a, tier)
	if why != "" || class != model.ScopeOwned || a.Scope != model.ScopeOwned {
		return nil
	}
	var retired []check.Check
	for _, c := range r.checks {
		if c.Tier() != tier || (name != "" && c.Name() != name) || c.Applies(a) || resolveFor(r.Config, a, tier, c).Interval <= 0 {
			continue
		}
		if enabled, ok := r.Config.Checks[c.Name()]["enabled"].(bool); ok && !enabled {
			continue
		}
		retired = append(retired, c)
	}
	if len(retired) == 0 {
		return nil
	}
	if reason, _ := r.destinationSkip(ctx, a, tier); reason != "" {
		return nil
	}
	for _, c := range retired {
		n, err := r.Store.ResolveInapplicableFindings(ctx, a, c.Name(), r.now())
		if err != nil {
			return fmt.Errorf("retire inapplicable %s findings for asset %d: %w", c.Name(), a.ID, err)
		}
		if n > 0 {
			r.log.Info("findings resolved because check no longer applies", "asset", a.Key, "check", c.Name(), "count", n)
		}
	}
	return nil
}
