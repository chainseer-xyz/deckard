// Package registry holds the set of known checks. Checks are added explicitly
// by the wiring code (no init() registration).
package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Registry is a name-indexed set of checks.
type Registry struct {
	mu     sync.RWMutex
	checks map[string]check.Check
}

// New returns an empty registry.
func New() *Registry { return &Registry{checks: map[string]check.Check{}} }

// Register adds c; names must be non-empty and unique.
func (r *Registry) Register(c check.Check) error {
	name := c.Name()
	if name == "" {
		return fmt.Errorf("registry: check with empty name")
	}
	if !c.Tier().Valid() {
		return fmt.Errorf("registry: check %q has invalid tier %q", name, c.Tier())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.checks[name]; dup {
		return fmt.Errorf("registry: duplicate check %q", name)
	}
	r.checks[name] = c
	return nil
}

// All returns every check sorted by name.
func (r *Registry) All() []check.Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]check.Check, 0, len(r.checks))
	for _, c := range r.checks {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// ByName looks a check up by name.
func (r *Registry) ByName(name string) (check.Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checks[name]
	return c, ok
}

// ForTier returns the checks of exactly tier, sorted by name.
func (r *Registry) ForTier(t model.Tier) []check.Check {
	var out []check.Check
	for _, c := range r.All() {
		if c.Tier() == t {
			out = append(out, c)
		}
	}
	return out
}

// Default is the process-wide registry used by the package-level functions.
var Default = New()

// Register adds c to Default and panics on error (a wiring bug).
func Register(c check.Check) {
	if err := Default.Register(c); err != nil {
		panic(err)
	}
}

// All returns Default's checks.
func All() []check.Check { return Default.All() }

// ByName looks a check up in Default.
func ByName(name string) (check.Check, bool) { return Default.ByName(name) }

// ForTier filters Default by tier.
func ForTier(t model.Tier) []check.Check { return Default.ForTier(t) }
