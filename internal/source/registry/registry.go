// Package registry builds a source.Source from its config entry. Source types
// register a Constructor under their type name; cloudflare and static are
// built in. Other packages (route53, kubernetes) call Register from their own
// init or from the binary's wiring code, which keeps this package free of
// their dependencies.
package registry

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/source/cloudflare"
	"github.com/chainseer-xyz/deckard/internal/source/static"
)

// Constructor builds one source instance.
type Constructor func(cfg config.SourceConfig, scope config.ScopeConfig, getenv func(string) string, log *slog.Logger) (source.Source, error)

var (
	mu    sync.RWMutex
	ctors = map[string]Constructor{
		"cloudflare": func(cfg config.SourceConfig, _ config.ScopeConfig, getenv func(string) string, log *slog.Logger) (source.Source, error) {
			return cloudflare.New(cfg, getenv, log)
		},
		"static": func(cfg config.SourceConfig, scope config.ScopeConfig, _ func(string) string, _ *slog.Logger) (source.Source, error) {
			return static.New(cfg, scope.MaxCIDRHosts)
		},
	}
)

// Register adds or replaces the constructor for a source type.
func Register(typeName string, ctor Constructor) {
	mu.Lock()
	defer mu.Unlock()
	ctors[typeName] = ctor
}

// Types lists the registered type names, sorted.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(ctors))
	for k := range ctors {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Build constructs the source described by cfg.
func Build(cfg config.SourceConfig, scope config.ScopeConfig, getenv func(string) string, log *slog.Logger) (source.Source, error) {
	mu.RLock()
	ctor, ok := ctors[cfg.Type]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("source %q: type %q is not available (registered: %s)", cfg.Name, cfg.Type, strings.Join(Types(), ", "))
	}
	return ctor(cfg, scope, getenv, log)
}
