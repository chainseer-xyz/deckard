// Package source defines the asset-discovery contract. Implementations live in
// subpackages (cloudflare, route53, gcpdns, kubernetes, static).
package source

import (
	"context"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// Zone is a DNS zone an operator owns, as reported by a source.
type Zone struct {
	Name   string
	Source string
}

// Discovery is the full result of one successful sync of one source.
type Discovery struct {
	Zones     []Zone
	Assets    []model.AssetInput
	Relations []model.RelationInput

	// PreserveImageWorkloads retains previous runs edges only for these exact,
	// present workload keys whose runtime manifest identity is unknown.
	PreserveImageWorkloads []string
	// Warnings report metadata gaps that do not invalidate asset enumeration.
	Warnings []string

	// Partial is set when a sub-feature was skipped because the upstream
	// refused or lacked it (403, 404, "not enabled"), so the result may lack
	// assets that feature would have produced. The inventory still upserts a
	// partial result but never marks unseen assets removed: absence is not
	// evidence. Features known to be absent (e.g. an uninstalled CRD) do not
	// set it.
	Partial bool
	// PartialReasons says which features were skipped and why; shown as the
	// sync warning.
	PartialReasons []string
}

// Source discovers assets. Discover must return an error when the upstream
// API fails, so callers can safely treat a nil error as a complete snapshot
// and mark unseen assets removed, unless Discovery.Partial says a sub-feature
// was skipped.
type Source interface {
	Name() string
	Type() string
	Discover(ctx context.Context) (*Discovery, error)
}
