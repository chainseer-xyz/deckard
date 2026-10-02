package scope

import "github.com/chainseer-xyz/deckard/internal/model"

// Allowed reports whether a probe of the given tier may touch an asset of the
// given class.
//
//	owned    -> passive, active, intrusive
//	shared   -> passive only
//	external -> passive only
//	excluded -> nothing
//
// For shared and external assets "passive" means HOSTNAME-BASED probing only
// (resolving or requesting an owned hostname and observing what comes back).
// IP-based network probing of shared/external addresses is never allowed;
// Allowed cannot see the asset kind, so callers that know it MUST use
// AllowedFor, and the guarded Dialer enforces the rule on the wire regardless.
func Allowed(tier model.Tier, class model.ScopeClass) bool {
	if !tier.Valid() {
		return false
	}
	switch class {
	case model.ScopeOwned:
		return true
	case model.ScopeShared, model.ScopeExternal:
		return tier == model.TierPassive
	}
	return false
}

// AllowedFor is Allowed plus the asset-kind rule: shared/external assets may
// only be probed by hostname (hostname, zone, URL), never by IP or service
// endpoint.
func AllowedFor(kind model.AssetKind, tier model.Tier, class model.ScopeClass) bool {
	if !Allowed(tier, class) {
		return false
	}
	if class == model.ScopeOwned {
		return true
	}
	switch kind {
	case model.KindHostname, model.KindZone, model.KindURL:
		return true
	}
	return false
}
