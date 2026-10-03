package engine

import (
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Resolved is the effective scan policy for one (asset, tier).
type Resolved struct {
	Enabled            bool
	Interval           time.Duration
	RatePerSec         float64 // events/s per target host; 0 = unlimited
	PerHostConcurrency int     // >= 1
	OnInventoryChange  bool    // scan immediately when the asset is added/changed
}

// ResolveProfile merges the global profile for tier with every matching
// asset_groups override.
//
// Precedence (lowest to highest):
//
//  1. cfg.Profiles.<tier> (global).
//  2. asset_groups entries in config order; a later matching group overrides an
//     earlier one field by field. Only fields a group sets (non-nil) override.
//
// A group matches when every non-empty criterion in its Match matches
// (AND across zones/sources/hostnames/cidrs, OR within each list). A group with
// an empty Match matches nothing, so a misconfigured group can never widen
// scanning. Groups cannot set on_inventory_change; that stays global.
//
// Safety: nothing is enabled unless the global profile or a group says
// "enabled: true" explicitly, so intrusive stays off by default and a group
// that only tunes an interval never turns a tier on. Scope classification is
// separate and always applies on top (see runScan).
func ResolveProfile(cfg config.Config, asset model.Asset, tier model.Tier) Resolved {
	var base config.Profile
	switch tier {
	case model.TierPassive:
		base = cfg.Profiles.Passive
	case model.TierActive:
		base = cfg.Profiles.Active
	case model.TierIntrusive:
		base = cfg.Profiles.Intrusive
	default:
		return Resolved{}
	}
	rate, _ := config.ParseRate(base.RateLimit)
	r := Resolved{
		Enabled:            base.Enabled,
		Interval:           base.Interval,
		RatePerSec:         rate,
		PerHostConcurrency: base.PerHostConcurrency,
		OnInventoryChange:  base.OnInventoryChange,
	}
	for _, g := range cfg.AssetGroups {
		o, ok := g.Profiles[string(tier)]
		if !ok || !groupMatches(g.Match, asset) {
			continue
		}
		if o.Enabled != nil {
			r.Enabled = *o.Enabled
		}
		if o.Interval != nil {
			r.Interval = *o.Interval
		}
		if o.RateLimit != nil {
			if v, err := config.ParseRate(*o.RateLimit); err == nil {
				r.RatePerSec = v
			}
		}
		if o.PerHostConcurrency != nil {
			r.PerHostConcurrency = *o.PerHostConcurrency
		}
	}
	if r.PerHostConcurrency < 1 {
		r.PerHostConcurrency = 1
	}
	if tier == model.TierIntrusive {
		// Intrusive probes can disturb services; they run only on their own
		// schedule, never because an asset appeared, whatever the config says.
		r.OnInventoryChange = false
	}
	return r
}

// ResolveCheck is ResolveProfile refined by the per-check overrides under
// checks.<name>:
//
//   - interval replaces the tier interval (it may lengthen or shorten it).
//   - on_new_asset (default true) can only turn the tier's on_inventory_change
//     off for that check; it never turns it on.
//
// The overrides never touch Enabled: a disabled tier (global or via an asset
// group) stays disabled, and scope classification is applied separately. Invalid
// values are ignored here (config.Validate rejects them at load).
func ResolveCheck(cfg config.Config, asset model.Asset, tier model.Tier, checkName string) Resolved {
	r := ResolveProfile(cfg, asset, tier)
	return applyCheckOverrides(cfg, r, checkName)
}

// resolveFor is ResolveCheck for a check instance: a check implementing
// check.DefaultIntervaler replaces the tier (and asset-group) interval with its
// own before the checks.<name> overrides apply.
func resolveFor(cfg config.Config, asset model.Asset, tier model.Tier, c check.Check) Resolved {
	r := ResolveProfile(cfg, asset, tier)
	if di, ok := c.(check.DefaultIntervaler); ok {
		if d := di.DefaultInterval(); d > 0 {
			r.Interval = d
		}
	}
	return applyCheckOverrides(cfg, r, c.Name())
}

func applyCheckOverrides(cfg config.Config, r Resolved, checkName string) Resolved {
	opts := cfg.Checks[checkName]
	if d, ok, err := config.CheckInterval(opts); err == nil && ok {
		r.Interval = d
	}
	if v, ok, err := config.CheckOnNewAsset(opts); err == nil && ok && !v {
		r.OnInventoryChange = false
	}
	return r
}

func groupMatches(m config.GroupMatch, a model.Asset) bool {
	if len(m.Zones) == 0 && len(m.Sources) == 0 && len(m.Hostnames) == 0 && len(m.CIDRs) == 0 {
		return false
	}
	if len(m.Zones) > 0 && !anyZone(m.Zones, a) {
		return false
	}
	if len(m.Sources) > 0 && !anyFold(m.Sources, a.Source) {
		return false
	}
	if len(m.Hostnames) > 0 && !anyHostGlob(m.Hostnames, a) {
		return false
	}
	if len(m.CIDRs) > 0 && !anyCIDR(m.CIDRs, a) {
		return false
	}
	return true
}

func normName(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }

func anyFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

// assetHost is the DNS name of a hostname/zone/url asset ("" otherwise).
func assetHost(a model.Asset) string {
	switch a.Kind {
	case model.KindHostname, model.KindZone:
		return normName(a.Key)
	case model.KindURL:
		if u, err := url.Parse(a.Key); err == nil {
			return normName(u.Hostname())
		}
	}
	return ""
}

func anyZone(zones []string, a model.Asset) bool {
	host := assetHost(a)
	for _, z := range zones {
		z = normName(z)
		if z == "" {
			continue
		}
		if a.Zone != "" && normName(a.Zone) == z {
			return true
		}
		if host != "" && (host == z || strings.HasSuffix(host, "."+z)) {
			return true
		}
	}
	return false
}

func anyHostGlob(globs []string, a model.Asset) bool {
	host := assetHost(a)
	if host == "" {
		return false
	}
	for _, g := range globs {
		g = normName(g)
		if g == "" {
			continue
		}
		if strings.HasPrefix(g, "*.") && !strings.ContainsAny(g[2:], "*?[") {
			if strings.HasSuffix(host, g[1:]) { // any depth under the suffix
				return true
			}
			continue
		}
		if ok, _ := path.Match(g, host); ok {
			return true
		}
	}
	return false
}

// assetIP extracts the IP from ip assets ("1.2.3.4") and service assets
// ("1.2.3.4:443/tcp", "[::1]:443/tcp").
func assetIP(a model.Asset) (netip.Addr, bool) {
	switch a.Kind {
	case model.KindIP:
		ip, err := netip.ParseAddr(strings.TrimSpace(a.Key))
		return ip.Unmap(), err == nil
	case model.KindService:
		k, _, _ := strings.Cut(a.Key, "/")
		if ap, err := netip.ParseAddrPort(k); err == nil {
			return ap.Addr().Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func anyCIDR(cidrs []string, a model.Asset) bool {
	ip, ok := assetIP(a)
	if !ok {
		return false
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil && p.Contains(ip) {
			return true
		}
		if addr, err := netip.ParseAddr(strings.TrimSpace(c)); err == nil && addr.Unmap() == ip {
			return true
		}
	}
	return false
}
