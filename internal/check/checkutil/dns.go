package checkutil

import (
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// IsNotFound reports whether err is an NXDOMAIN-style "no such host" answer.
func IsNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// OwnedZones returns the zones whose names a check may emit as discovered
// hostnames: the asset's own zone plus the optional `owned_zones` config key.
func OwnedZones(t check.Target) []string {
	var zones []string
	if t.Asset.Kind == model.KindZone {
		zones = append(zones, Norm(t.Asset.Key))
	}
	for _, fact := range assetFacts(t.Asset) {
		if fact.Zone != "" {
			zones = append(zones, Norm(fact.Zone))
		}
	}
	for _, z := range Strings(t.Config, "owned_zones", nil) {
		zones = append(zones, Norm(z))
	}
	return zones
}

// ZoneOf returns the longest zone in zones that name equals or falls under,
// or "" when none does.
func ZoneOf(name string, zones []string) string {
	name = Norm(name)
	best := ""
	for _, z := range zones {
		z = Norm(z)
		if z == "" {
			continue
		}
		if (name == z || strings.HasSuffix(name, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	return best
}

// Source is the Source label for assets a check discovers.
func Source(checkName string) string { return "check:" + checkName }

// SortedUnique returns s sorted with duplicates removed.
func SortedUnique(s []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
