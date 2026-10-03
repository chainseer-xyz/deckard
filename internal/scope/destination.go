package scope

import (
	"context"
	"fmt"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// Reasons DestinationSkip reports (bounded: they label a metric).
const (
	// SkipSharedDestination: an owned name resolves to shared infrastructure
	// (a CDN or SaaS edge) that only the passive tier may reach.
	SkipSharedDestination = "shared_destination"
	// SkipExternalDestination: an owned name resolves to third-party
	// addresses that only the passive tier may reach.
	SkipExternalDestination = "external_destination"
	// SkipPrivateDestination: an owned name resolves to private addresses
	// that are not declared owned (typically split-horizon DNS seen from
	// inside a cluster or VPC); the guard probes none of them.
	SkipPrivateDestination = "private_destination"
)

// DestinationSkip decides, before anything is dialled, whether a probe of
// tier through host would be refused for an expected reason: host is an owned
// name, but it resolves to shared or external addresses, which only the
// passive tier may connect to, or to private addresses that are not owned.
// It returns a metric reason (one of the Skip* constants) and a
// human-readable detail, or "" when the probe should go ahead and meet the
// guard as usual.
//
// It never permits anything: the guarded dialer and VerifyOwnedTarget still
// vet every connection. It only names the expected case. Everything else
// returns "": the passive tier, IP literals and non-owned names (the engine
// classifies those itself), lookups that fail or return nothing, and any
// answer that is unparseable, excluded or anomalous (loopback, link-local,
// metadata, reserved; see isAnomalous). Those are anomalies the guard must
// refuse loudly at dial time, not routine skips.
func (g *Guard) DestinationSkip(ctx context.Context, tier model.Tier, host string) (reason, detail string) {
	if tier == model.TierPassive || !tier.Valid() {
		return "", ""
	}
	if _, isIP := parseIP(host); isIP {
		return "", ""
	}
	name, ok := normHost(host)
	if !ok || g.classifyName(name) != model.ScopeOwned {
		return "", ""
	}
	addrs, err := g.resolver.LookupHost(ctx, name)
	if err != nil || len(addrs) == 0 {
		return "", ""
	}
	var unowned []string
	var shared, external bool
	for _, a := range addrs {
		ip, ok := parseIP(a)
		if !ok {
			return "", ""
		}
		switch class := g.classifyIP(ip); {
		case class == model.ScopeOwned:
			continue
		case class == model.ScopeExcluded, isAnomalous(ip):
			return "", ""
		case class == model.ScopeShared:
			shared = true
		case !isSpecial(ip):
			external = true
		}
		unowned = append(unowned, ip.String())
	}
	if len(unowned) == 0 {
		return "", ""
	}
	kind := "private"
	reason = SkipPrivateDestination
	switch {
	case shared:
		kind, reason = "shared", SkipSharedDestination
	case external:
		kind, reason = "external", SkipExternalDestination
	}
	return reason, fmt.Sprintf("%s resolves to %s address(es) %s; the %s tier only probes owned destination IPs",
		name, kind, strings.Join(unowned, ", "), tier)
}
