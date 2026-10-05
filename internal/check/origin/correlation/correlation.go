// Package correlation implements origin.correlation: pure graph logic that
// flags a proxied origin IP which is also published through other DNS
// records, defeating the CDN/WAF. It makes no network connections.
//
// Applies to owned ip assets with attrs.origin=true. Over the hostnames that
// resolve_to the IP (neighbours with relation resolves_to), the rules are:
//
//	proxied set   P: hostnames with attrs.proxied == true
//	unproxied set U: hostnames with attrs.proxied == false (an absent or
//	                 non-bool attribute is "unknown" and never counts)
//	discovered D:    hostnames with attrs.discovered_by set (CT/expansion)
//
// For each unproxied hostname u in U, at most one finding:
//
//  1. HIGH   key published:<u>   when P is non-empty and u shares a zone with
//     some hostname in P (the record plainly leaks the origin).
//  2. MEDIUM key cross-zone:<u>  otherwise, when u's zone differs from every
//     zone in P (or P is empty): the origin is published from another zone,
//     which is easy to miss when locking down DNS.
//
// For each discovered hostname d not already in U (proxied state unknown, or
// proxied itself): MEDIUM key discovered:<d>, because an expansion-discovered
// name resolving to the origin is a leak lead.
//
// Not findings: two proxied hostnames sharing an origin; an IP that is not
// flagged origin (Applies is false and Run returns nothing); many unproxied
// names on a non-origin IP; neighbours via any relation but resolves_to.
package correlation

import (
	"context"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "origin.correlation"

// Host is a hostname that resolves to the IP.
type Host struct {
	Name, Zone, Source string
}

// Set is the hostnames pointing at an IP, split by proxy state.
type Set struct {
	Proxied, Unproxied, Discovered []Host
	// Conflicting proxy evidence forbids absence-based finding resolution.
	Conflicting []Host
}

// Names returns the sorted hostname names of hs.
func Names(hs []Host) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, h.Name)
	}
	sort.Strings(out)
	return out
}

// Publish classifies the resolves_to hostname neighbours. It is shared with
// origin.exposed so its evidence can name the same hostnames.
func Publish(ns []check.Neighbour) Set {
	var p Set
	seen := map[string]bool{}
	for _, n := range ns {
		if n.Asset.Kind != model.KindHostname || n.Relation != model.RelResolvesTo {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(n.Asset.Key, "."))
		if seen[name] {
			continue
		}
		seen[name] = true
		h := Host{Name: name, Zone: checkutil.AssetZone(n.Asset), Source: n.Asset.Source}
		if d, _ := n.Asset.Attrs["discovered_by"].(string); d != "" {
			p.Discovered = append(p.Discovered, h)
		}
		v, source, ok, conflict := checkutil.BoolAttribute(n.Asset, "proxied")
		if conflict {
			p.Conflicting = append(p.Conflicting, h)
		}
		if ok {
			h.Source = source
			if v {
				p.Proxied = append(p.Proxied, h)
			} else {
				p.Unproxied = append(p.Unproxied, h)
			}
		}
	}
	for _, s := range [][]Host{p.Proxied, p.Unproxied, p.Discovered, p.Conflicting} {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	}
	return p
}

// Check is the origin.correlation check.
type Check struct{}

// New builds the check.
func New() *Check { return &Check{} }

// Checks is the wiring constructor.
func Checks(_ map[string]map[string]any) []check.Check { return []check.Check{New()} }

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

// Applies matches owned IPs flagged as an origin behind a proxy.
func (*Check) Applies(a model.Asset) bool {
	return a.Kind == model.KindIP && a.Scope == model.ScopeOwned && checkutil.AnyAttributeTrue(a, "origin")
}

// Run applies the rules in the package documentation.
func (c *Check) Run(_ context.Context, t check.Target) (*check.Result, error) {
	res := &check.Result{}
	if !c.Applies(t.Asset) {
		return res, nil
	}
	ip := t.Asset.Key
	p := Publish(t.Neighbours)
	res.Partial = len(p.Conflicting) > 0
	pzones := map[string]bool{}
	for _, h := range p.Proxied {
		pzones[h.Zone] = true
	}
	inU := map[string]bool{}
	for _, u := range p.Unproxied {
		inU[u.Name] = true
		switch {
		case len(p.Proxied) > 0 && pzones[u.Zone]:
			res.Findings = append(res.Findings, high(ip, u, p))
		case !pzones[u.Zone]:
			res.Findings = append(res.Findings, medium(ip, "cross-zone:"+u.Name,
				"Proxied origin IP is also published by an unproxied record in another zone",
				"The origin IP "+ip+" is the unproxied target of "+u.Name+" in zone "+u.Zone+", a different zone from its proxied hostnames. Anyone enumerating DNS can learn the origin and bypass the CDN/WAF.", u, p))
		}
	}
	for _, d := range p.Discovered {
		if inU[d.Name] {
			continue
		}
		res.Findings = append(res.Findings, medium(ip, "discovered:"+d.Name,
			"Origin IP is the target of a hostname found by CT/expansion discovery",
			"The origin IP "+ip+" is the A record target of "+d.Name+", a name found through certificate transparency or expansion rather than your DNS sources. Verify it is not leaking the origin.", d, p))
	}
	return res, nil
}

const remediation = "Proxy the record through the CDN or remove it, then firewall the origin so it accepts traffic only from the CDN's published IP ranges (or use a tunnel / authenticated origin pull). Rotate the origin IP if it was exposed for long."

func evidence(ip string, u Host, p Set) map[string]any {
	srcs := map[string]string{}
	for _, hs := range [][]Host{p.Proxied, {u}} {
		for _, h := range hs {
			srcs[h.Name] = h.Source
		}
	}
	return map[string]any{
		"ip":                  ip,
		"proxied_hostnames":   Names(p.Proxied),
		"unproxied_hostnames": []string{u.Name},
		"sources":             srcs,
	}
}

func high(ip string, u Host, p Set) model.FindingInput {
	return model.FindingInput{
		Check: Name, Key: "published:" + u.Name, Severity: model.SeverityHigh,
		Title:       "Proxied origin IP is directly published by an unproxied DNS record",
		Description: "The origin IP " + ip + " serves proxied hostnames " + strings.Join(Names(p.Proxied), ", ") + ", but the unproxied record " + u.Name + " resolves straight to it, revealing the origin and letting attackers bypass the CDN's WAF, DDoS protection and rate limits.",
		Remediation: remediation, Evidence: evidence(ip, u, p),
		Tags: []string{"origin", "waf-bypass", "dns"},
	}
}

func medium(ip, key, title, desc string, u Host, p Set) model.FindingInput {
	return model.FindingInput{
		Check: Name, Key: key, Severity: model.SeverityMedium,
		Title: title, Description: desc, Remediation: remediation,
		Evidence: evidence(ip, u, p), Tags: []string{"origin", "dns"},
	}
}
