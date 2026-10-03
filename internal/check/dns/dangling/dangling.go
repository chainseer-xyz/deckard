// Package dangling implements dns.dangling: CNAMEs and NS delegations that
// point at names which no longer exist (a precursor to subdomain / delegation
// takeover).
//
// Config keys (Target.Config, overlaid on the constructor config):
//
//	owned_zones  []string  extra zones whose names may be emitted as discovered
//	                       hostnames/relations (default: the asset's own zone)
//	check_ns     bool      also check NS delegations (default true)
package dangling

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "dns.dangling"

// Check is the dns.dangling check.
type Check struct{ base map[string]any }

// New builds the check with constructor-level config.
func New(cfg map[string]any) *Check { return &Check{base: cfg} }

// Checks is the constructor the wiring code calls with the global per-check
// config map.
func Checks(cfg map[string]map[string]any) []check.Check {
	return []check.Check{New(cfg[Name])}
}

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

// Applies matches owned hostnames and zones.
func (*Check) Applies(a model.Asset) bool {
	return (a.Kind == model.KindHostname || a.Kind == model.KindZone) && a.Scope == model.ScopeOwned
}

// ClassifyCNAME turns a resolved CNAME chain end into a finding, or nil when
// the chain is healthy. owned says the final target sits in an owned zone.
func ClassifyCNAME(host, final string, finalNXDomain, owned bool) *model.FindingInput {
	if !finalNXDomain || final == host {
		return nil
	}
	ev := map[string]any{"host": host, "cname_target": final, "target_in_owned_zone": owned}
	if owned {
		return &model.FindingInput{
			Check: Name, Key: "cname-owned-missing", Severity: model.SeverityHigh,
			Title:       fmt.Sprintf("%s is a CNAME to %s, which no longer exists", host, final),
			Description: "The CNAME points at a name inside one of your own zones that returns NXDOMAIN. The alias is dead, and anyone able to (re)create that name, or an attacker who can register the service it fronts, can serve content under " + host + ".",
			Remediation: "Delete the CNAME for " + host + " if it is no longer needed, or recreate the missing target " + final + " (and anything it fronts) so the alias resolves again.",
			Evidence:    ev, Tags: []string{"dns", "dangling", "takeover"},
		}
	}
	return &model.FindingInput{
		Check: Name, Key: "cname-nxdomain", Severity: model.SeverityHigh,
		Title:       fmt.Sprintf("%s CNAME chain ends in NXDOMAIN (%s)", host, final),
		Description: "The CNAME chain for this name terminates at a name that does not exist. If the target is a third-party service endpoint that someone else can claim, this is a subdomain takeover risk.",
		Remediation: "Remove the stale CNAME for " + host + ", or restore the third-party resource it pointed at. Review dns.takeover results for the same host.",
		Evidence:    ev, Tags: []string{"dns", "dangling", "takeover"},
	}
}

// ClassifyNS flags a delegation to a nameserver whose name does not exist.
func ClassifyNS(zone, ns string, nxdomain bool) *model.FindingInput {
	if !nxdomain {
		return nil
	}
	return &model.FindingInput{
		Check: Name, Key: "ns:" + ns, Severity: model.SeverityCritical,
		Title:       fmt.Sprintf("%s delegates to non-existent nameserver %s", zone, ns),
		Description: "An NS record delegates this name to a nameserver whose hostname returns NXDOMAIN. Whoever registers that nameserver domain can answer authoritatively for " + zone + " (delegation takeover), allowing them to serve any record, including mail and TLS validation records.",
		Remediation: "Remove the NS record for " + ns + " from the parent zone, or point it at a nameserver you control. If the nameserver domain expired, re-register it immediately.",
		Evidence:    map[string]any{"zone": zone, "nameserver": ns},
		Tags:        []string{"dns", "delegation", "takeover"},
	}
}

// Run resolves the asset's CNAME chain and NS delegations.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	t.Config = cfg
	host := checkutil.Norm(t.Asset.Key)
	zones := checkutil.OwnedZones(t)
	res := &check.Result{}
	obs := map[string]any{"host": host}

	if t.DNS != nil {
		c.runDNS(ctx, t, res, obs, cfg, host, zones)
		res.Observations = append(res.Observations, model.ObservationInput{Check: Name, Data: obs})
		res.Partial = unknown(obs)
		return res, nil
	}

	cname, err := t.Resolver.LookupCNAME(ctx, host)
	switch {
	case err == nil:
		final := checkutil.Norm(cname)
		obs["cname_chain"] = []string{host, final}
		if final != host {
			c.cnameRun(ctx, t, res, obs, host, final, zones)
		}
	case checkutil.IsNotFound(err):
		obs["exists"] = false
	default:
		obs["cname_error"] = err.Error()
	}

	if checkutil.Bool(cfg, "check_ns", true) {
		c.nsRun(ctx, t, res, obs, host)
	}
	res.Observations = append(res.Observations, model.ObservationInput{Check: Name, Data: obs})
	res.Partial = unknown(obs)
	return res, nil
}

// unknown reports whether a lookup ended in SERVFAIL, a timeout or another
// non-NXDOMAIN error. Such a run is partial: it saw nothing, so it must not
// count a miss against (and eventually resolve) an open finding.
func unknown(obs map[string]any) bool {
	for _, k := range []string{"dns_unknown", "cname_error", "final_error", "ns_error"} {
		if _, ok := obs[k]; ok {
			return true
		}
	}
	return false
}

func (c *Check) cnameRun(ctx context.Context, t check.Target, res *check.Result, obs map[string]any, host, final string, zones []string) {
	_, err := t.Resolver.LookupHost(ctx, final)
	nx := checkutil.IsNotFound(err)
	obs["final_resolves"] = err == nil
	if err != nil && !nx {
		obs["final_error"] = err.Error()
	}
	finalZone := checkutil.ZoneOf(final, zones)
	if f := ClassifyCNAME(host, final, nx, finalZone != ""); f != nil {
		res.Findings = append(res.Findings, *f)
	}
	// Graph edges are emitted only for names in owned zones.
	if finalZone != "" && checkutil.ZoneOf(host, zones) != "" {
		res.Discovered = append(res.Discovered, model.AssetInput{
			Kind: model.KindHostname, Key: final, Source: checkutil.Source(Name), Zone: finalZone,
		})
		res.Relations = append(res.Relations, model.RelationInput{
			FromKind: model.KindHostname, FromKey: host, ToKind: model.KindHostname, ToKey: final, Type: model.RelCNAMETo,
		})
	}
}

func (c *Check) nsRun(ctx context.Context, t check.Target, res *check.Result, obs map[string]any, host string) {
	nss, err := t.Resolver.LookupNS(ctx, host)
	if err != nil {
		if !checkutil.IsNotFound(err) {
			obs["ns_error"] = err.Error()
		}
		return
	}
	var names []string
	status := map[string]string{}
	for _, raw := range nss {
		ns := checkutil.Norm(raw)
		if ns == "" || strings.ContainsAny(ns, " \t") {
			continue
		}
		names = append(names, ns)
		_, err := t.Resolver.LookupHost(ctx, ns)
		nx := checkutil.IsNotFound(err)
		switch {
		case nx:
			status[ns] = "nxdomain"
		case err != nil:
			status[ns] = "error"
			obs["dns_unknown"] = true
		default:
			status[ns] = "ok"
		}
		if f := ClassifyNS(host, ns, nx); f != nil {
			res.Findings = append(res.Findings, *f)
		}
	}
	obs["ns"] = checkutil.SortedUnique(names)
	obs["ns_status"] = status
}

// runDNS is the rcode-aware path used when Target.DNS is set. A dangling
// CNAME is a chain that a resolver confirmed ends in NXDOMAIN at some hop;
// SERVFAIL, timeouts, loops and over-long chains are unknown and never produce
// a finding (they are recorded in the observation instead).
func (c *Check) runDNS(ctx context.Context, t check.Target, res *check.Result, obs map[string]any, cfg map[string]any, host string, zones []string) {
	ch, err := t.DNS.ResolveChain(ctx, host)
	if err != nil {
		obs["cname_error"] = err.Error()
	} else {
		obs["cname_chain"] = ch.Names()
		obs["cname_state"] = ch.State.String()
		switch {
		case ch.State == dnsx.StateUnknown:
			obs["dns_unknown"] = true
			obs["cname_end"] = ch.End
			if ch.Err != nil {
				obs["cname_error"] = ch.Err.Error()
			} else {
				obs["cname_error"] = "resolver answered rcode " + dns.RcodeToString[ch.Rcode]
			}
		case ch.State == dnsx.StateLoop || ch.State == dnsx.StateTooDeep:
			obs["cname_end"] = ch.End
		case ch.Len() == 0:
			obs["exists"] = ch.State != dnsx.StateNXDomain
		default:
			final := ch.End
			obs["final_resolves"] = ch.State == dnsx.StateResolved
			finalZone := checkutil.ZoneOf(final, zones)
			if f := ClassifyCNAME(host, final, ch.State == dnsx.StateNXDomain, finalZone != ""); f != nil {
				f.Evidence["cname_chain"] = ch.Names()
				f.Evidence["nxdomain_at_hop"] = ch.Len()
				res.Findings = append(res.Findings, *f)
			}
			if finalZone != "" && checkutil.ZoneOf(host, zones) != "" {
				res.Discovered = append(res.Discovered, model.AssetInput{
					Kind: model.KindHostname, Key: final, Source: checkutil.Source(Name), Zone: finalZone,
				})
				res.Relations = append(res.Relations, model.RelationInput{
					FromKind: model.KindHostname, FromKey: host, ToKind: model.KindHostname, ToKey: final, Type: model.RelCNAMETo,
				})
			}
		}
	}
	if checkutil.Bool(cfg, "check_ns", true) {
		c.nsRunDNS(ctx, t, res, obs, host)
	}
}

func (c *Check) nsRunDNS(ctx context.Context, t check.Target, res *check.Result, obs map[string]any, host string) {
	resp, err := t.DNS.Query(ctx, host, dns.TypeNS)
	if err != nil {
		obs["ns_error"] = err.Error()
		obs["dns_unknown"] = true
		return
	}
	if st := resp.State(); st == dnsx.StateUnknown {
		obs["ns_error"] = "resolver answered rcode " + dns.RcodeToString[resp.Rcode]
		obs["dns_unknown"] = true
		return
	}
	var names []string
	status := map[string]string{}
	for _, rr := range resp.Records(dns.TypeNS) {
		ns := checkutil.Norm(rr.(*dns.NS).Ns)
		if ns == "" || strings.ContainsAny(ns, " \t") {
			continue
		}
		names = append(names, ns)
		ch, err := t.DNS.ResolveChain(ctx, ns)
		switch {
		case err != nil || ch.State == dnsx.StateUnknown || ch.State == dnsx.StateLoop || ch.State == dnsx.StateTooDeep:
			status[ns] = "error"
			obs["dns_unknown"] = true
		case ch.State == dnsx.StateNXDomain:
			status[ns] = "nxdomain"
			res.Findings = append(res.Findings, *ClassifyNS(host, ns, true))
		default:
			status[ns] = "ok"
		}
	}
	obs["ns"] = checkutil.SortedUnique(names)
	obs["ns_status"] = status
}
