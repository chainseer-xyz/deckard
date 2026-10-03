// Package expiry implements domain.expiry: registration health of the owned
// registrable domains (zone apexes), read from the registry's RDAP service
// through Target.Intel. It never contacts the domain's own infrastructure,
// except for one NS lookup through the scope-guarded resolver.
//
// Only owned zone assets that are registrable domains (ICANN eTLD+1, via the
// public suffix list) apply: subzones such as corp.example.com share the
// apex's registration and public suffixes have none. Every zone asset of one
// apex resolves to the same RDAP URL, so the intel client's cache and
// single-flight collapse them into one registry query.
//
// Findings (thresholds under checks.domain.expiry):
//
//	expired               critical  past the expiration date, or the registry
//	                                shows redemption period / pending delete
//	expiring              high      expires within high_days (14)
//	                      medium    within medium_days (30)
//	                      low       within low_days (60)
//	transfer-unlocked     medium    no client/server transfer prohibited status
//	no-delete-protection  info      no client/server delete prohibited status
//	drift/registrar       high      the registrar differs from the learned baseline
//	drift/nameservers     high      the delegated nameserver set differs from the
//	                                baseline (order is ignored)
//
// Lock findings need a status list: registries that publish none are noted,
// not flagged. lock_exempt_tlds (list) skips them for TLDs whose registrars
// cannot set the locks.
//
// An unsupported TLD, a 404, a lookup failure or a disabled intel client is
// never a finding: the run records an observation (rdap: unsupported,
// not_found, unavailable or skipped) and is partial, so nothing resolves and
// no baseline moves.
package expiry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/intel/rdap"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "domain.expiry"

// DefaultInterval is the check's cadence: registry data moves slowly and the
// thresholds are measured in days.
const DefaultInterval = 12 * time.Hour

// Default thresholds in days.
const (
	DefaultHighDays   = 14
	DefaultMediumDays = 30
	DefaultLowDays    = 60
)

// RDAP observation states.
const (
	StateOK          = "ok"
	StateUnsupported = "unsupported"
	StateNotFound    = "not_found"
	StateUnavailable = "unavailable"
	StateSkipped     = "skipped"
)

// Check is the domain.expiry check.
type Check struct {
	base map[string]any
	now  func() time.Time
}

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg, now: time.Now} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string                   { return Name }
func (*Check) Tier() model.Tier               { return model.TierPassive }
func (*Check) DefaultInterval() time.Duration { return DefaultInterval }

// Applies matches owned zones that are registrable domains.
func (*Check) Applies(a model.Asset) bool {
	if a.Kind != model.KindZone || a.Scope != model.ScopeOwned {
		return false
	}
	apex, ok := Registrable(a.Key)
	return ok && apex == checkutil.Norm(a.Key)
}

// Registrable returns name's registrable domain: the label in front of its
// ICANN public suffix. Private suffixes (github.io, ...) are walked past, since
// the registration that matters is the ICANN one. ok is false for public
// suffixes themselves, unlisted TLDs and names that are not plain LDH.
func Registrable(name string) (string, bool) {
	n := checkutil.Norm(name)
	if !ldh(n) {
		return "", false
	}
	suffix, icann := publicsuffix.PublicSuffix(n)
	for !icann {
		i := strings.IndexByte(suffix, '.')
		if i < 0 {
			return "", false // no ICANN suffix: an unlisted TLD
		}
		suffix, icann = publicsuffix.PublicSuffix(suffix[i+1:])
	}
	if suffix == n || !strings.HasSuffix(n, "."+suffix) {
		return "", false
	}
	rest := strings.TrimSuffix(n, "."+suffix)
	return rest[strings.LastIndexByte(rest, '.')+1:] + "." + suffix, true
}

func ldh(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

type thresholds struct{ high, medium, low int }

func readThresholds(cfg map[string]any, obs map[string]any) thresholds {
	th := thresholds{
		high:   checkutil.Int(cfg, "high_days", DefaultHighDays),
		medium: checkutil.Int(cfg, "medium_days", DefaultMediumDays),
		low:    checkutil.Int(cfg, "low_days", DefaultLowDays),
	}
	if th.high < 1 || th.medium < th.high || th.low < th.medium || th.low > 3650 {
		obs["thresholds_note"] = fmt.Sprintf("invalid thresholds (need 1 <= high_days <= medium_days <= low_days <= 3650); using %d/%d/%d",
			DefaultHighDays, DefaultMediumDays, DefaultLowDays)
		return thresholds{DefaultHighDays, DefaultMediumDays, DefaultLowDays}
	}
	return th
}

// Run looks the zone apex up in its registry's RDAP service.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	domain := checkutil.Norm(t.Asset.Key)
	obs := map[string]any{"domain": domain}
	res := &check.Result{}
	skip := func(state, note string) (*check.Result, error) {
		obs["rdap"] = state
		obs["rdap_note"] = note
		res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
		res.Partial = true // no answer proves nothing: nothing resolves, no baseline moves
		return res, nil
	}
	if apex, ok := Registrable(domain); !ok || apex != domain {
		return skip(StateSkipped, "not a registrable domain (a subzone or public suffix); the registration is checked at the apex")
	}
	if t.Intel == nil {
		return skip(StateSkipped, "metadata client not available")
	}
	base, err := t.Intel.RDAPBase(ctx, domain)
	if err != nil {
		return skip(classify(err))
	}
	resp, err := t.Intel.Get(ctx, intel.ServiceRDAP, base+"domain/"+url.PathEscape(domain))
	if err != nil {
		return skip(classify(err))
	}
	d, err := rdap.ParseDomain(resp.Body, domain)
	if err != nil {
		return skip(StateUnavailable, "unusable rdap response: "+err.Error())
	}

	now := c.now()
	th := readThresholds(cfg, obs)
	obs["rdap"] = StateOK
	obs["registrar"] = d.Registrar
	obs["nameservers"] = nonNil(d.Nameservers)
	obs["statuses"] = nonNil(d.Statuses)
	if !d.Expires.IsZero() {
		obs["expires"] = d.Expires.Format(time.RFC3339)
		obs["days_remaining"] = daysRemaining(d.Expires, now)
	}
	if !d.Registered.IsZero() {
		obs["registered"] = d.Registered.Format(time.RFC3339)
	}
	if d.DNSSEC != nil {
		obs["dnssec"] = *d.DNSSEC
	}
	if t.Resolver != nil {
		if live, err := t.Resolver.LookupNS(ctx, domain); err == nil && len(live) > 0 {
			obs["live_nameservers_match"] = sameSet(normAll(live), d.Nameservers)
		}
	}

	ev := evidence(d, now)
	res.Findings = append(res.Findings, expiryFindings(d, now, th, ev)...)
	if len(d.Statuses) == 0 {
		obs["locks_note"] = "the registry publishes no status values; lock findings skipped"
	} else if !exempt(cfg, domain) {
		res.Findings = append(res.Findings, lockFindings(d, ev)...)
	}
	res.Findings = append(res.Findings, driftFindings(t.Baseline[Name], d, ev)...)
	res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
	return res, nil
}

// classify maps an intel error onto an observation state and note. None of
// them is a finding.
func classify(err error) (string, string) {
	switch {
	case errors.Is(err, intel.ErrDisabled):
		return StateSkipped, "intel disabled (intel.enabled or intel.services.rdap.enabled is false)"
	case errors.Is(err, intel.ErrUnsupported):
		return StateUnsupported, "the TLD publishes no RDAP service in the IANA bootstrap"
	case errors.Is(err, intel.ErrNotFound):
		return StateNotFound, "the registry's RDAP service has no record of this domain"
	}
	return StateUnavailable, err.Error()
}

func daysRemaining(exp, now time.Time) int { return int(exp.Sub(now).Hours() / 24) }

func evidence(d *rdap.Domain, now time.Time) map[string]any {
	ev := map[string]any{
		"domain":      d.Name,
		"registrar":   d.Registrar,
		"statuses":    nonNil(d.Statuses),
		"nameservers": nonNil(d.Nameservers),
	}
	if !d.Expires.IsZero() {
		ev["expires"] = d.Expires.Format(time.RFC3339)
		ev["days_remaining"] = daysRemaining(d.Expires, now)
	}
	if !d.LastChanged.IsZero() {
		ev["last_changed"] = d.LastChanged.Format(time.RFC3339)
	}
	if d.RegistrarIANAID != "" {
		ev["registrar_iana_id"] = d.RegistrarIANAID
	}
	return ev
}

func finding(key string, sev model.Severity, title, desc, remediation string, ev map[string]any, tags ...string) model.FindingInput {
	return model.FindingInput{Check: Name, Key: key, Severity: sev, Title: title, Description: desc,
		Remediation: remediation, Evidence: ev, Tags: append([]string{"domain", "registration"}, tags...)}
}

const renewAdvice = "Renew the domain at the registrar now, then enable auto-renew, check that the payment method on file is valid and that renewal notices go to a monitored mailbox."

func expiryFindings(d *rdap.Domain, now time.Time, th thresholds, ev map[string]any) []model.FindingInput {
	date := d.Expires.Format("2006-01-02")
	switch {
	case d.Has(rdap.StatusRedemptionPeriod) || d.Has(rdap.StatusPendingDelete):
		return []model.FindingInput{finding("expired", model.SeverityCritical,
			fmt.Sprintf("Domain %s is being deleted by its registry (%s)", d.Name, strings.Join(deletionStates(d), ", ")),
			"The registry shows the domain in its deletion pipeline. Its DNS may already have stopped resolving, and once the deletion completes anyone can register it and receive its traffic and mail.",
			"Restore the domain with the registrar immediately (a redemption restore carries a fee), then enable auto-renew and check the payment method on file.", ev)}
	case d.Expires.IsZero():
		return nil
	case !now.Before(d.Expires):
		return []model.FindingInput{finding("expired", model.SeverityCritical,
			fmt.Sprintf("Domain %s expired on %s", d.Name, date),
			"The registration has passed its expiration date. The registrar may stop resolving it at any moment, and after the grace periods it is released for anyone to register.",
			renewAdvice, ev)}
	}
	days := daysRemaining(d.Expires, now)
	var sev model.Severity
	var limit int
	switch {
	case days <= th.high:
		sev, limit = model.SeverityHigh, th.high
	case days <= th.medium:
		sev, limit = model.SeverityMedium, th.medium
	case days <= th.low:
		sev, limit = model.SeverityLow, th.low
	default:
		return nil
	}
	return []model.FindingInput{finding("expiring", sev,
		fmt.Sprintf("Domain %s expires in %d days", d.Name, days),
		fmt.Sprintf("The registration expires on %s, within the %d-day threshold. If it lapses the domain stops resolving and can eventually be registered by someone else.", date, limit),
		renewAdvice, ev)}
}

func deletionStates(d *rdap.Domain) []string {
	var out []string
	for _, s := range []string{rdap.StatusRedemptionPeriod, rdap.StatusPendingDelete} {
		if d.Has(s) {
			out = append(out, s)
		}
	}
	return out
}

func lockFindings(d *rdap.Domain, ev map[string]any) []model.FindingInput {
	var out []model.FindingInput
	if !d.Has(rdap.StatusClientTransferProhibited) && !d.Has(rdap.StatusServerTransferProhibited) {
		out = append(out, finding("transfer-unlocked", model.SeverityMedium,
			fmt.Sprintf("Domain %s has no transfer lock", d.Name),
			"The registry shows neither clientTransferProhibited nor serverTransferProhibited, so a transfer request backed by a leaked or socially engineered auth code can move the domain to another registrar. Unauthorised transfers are a common route to domain hijacking.",
			"Enable the registrar lock (clientTransferProhibited, usually a \"transfer lock\" switch in the registrar's control panel) and lift it only for a planned transfer. For high-value domains ask the registrar for a registry lock (serverTransferProhibited).",
			ev, "hijack"))
	}
	if !d.Has(rdap.StatusClientDeleteProhibited) && !d.Has(rdap.StatusServerDeleteProhibited) {
		out = append(out, finding("no-delete-protection", model.SeverityInfo,
			fmt.Sprintf("Domain %s has no delete protection", d.Name),
			"The registry shows neither clientDeleteProhibited nor serverDeleteProhibited, so a mistaken request or a compromised registrar account can delete the domain.",
			"Enable clientDeleteProhibited at the registrar (often part of its domain lock), or a registry lock for high-value domains.", ev))
	}
	return out
}

func exempt(cfg map[string]any, domain string) bool {
	for _, tld := range checkutil.Strings(cfg, "lock_exempt_tlds", nil) {
		tld = strings.Trim(strings.ToLower(strings.TrimSpace(tld)), ".")
		if tld != "" && strings.HasSuffix(domain, "."+tld) {
			return true
		}
	}
	return false
}

// driftFindings compares the registrar and nameserver set with the learned
// baseline (the previous successful observation, or the stable value while a
// change is pending). They keep firing until the baseline adopts the change,
// then resolve like any drift.
func driftFindings(base map[string]any, d *rdap.Domain, ev map[string]any) []model.FindingInput {
	if base == nil || base["rdap"] != StateOK {
		return nil
	}
	var out []model.FindingInput
	if old, _ := base["registrar"].(string); old != "" && d.Registrar != "" && !strings.EqualFold(old, d.Registrar) {
		e := clone(ev)
		e["old"], e["new"] = old, d.Registrar
		out = append(out, finding("drift/registrar", model.SeverityHigh,
			fmt.Sprintf("Registrar of %s changed from %s to %s", d.Name, old, d.Registrar),
			"The domain is now sponsored by a different registrar than the learned baseline. If nobody planned a transfer, this is a strong sign of domain hijacking: whoever controls the new registrar account controls the domain's DNS.",
			"Confirm with whoever owns the domain whether the transfer was planned. If not, contact both registrars immediately to dispute the transfer, and enable the transfer lock once it is back. If it was planned, the baseline adopts the new registrar after several consistent runs and this finding resolves.",
			e, "drift", "hijack"))
	}
	if old := toStrings(base["nameservers"]); len(old) > 0 && len(d.Nameservers) > 0 && !sameSet(old, d.Nameservers) {
		e := clone(ev)
		e["old"], e["new"] = old, d.Nameservers
		out = append(out, finding("drift/nameservers", model.SeverityHigh,
			fmt.Sprintf("Nameservers of %s changed at the registry", d.Name),
			"The delegation published by the registry differs from the learned baseline. If nobody changed DNS providers, someone with access to the registrar account may have redirected the domain: they can then answer for every name in it, including mail and certificate validation.",
			"Confirm the change with your DNS owners. If it was not planned, restore the nameservers at the registrar, rotate the registrar account's credentials and enable its lock. If it was planned, the baseline adopts the new set after several consistent runs and this finding resolves.",
			e, "drift", "hijack"))
	}
	return out
}

func toStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case []string:
		out = slices.Clone(t)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return normAll(out)
}

func normAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if n := checkutil.Norm(s); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

func sameSet(a, b []string) bool { return slices.Equal(normAll(a), normAll(b)) }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}
