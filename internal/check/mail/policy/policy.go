// Package policy implements mail.policy: the mail-security policies of the
// owned registrable domains that dns.hygiene does not cover. dns.hygiene owns
// SPF/DMARC presence, "+all", "?all", a missing "all", more than ten DNS lookups,
// multiple SPF records and p=none; this check never repeats those. It adds:
//
//	mta-sts-missing          low     the zone receives mail (MX) but publishes no
//	                                 MTA-STS (_mta-sts TXT)
//	mta-sts-txt-invalid      medium  more than one v=STSv1 record, or no usable id
//	mta-sts-policy-unavailable medium the TXT record is published but the policy file
//	                                 answers 4xx
//	mta-sts-policy-redirect  medium  the policy file redirects (RFC 8461 forbids
//	                                 following redirects, so senders ignore it)
//	mta-sts-policy-invalid   medium  the policy file lacks version, mode, max_age
//	                                 or (unless mode is none) mx, or is malformed
//	mta-sts-mode-none        low     mode: none switches the policy off
//	mta-sts-mode-testing     low     mode: testing never makes a sender refuse
//	                                 delivery
//	mta-sts-max-age-short    low     max_age below min_max_age (default one week)
//	mta-sts-mx-mismatch      medium  (enforce) / low (testing): a real MX host
//	                                 matches no mx: pattern; enforcing senders
//	                                 would refuse to deliver to it
//	tls-rpt-missing          info    no _smtp._tls TXT record (low when MTA-STS is
//	                                 published, since failures would go unseen)
//	tls-rpt-invalid          low     more than one record, or no mailto:/https: rua
//	dmarc-multiple           medium  more than one DMARC record (receivers ignore
//	                                 all of them)
//	dmarc-pct                low     pct below 100 on an enforcing policy
//	dmarc-sp-none            low     sp=none exempts subdomains from an enforcing p
//	dmarc-no-rua             info    no aggregate report address
//	spf-softfail             low     "~all" on a mail zone without an enforcing DMARC
//	                         info    ... with one (DMARC decides, ~all is common)
//	null-mx-missing          info    a zone with no MX and no RFC 7505 null MX
//
// Only a zone with MX records (or checks.mail.policy.expects_mail) is judged a
// mail zone. MTA-STS and TLS-RPT protect inbound mail, so their absence is only
// raised for zones with a real MX. Parked zones (no MX) should publish null
// SPF/DMARC records: dns.hygiene already reports those as missing, with the
// exact records, so this check adds only the null MX that closes the remaining
// gap. Findings are never above medium.
//
// MTA-STS policies are fetched from https://mta-sts.<zone>/.well-known/mta-sts.txt
// through the scope-guarded Target.HTTP, at most 64 KiB. Anything the check
// could not establish (MX unknown, a TXT lookup that failed, a policy fetch
// that failed, timed out, was refused by the guard or answered 5xx/429, no HTTP
// client) is noted in the observation and makes the run partial: nothing
// resolves on missing data.
//
// Options (checks.mail.policy):
//
//	expects_mail   bool  treat the zone as a mail zone even without MX (same
//	                     meaning as for dns.hygiene)
//	check_mta_sts  bool  default true; false skips every MTA-STS finding
//	check_tls_rpt  bool  default true; false skips the TLS-RPT findings
//	min_max_age    int   seconds; MTA-STS max_age below this is short
//	                     (default 604800, one week)
//	timeout_seconds int  policy fetch timeout (default 10)
package policy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/check/domain/expiry"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "mail.policy"

// Defaults.
const (
	DefaultMinMaxAge = 7 * 24 * 3600
	DefaultTimeout   = 10
)

// Check is the mail.policy check.
type Check struct{ base map[string]any }

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

// Applies matches owned zones that are registrable domains: the zone where a
// domain's mail policies live. Subzones inherit the organisational domain's
// DMARC and have no MTA-STS of their own to judge.
func (*Check) Applies(a model.Asset) bool {
	if a.Kind != model.KindZone || a.Scope != model.ScopeOwned {
		return false
	}
	apex, ok := expiry.Registrable(a.Key)
	return ok && apex == checkutil.Norm(a.Key)
}

func finding(key string, sev model.Severity, title, desc, remediation string, ev map[string]any, tags ...string) model.FindingInput {
	return model.FindingInput{Check: Name, Key: key, Severity: sev, Title: title, Description: desc,
		Remediation: remediation, Evidence: ev, Tags: append([]string{"mail", "email-auth"}, tags...)}
}

// run is the state of one Run.
type run struct {
	t    check.Target
	cfg  map[string]any
	zone string
	res  *check.Result
	obs  map[string]any
	// unsure is set by any lookup that did not give an answer.
	unsure bool
	// mxHosts are the real (non-null) MX targets; mxKnown says the MX query
	// was answered.
	mxHosts []string
	mxKnown bool
	nullMX  bool
}

// note records something that could not be established; the run turns partial.
func (r *run) note(key, msg string) {
	r.unsure = true
	r.obs[key] = msg
}

func (r *run) add(f model.FindingInput) { r.res.Findings = append(r.res.Findings, f) }

// Run judges the zone's mail policies.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	zone := checkutil.Norm(t.Asset.Key)
	r := &run{t: t, cfg: checkutil.Merge(c.base, t.Config), zone: zone, res: &check.Result{}, obs: map[string]any{"zone": zone}}
	defer func() {
		r.res.Observations = []model.ObservationInput{{Check: Name, Data: r.obs}}
		r.res.Partial = r.unsure
	}()

	if apex, ok := expiry.Registrable(zone); !ok || apex != zone {
		r.note("skipped", "not a registrable domain (a subzone or public suffix)")
		return r.res, nil
	}
	if t.Resolver == nil {
		r.note("skipped", "no resolver in target")
		return r.res, nil
	}
	r.lookupMX(ctx)
	expects := checkutil.Bool(r.cfg, "expects_mail", false)
	switch {
	case len(r.mxHosts) > 0 || expects:
		r.obs["mail"] = "yes"
	case r.mxKnown:
		r.obs["mail"] = "no"
	default:
		r.note("skipped", "whether the zone handles mail is unknown (MX not answered); no mail policy judged")
		return r.res, nil
	}

	if r.obs["mail"] == "no" {
		if !r.nullMX {
			r.add(finding("null-mx-missing", model.SeverityInfo,
				"Zone "+zone+" receives no mail but publishes no null MX",
				"The zone has no MX record, so senders fall back to delivering to its address (A/AAAA) records and keep retrying a host that does not accept mail. A null MX (RFC 7505) says explicitly that the domain accepts no mail.",
				"Publish a null MX on the zone apex: "+zone+". IN MX 0 .",
				map[string]any{"zone": zone}, "mx"))
		}
		return r.res, nil
	}

	dm := r.dmarc(ctx)
	r.spf(ctx, dm)
	mode := ""
	if checkutil.Bool(r.cfg, "check_mta_sts", true) {
		mode = r.mtaSTS(ctx)
	}
	if checkutil.Bool(r.cfg, "check_tls_rpt", true) {
		r.tlsRPT(ctx, mode)
	}
	return r.res, nil
}

// lookupMX fills the MX facts through the rcode-aware querier. Without one the
// MX status stays unknown.
func (r *run) lookupMX(ctx context.Context) {
	if r.t.DNS == nil {
		r.note("mx_error", "no DNS querier in target; MX status unknown")
		return
	}
	resp, err := r.t.DNS.Query(ctx, r.zone, dns.TypeMX)
	if err != nil || resp == nil {
		r.note("mx_error", fmt.Sprint("MX lookup failed: ", err))
		return
	}
	switch resp.State() {
	case dnsx.StateResolved:
		for _, rr := range resp.Records(dns.TypeMX) {
			m, ok := rr.(*dns.MX)
			if !ok {
				continue
			}
			if m.Preference == 0 && (m.Mx == "." || m.Mx == "") {
				r.nullMX = true // RFC 7505: the domain explicitly takes no mail
				continue
			}
			r.mxHosts = append(r.mxHosts, checkutil.Norm(m.Mx))
		}
		slices.Sort(r.mxHosts)
		r.mxHosts = slices.Compact(r.mxHosts)
		r.mxKnown = true
	case dnsx.StateNoData:
		r.mxKnown = true
	default: // SERVFAIL, timeouts, NXDOMAIN, loops: nothing to judge
		r.note("mx_error", "MX lookup inconclusive: "+resp.State().String())
	}
}

// txts looks up TXT records. found is false when the lookup failed (noted);
// a missing name is an empty, successful answer.
func (r *run) txts(ctx context.Context, name, what string) (recs []string, found bool) {
	recs, err := r.t.Resolver.LookupTXT(ctx, name)
	if err != nil && !checkutil.IsNotFound(err) {
		r.note(what+"_error", err.Error())
		return nil, false
	}
	return recs, true
}

// matching returns the records that start with prefix (case-insensitive,
// after trimming).
func matching(recs []string, prefix string) []string {
	var out []string
	for _, s := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), prefix) {
			out = append(out, s)
		}
	}
	return out
}
