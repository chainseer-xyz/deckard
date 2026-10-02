// Package hygiene implements dns.hygiene: zone-level email-authentication and
// record hygiene (SPF, DMARC, wildcard records).
//
// Config keys:
//
//	expects_mail  bool  force mail treatment: missing SPF/DMARC are medium even
//	                    when no MX is found (default false). Without it, mail
//	                    usage is inferred from MX records when Target.DNS is
//	                    set: a zone with MX => missing DMARC/SPF medium; a zone
//	                    without MX (parked) => low, recommending the
//	                    null-sender records; MX unknown => DMARC medium, SPF low.
//	check_wildcard bool probe for wildcard records (default true; one query)
//
// When Target.DNS is set the check additionally reports (all via the
// rcode-aware querier; SERVFAIL/timeouts are unknown and produce no finding,
// only an observation note):
//
//	caa-missing        info    no CAA record at the zone name
//	dnssec-unsigned    low     zone apex has neither DNSKEY nor DS
//	mx-without-spf     medium  zone has a (non-null) MX but no SPF record;
//	                           replaces spf-missing for that zone
//	axfr-open          critical a nameserver serves a zone transfer (the AXFR
//	                           goes through the guarded dialer, so it is only
//	                           attempted against owned nameserver addresses)
//
// check_axfr bool (default true) disables the zone-transfer attempt.
package hygiene

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "dns.hygiene"

// Check is the dns.hygiene check.
type Check struct {
	base      map[string]any
	randLabel func() string
}

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg, randLabel: defaultLabel} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func defaultLabel() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "deckard-wc-" + hex.EncodeToString(b)
}

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

// Applies matches owned zones.
func (*Check) Applies(a model.Asset) bool {
	return a.Kind == model.KindZone && a.Scope == model.ScopeOwned
}

func finding(key string, sev model.Severity, title, desc, remediation string, ev map[string]any) model.FindingInput {
	return model.FindingInput{Check: Name, Key: key, Severity: sev, Title: title, Description: desc,
		Remediation: remediation, Evidence: ev, Tags: []string{"dns", "email-auth"}}
}

// MailUsage says whether a zone handles mail; it drives the severity of
// missing email-authentication records.
type MailUsage int

const (
	// MailUnknown: MX status could not be determined (no DNS querier or an
	// inconclusive answer).
	MailUnknown MailUsage = iota
	// MailYes: the zone has a real MX or the operator set expects_mail.
	MailYes
	// MailNo: the zone demonstrably has no MX (or only a null MX).
	MailNo
)

const spoofNote = " Unprotected domains that send no mail can still be spoofed by attackers."

// ClassifySPF turns the zone's TXT records into SPF findings. lookups is the
// recursive lookup count (only evaluated when a single record exists).
func ClassifySPF(zone string, txts []string, lookups func(SPF) int, usage MailUsage) []model.FindingInput {
	var recs []string
	for _, t := range txts {
		if IsSPFRecord(t) {
			recs = append(recs, t)
		}
	}
	switch len(recs) {
	case 0:
		sev := model.SeverityLow
		if usage == MailYes {
			sev = model.SeverityMedium
		}
		return []model.FindingInput{finding("spf-missing", sev,
			"No SPF record for "+zone,
			"The zone publishes no SPF record, so receivers cannot tell which servers may send mail for it, and mail can be spoofed more easily."+nonSendingNote(usage),
			`Publish a TXT record on the zone apex. For a domain that sends no mail use the null-sender record "v=spf1 -all"; otherwise list your senders and end with "-all" (or "~all" while rolling out).`,
			map[string]any{"zone": zone, "expects_mail": usage == MailYes})}
	case 1:
	default:
		return []model.FindingInput{finding("spf-multiple", model.SeverityMedium,
			"Multiple SPF records for "+zone,
			"RFC 7208 allows exactly one SPF record; multiple records cause a permanent error and SPF is ignored by receivers.",
			"Merge all SPF TXT records into a single record.",
			map[string]any{"zone": zone, "records": recs})}
	}
	spf, _ := ParseSPF(recs[0])
	ev := map[string]any{"zone": zone, "record": recs[0]}
	var out []model.FindingInput
	switch spf.All {
	case "+":
		out = append(out, finding("spf-plus-all", model.SeverityHigh,
			"SPF record for "+zone+" allows any sender (+all)",
			"The record ends in +all (or bare \"all\"), authorising every server on the internet to send as this domain; SPF provides no protection.",
			`Replace +all with "-all" (or "~all" during rollout) after listing your legitimate senders.`, ev))
	case "?":
		out = append(out, finding("spf-neutral-all", model.SeverityMedium,
			"SPF record for "+zone+" is neutral (?all)",
			"?all makes SPF results neutral, so spoofed mail is not distinguished from legitimate mail.",
			`Change ?all to "-all" (or "~all" while rolling out).`, ev))
	case "":
		if spf.Redirect == "" {
			out = append(out, finding("spf-no-all", model.SeverityLow,
				"SPF record for "+zone+" has no terminating all",
				"Without an all mechanism or redirect the default result is neutral, so the record does not restrict unlisted senders.",
				`Terminate the record with "-all" or "~all".`, ev))
		}
	}
	if lookups != nil {
		if n := lookups(spf); n > 10 {
			e := map[string]any{"zone": zone, "record": recs[0], "dns_lookups": n, "limit": 10}
			out = append(out, finding("spf-too-many-lookups", model.SeverityMedium,
				fmt.Sprintf("SPF record for %s needs %d DNS lookups (limit 10)", zone, n),
				"RFC 7208 limits SPF evaluation to 10 DNS-querying terms. Exceeding it yields a permanent error and receivers ignore SPF.",
				"Flatten includes, remove unused vendors, or replace include chains with ip4/ip6 ranges.", e))
		}
	}
	return out
}

func nonSendingNote(usage MailUsage) string {
	if usage == MailYes {
		return ""
	}
	return spoofNote
}

// ClassifyDMARC flags a missing or monitor-only DMARC policy.
func ClassifyDMARC(zone string, txts []string, usage MailUsage) []model.FindingInput {
	for _, t := range txts {
		d, ok := ParseDMARC(t)
		if !ok {
			continue
		}
		if d.Policy == "none" {
			return []model.FindingInput{finding("dmarc-p-none", model.SeverityLow,
				"DMARC policy for "+zone+" is p=none",
				"p=none only monitors; spoofed mail that fails SPF/DKIM is still delivered.",
				"Review aggregate reports, then move to p=quarantine and finally p=reject.",
				map[string]any{"zone": zone, "record": t})}
		}
		return nil
	}
	if usage == MailNo {
		return []model.FindingInput{finding("dmarc-missing", model.SeverityLow,
			"No DMARC record for "+zone,
			"No TXT record exists at _dmarc."+zone+", so receivers have no policy for mail that fails authentication. This zone has no MX records."+spoofNote,
			`This domain appears to send no mail: publish "v=DMARC1; p=reject;" at _dmarc.`+zone+` (and "v=spf1 -all" on the apex) so spoofed mail is rejected.`,
			map[string]any{"zone": zone, "mail": "no_mx"})}
	}
	// MailYes, or MX status unknown (stay conservative): medium.
	return []model.FindingInput{finding("dmarc-missing", model.SeverityMedium,
		"No DMARC record for "+zone,
		"No TXT record exists at _dmarc."+zone+", so receivers have no policy for mail that fails authentication.",
		`Publish "v=DMARC1; p=none; rua=mailto:dmarc@`+zone+`" to start collecting reports, then tighten to quarantine/reject. If the domain sends no mail, publish "v=DMARC1; p=reject;" instead.`,
		map[string]any{"zone": zone})}
}

// WildcardFinding reports a wildcard record.
func WildcardFinding(zone, probe string, addrs []string) model.FindingInput {
	return finding("wildcard-record", model.SeverityInfo,
		"Wildcard DNS record in "+zone,
		"A random, never-created label resolves, so a wildcard record exists. Wildcards hide typos and dangling names and mask subdomain-discovery results.",
		"Confirm the wildcard is intentional; prefer explicit records for the names you serve.",
		map[string]any{"zone": zone, "probe": probe, "addresses": addrs})
}

// Run queries the zone's TXT, _dmarc TXT and a wildcard probe.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	zone := checkutil.Norm(t.Asset.Key)
	res := &check.Result{}
	obs := map[string]any{"zone": zone}
	lookup := func(ctx context.Context, name string) ([]string, error) { return t.Resolver.LookupTXT(ctx, name) }

	var mxPresent, mxKnown bool
	if t.DNS != nil {
		mxPresent, mxKnown = c.dnsExtras(ctx, t, zone, cfg, res, obs)
	}
	usage := MailUnknown
	switch {
	case checkutil.Bool(cfg, "expects_mail", false) || mxPresent:
		usage = MailYes
	case mxKnown:
		usage = MailNo
	}

	txts, err := t.Resolver.LookupTXT(ctx, zone)
	switch {
	case err == nil || checkutil.IsNotFound(err):
		var spf []string
		for _, s := range txts {
			if IsSPFRecord(s) {
				spf = append(spf, s)
			}
		}
		obs["spf"] = spf
		res.Findings = append(res.Findings, ClassifySPF(zone, txts, func(s SPF) int { return CountLookups(ctx, s, lookup) },
			usage)...)
		if mxPresent {
			res.Findings = mxWithoutSPF(zone, res.Findings, obs)
		}
	default:
		obs["txt_error"] = err.Error()
	}

	dm, err := t.Resolver.LookupTXT(ctx, "_dmarc."+zone)
	if err == nil || checkutil.IsNotFound(err) {
		var recs []string
		for _, s := range dm {
			if IsDMARCRecord(s) {
				recs = append(recs, s)
			}
		}
		obs["dmarc"] = recs
		res.Findings = append(res.Findings, ClassifyDMARC(zone, dm, usage)...)
	} else {
		obs["dmarc_error"] = err.Error()
	}

	if checkutil.Bool(cfg, "check_wildcard", true) {
		probe := c.randLabel() + "." + zone
		addrs, err := t.Resolver.LookupHost(ctx, probe)
		obs["wildcard"] = err == nil && len(addrs) > 0
		if err == nil && len(addrs) > 0 {
			res.Findings = append(res.Findings, WildcardFinding(zone, strings.TrimSuffix(probe, "."), addrs))
		}
	}
	res.Observations = append(res.Observations, model.ObservationInput{Check: Name, Data: obs})
	return res, nil
}

func dnsFinding(key string, sev model.Severity, title, desc, remediation string, ev map[string]any) model.FindingInput {
	return model.FindingInput{Check: Name, Key: key, Severity: sev, Title: title, Description: desc,
		Remediation: remediation, Evidence: ev, Tags: []string{"dns"}}
}

// mxWithoutSPF swaps the generic spf-missing finding for the sharper
// mx-without-spf one when the zone demonstrably handles mail.
func mxWithoutSPF(zone string, fs []model.FindingInput, obs map[string]any) []model.FindingInput {
	out := fs[:0:0]
	missing := false
	for _, f := range fs {
		if f.Key == "spf-missing" {
			missing = true
			continue
		}
		out = append(out, f)
	}
	if !missing {
		return fs
	}
	f := finding("mx-without-spf", model.SeverityMedium,
		"Zone "+zone+" has MX records but no SPF record",
		"The zone receives mail (MX present) yet publishes no SPF record, so receivers cannot tell which servers may send as this domain and spoofing is easier.",
		`Publish an SPF TXT record on the zone apex listing your senders and ending in "-all" (or "~all" while rolling out).`,
		map[string]any{"zone": zone, "mx": obs["mx"]})
	return append(out, f)
}

// unknownNote records a lookup that could not be completed without raising a
// finding.
func unknownNote(obs map[string]any, what string, resp *dnsx.Response, err error) {
	obs["dns_unknown"] = true
	switch {
	case err != nil:
		obs[what+"_error"] = err.Error()
	case resp != nil:
		obs[what+"_error"] = "resolver answered rcode " + dns.RcodeToString[resp.Rcode]
	}
}

// dnsExtras runs the querier-based checks and reports whether the zone has a
// real (non-null) MX.
func (c *Check) dnsExtras(ctx context.Context, t check.Target, zone string, cfg map[string]any, res *check.Result, obs map[string]any) (mxPresent, mxKnown bool) {
	if r, err := t.DNS.Query(ctx, zone, dns.TypeMX); err != nil || r.State() == dnsx.StateUnknown {
		unknownNote(obs, "mx", r, err)
	} else {
		var mxs []string
		for _, rr := range r.Records(dns.TypeMX) {
			m := rr.(*dns.MX)
			if m.Preference == 0 && (m.Mx == "." || m.Mx == "") {
				continue // RFC 7505 null MX: the domain explicitly takes no mail
			}
			mxs = append(mxs, checkutil.Norm(m.Mx))
		}
		obs["mx"] = mxs
		mxPresent, mxKnown = len(mxs) > 0, true
	}

	if r, err := t.DNS.Query(ctx, zone, dns.TypeCAA); err != nil || r.State() == dnsx.StateUnknown {
		unknownNote(obs, "caa", r, err)
	} else if st := r.State(); st == dnsx.StateNoData {
		obs["caa"] = []string{}
		res.Findings = append(res.Findings, dnsFinding("caa-missing", model.SeverityInfo,
			"No CAA record for "+zone,
			"Without a CAA record any public CA may issue certificates for this zone. CAA restricts issuance to the CAs you choose.",
			`Publish a CAA record, e.g. 0 issue "letsencrypt.org", for the CAs you actually use.`,
			map[string]any{"zone": zone}))
	} else if st == dnsx.StateResolved {
		var recs []string
		for _, rr := range r.Records(dns.TypeCAA) {
			recs = append(recs, strings.TrimPrefix(rr.String(), rr.Header().String()))
		}
		obs["caa"] = recs
	}

	c.dnssec(ctx, t, zone, res, obs)

	if checkutil.Bool(cfg, "check_axfr", true) {
		rep, err := t.DNS.AXFR(ctx, zone)
		if err != nil {
			obs["axfr_error"] = err.Error()
		} else {
			summary := make([]map[string]any, 0, len(rep.Attempts))
			for _, a := range rep.Attempts {
				e := map[string]any{"ns": a.NS, "addr": a.Addr, "outcome": string(a.Outcome)}
				if a.Note != "" {
					e["note"] = a.Note
				}
				summary = append(summary, e)
			}
			obs["axfr"] = summary
			if rep.Note != "" {
				obs["axfr_note"] = rep.Note
			}
			for _, a := range rep.Open() {
				res.Findings = append(res.Findings, dnsFinding("axfr-open:"+a.NS, model.SeverityCritical,
					fmt.Sprintf("Zone transfer (AXFR) of %s is open on %s", zone, a.NS),
					"The nameserver hands the full zone to anyone who asks, exposing every hostname and record (internal names, mail and service layout) and easing targeted attacks.",
					"Restrict AXFR on "+a.NS+" to your secondary nameservers (allow-transfer / TSIG).",
					map[string]any{"zone": zone, "nameserver": a.NS, "address": a.Addr, "records": a.Records}))
			}
		}
	}
	return mxPresent, mxKnown
}

// dnssec reports an unsigned zone: an owned zone apex (it has an SOA of its
// own) with neither DNSKEY nor DS. Anything uncertain is only noted.
func (c *Check) dnssec(ctx context.Context, t check.Target, zone string, res *check.Result, obs map[string]any) {
	if t.Asset.Scope != model.ScopeOwned {
		return
	}
	soa, err := t.DNS.Query(ctx, zone, dns.TypeSOA)
	if err != nil || soa.State() != dnsx.StateResolved {
		if err != nil || soa.State() == dnsx.StateUnknown {
			unknownNote(obs, "dnssec", soa, err)
		}
		return // not a zone apex (or nonexistent): DNSSEC status is not meaningful here
	}
	key, err1 := t.DNS.Query(ctx, zone, dns.TypeDNSKEY)
	ds, err2 := t.DNS.Query(ctx, zone, dns.TypeDS)
	if err1 != nil || err2 != nil || key.State() == dnsx.StateUnknown || ds.State() == dnsx.StateUnknown {
		obs["dns_unknown"] = true
		obs["dnssec_error"] = "DNSKEY/DS lookup incomplete"
		return
	}
	hasKey, hasDS := key.State() == dnsx.StateResolved, ds.State() == dnsx.StateResolved
	obs["dnssec"] = map[string]any{"dnskey": hasKey, "ds": hasDS, "ad": key.AD || ds.AD}
	if !hasKey && !hasDS && key.State() == dnsx.StateNoData && ds.State() == dnsx.StateNoData {
		res.Findings = append(res.Findings, dnsFinding("dnssec-unsigned", model.SeverityLow,
			"Zone "+zone+" is not DNSSEC-signed",
			"Neither a DNSKEY at the zone nor a DS in the parent was found, so resolvers cannot detect forged answers for this zone.",
			"Enable DNSSEC signing at your DNS provider and publish the DS record at your registrar.",
			map[string]any{"zone": zone}))
	}
}
