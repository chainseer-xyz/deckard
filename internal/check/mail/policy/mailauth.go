package policy

import (
	"context"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/check/dns/hygiene"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// dmarcState is what the DMARC lookup established.
type dmarcState struct {
	one      bool // exactly one record
	enforced bool // p is quarantine or reject
}

// dmarc judges the strength of the zone's DMARC policy. Presence and p=none
// belong to dns.hygiene.
func (r *run) dmarc(ctx context.Context) (st dmarcState) {
	recs, ok := r.txts(ctx, "_dmarc."+r.zone, "dmarc")
	if !ok {
		return st
	}
	recs = matching(recs, "v=dmarc1")
	switch len(recs) {
	case 0:
		return st
	case 1:
	default:
		r.obs["dmarc_policy"] = "multiple"
		r.add(finding("dmarc-multiple", model.SeverityMedium,
			"Multiple DMARC records for "+r.zone,
			"RFC 7489 allows exactly one DMARC record at _dmarc."+r.zone+"; with several, receivers discard all of them and the domain has no DMARC policy at all.",
			"Merge the records into one TXT record at _dmarc."+r.zone+" and delete the others.",
			map[string]any{"zone": r.zone, "records": recs}, "dmarc"))
		return st
	}
	d, _ := hygiene.ParseDMARC(recs[0])
	st.one = true
	st.enforced = d.Policy == "quarantine" || d.Policy == "reject"
	r.obs["dmarc_policy"] = d.Policy
	ev := map[string]any{"zone": r.zone, "record": recs[0], "policy": d.Policy, "pct": d.Pct}
	if st.enforced && d.Pct < 100 {
		r.add(finding("dmarc-pct", model.SeverityLow,
			"DMARC for "+r.zone+" applies its policy to only some mail",
			"The record has pct="+itoa(d.Pct)+", so p="+d.Policy+" is applied to that share of failing mail and the rest is delivered as if the policy were none. Attackers spoofing the domain get through the remaining share.",
			"Raise pct in steps to 100 (or remove it) once the aggregate reports show only legitimate mail passing.",
			ev, "dmarc"))
	}
	if st.enforced && d.SubdomainPolicy == "none" {
		r.add(finding("dmarc-sp-none", model.SeverityLow,
			"DMARC for "+r.zone+" exempts subdomains (sp=none)",
			"p="+d.Policy+" covers the domain itself, but sp=none leaves every subdomain unprotected, so spoofed mail from names like billing."+r.zone+" is delivered.",
			"Remove sp= (subdomains then follow p) or set sp=quarantine or sp=reject once subdomain senders are covered.",
			map[string]any{"zone": r.zone, "record": recs[0], "policy": d.Policy, "subdomain_policy": d.SubdomainPolicy}, "dmarc"))
	}
	if d.RUA == "" {
		r.add(finding("dmarc-no-rua", model.SeverityInfo,
			"DMARC for "+r.zone+" has no aggregate report address",
			"Without rua= no receiver sends aggregate reports, so you cannot see who sends mail as this domain, which senders fail authentication, or when spoofing happens.",
			`Add rua=mailto:dmarc-reports@`+r.zone+` (a mailbox or a DMARC reporting service you read) to the record.`,
			ev, "dmarc"))
	}
	return st
}

// spf reports "~all" on a mail zone. The other SPF findings belong to
// dns.hygiene.
func (r *run) spf(ctx context.Context, dm dmarcState) {
	recs, ok := r.txts(ctx, r.zone, "spf")
	if !ok {
		return
	}
	var spf []string
	for _, s := range recs {
		if hygiene.IsSPFRecord(s) {
			spf = append(spf, s)
		}
	}
	if len(spf) != 1 {
		return // missing and multiple records are dns.hygiene's
	}
	p, _ := hygiene.ParseSPF(spf[0])
	r.obs["spf_all"] = p.All
	if p.All != "~" {
		return
	}
	sev := model.SeverityLow
	note := " DMARC does not enforce a policy here, so a softfail is delivered like a pass."
	if dm.enforced {
		sev = model.SeverityInfo
		note = " DMARC enforces a policy for this domain, which covers most of the gap."
	}
	r.add(finding("spf-softfail", sev,
		"SPF for "+r.zone+" ends in ~all (softfail)",
		"The record marks mail from unlisted servers as a softfail, which receivers treat as suspicious but usually still accept."+note,
		`Change "~all" to "-all" once every legitimate sender is listed, or keep "~all" deliberately and enforce DMARC (p=quarantine or reject).`,
		map[string]any{"zone": r.zone, "record": spf[0], "dmarc_enforced": dm.enforced}, "spf"))
}

// tlsRPT checks for the TLS reporting record. mode is the MTA-STS mode ("" when
// none is published).
func (r *run) tlsRPT(ctx context.Context, mode string) {
	recs, ok := r.txts(ctx, "_smtp._tls."+r.zone, "tls_rpt")
	if !ok {
		return
	}
	recs = matching(recs, "v=tlsrptv1")
	r.obs["tls_rpt"] = len(recs) > 0
	switch {
	case len(recs) == 0:
		if len(r.mxHosts) == 0 {
			return // sender-only zone: TLS reports concern inbound mail
		}
		sev := model.SeverityInfo
		note := ""
		if mode != "" && mode != "none" {
			sev = model.SeverityLow
			note = " MTA-STS is published, so delivery failures caused by it would go unnoticed."
		}
		r.add(finding("tls-rpt-missing", sev,
			"No TLS-RPT record for "+r.zone,
			"No TXT record exists at _smtp._tls."+r.zone+", so sending mail servers do not report TLS negotiation failures (expired certificates, downgrade attempts) for this domain's mail."+note,
			`Publish a TXT record at _smtp._tls.`+r.zone+`: "v=TLSRPTv1; rua=mailto:tls-reports@`+r.zone+`".`,
			map[string]any{"zone": r.zone, "mta_sts_mode": mode}, "tls-rpt"))
	case len(recs) > 1:
		r.add(finding("tls-rpt-invalid", model.SeverityLow,
			"Multiple TLS-RPT records for "+r.zone,
			"RFC 8460 expects one record at _smtp._tls."+r.zone+"; with several, senders ignore them and send no reports.",
			"Keep a single TXT record at _smtp._tls."+r.zone+".",
			map[string]any{"zone": r.zone, "records": recs}, "tls-rpt"))
	case !validRUA(recs[0]):
		r.add(finding("tls-rpt-invalid", model.SeverityLow,
			"TLS-RPT record for "+r.zone+" has no usable report address",
			"The record has no rua= with a mailto: or https: destination, so senders have nowhere to send reports.",
			`Set the record to "v=TLSRPTv1; rua=mailto:tls-reports@`+r.zone+`".`,
			map[string]any{"zone": r.zone, "record": recs[0]}, "tls-rpt"))
	}
}

func validRUA(rec string) bool {
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "rua") {
			continue
		}
		for _, dest := range strings.Split(v, ",") {
			d := strings.ToLower(strings.TrimSpace(dest))
			if (strings.HasPrefix(d, "mailto:") && len(d) > len("mailto:")) || (strings.HasPrefix(d, "https://") && len(d) > len("https://")) {
				return true
			}
		}
	}
	return false
}
