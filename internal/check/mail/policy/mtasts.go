package policy

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// maxPolicyBytes is the policy size limit of RFC 8461.
const maxPolicyBytes = 64 << 10

// maxAgeLimit is the largest max_age RFC 8461 allows (about a year).
const maxAgeLimit = 31557600

func itoa(n int) string { return strconv.Itoa(n) }

// sts is a parsed MTA-STS policy.
type sts struct {
	Version string
	Mode    string
	MaxAge  int
	MX      []string
	// Problems lists what makes the policy unusable.
	Problems []string
}

// parseSTS parses an MTA-STS policy body (RFC 8461 section 3.2).
func parseSTS(body string) sts {
	p := sts{MaxAge: -1}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			p.Problems = append(p.Problems, fmt.Sprintf("line %q is not key: value", short(line)))
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "version":
			p.Version = v
		case "mode":
			p.Mode = strings.ToLower(v)
		case "max_age":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > maxAgeLimit {
				p.Problems = append(p.Problems, fmt.Sprintf("max_age %q is not an integer between 0 and %d", short(v), maxAgeLimit))
			} else {
				p.MaxAge = n
			}
		case "mx":
			if v != "" {
				p.MX = append(p.MX, strings.ToLower(strings.TrimSuffix(v, ".")))
			}
		}
	}
	if p.Version != "STSv1" {
		p.Problems = append(p.Problems, "version is not STSv1")
	}
	switch p.Mode {
	case "none", "testing", "enforce":
	case "":
		p.Problems = append(p.Problems, "mode is missing")
	default:
		p.Problems = append(p.Problems, fmt.Sprintf("mode %q is not none, testing or enforce", short(p.Mode)))
	}
	if p.MaxAge < 0 && !hasProblem(p.Problems, "max_age") {
		p.Problems = append(p.Problems, "max_age is missing")
	}
	if len(p.MX) == 0 && p.Mode != "none" && p.Mode != "" {
		p.Problems = append(p.Problems, "no mx: pattern")
	}
	return p
}

func hasProblem(ps []string, prefix string) bool {
	for _, p := range ps {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func short(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// mxMatches reports whether host matches an MTA-STS mx pattern: an exact name,
// or "*.example.com" for names with exactly one more leading label.
func mxMatches(pattern, host string) bool {
	pattern, host = strings.ToLower(pattern), strings.ToLower(host)
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		label, tail, found := strings.Cut(host, ".")
		return found && label != "" && tail == rest
	}
	return pattern == host
}

// mtaSTS judges the zone's MTA-STS deployment and returns the policy mode
// ("" when no policy is published or it could not be read).
func (r *run) mtaSTS(ctx context.Context) string {
	recs, ok := r.txts(ctx, "_mta-sts."+r.zone, "mta_sts")
	if !ok {
		return ""
	}
	recs = matching(recs, "v=stsv1")
	if len(recs) == 0 {
		r.obs["mta_sts"] = "absent"
		if len(r.mxHosts) > 0 {
			r.add(finding("mta-sts-missing", model.SeverityLow,
				"No MTA-STS policy for "+r.zone,
				"The zone receives mail (it has MX records) but publishes no MTA-STS record at _mta-sts."+r.zone+", so a network attacker can strip STARTTLS from incoming server-to-server connections and read or alter mail in transit.",
				`Publish a TXT record at _mta-sts.`+r.zone+` ("v=STSv1; id=<timestamp>") and serve the policy at https://mta-sts.`+r.zone+`/.well-known/mta-sts.txt, starting with mode: testing and moving to enforce.`,
				map[string]any{"zone": r.zone, "mx": r.mxHosts}, "mta-sts"))
		}
		return ""
	}
	if len(recs) > 1 || !validSTSID(recs[0]) {
		why := "has no valid id= (1 to 32 letters and digits)"
		if len(recs) > 1 {
			why = "is published more than once"
		}
		r.obs["mta_sts"] = "invalid"
		r.add(finding("mta-sts-txt-invalid", model.SeverityMedium,
			"MTA-STS record for "+r.zone+" is invalid",
			"The _mta-sts."+r.zone+" TXT record "+why+", so sending servers do not use the policy.",
			`Keep exactly one TXT record at _mta-sts.`+r.zone+` of the form "v=STSv1; id=<timestamp>", and change the id whenever the policy file changes.`,
			map[string]any{"zone": r.zone, "records": recs}, "mta-sts"))
		return ""
	}
	return r.mtaSTSPolicy(ctx, recs[0])
}

func validSTSID(rec string) bool {
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "id") {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 32 {
			return false
		}
		for _, c := range v {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
		return true
	}
	return false
}

// mtaSTSPolicy fetches and judges the policy file named by the TXT record.
func (r *run) mtaSTSPolicy(ctx context.Context, txt string) string {
	u := "https://mta-sts." + r.zone + "/.well-known/mta-sts.txt"
	if r.t.HTTP == nil {
		r.note("mta_sts_error", "no HTTP client in target; policy not fetched")
		return ""
	}
	timeout := time.Duration(checkutil.Int(r.cfg, "timeout_seconds", DefaultTimeout)) * time.Second
	resp, err := checkutil.Fetch(ctx, r.t.HTTP, u, checkutil.FetchOpts{MaxBody: maxPolicyBytes, Timeout: timeout})
	if err != nil {
		r.note("mta_sts_error", "policy fetch failed: "+err.Error()) // refused, timed out, bad TLS: proves nothing here
		return ""
	}
	ev := map[string]any{"zone": r.zone, "txt": txt, "policy_url": u, "status": resp.Status}
	switch {
	case (resp.Status >= 300 && resp.Status < 400) || len(resp.Hops) > 1:
		r.obs["mta_sts"] = "redirect"
		r.add(finding("mta-sts-policy-redirect", model.SeverityMedium,
			"MTA-STS policy for "+r.zone+" is served through a redirect",
			"The policy URL redirects. RFC 8461 forbids following redirects when fetching a policy, so sending servers do not use it and MTA-STS protects nothing.",
			"Serve the policy file directly at "+u+" with a 200 response and no redirect.",
			ev, "mta-sts"))
		return ""
	case resp.Status == http.StatusRequestTimeout || resp.Status == http.StatusTooManyRequests || resp.Status >= 500:
		r.note("mta_sts_error", fmt.Sprintf("policy fetch answered %d", resp.Status))
		return ""
	case resp.Status >= 400:
		r.obs["mta_sts"] = "unavailable"
		r.add(finding("mta-sts-policy-unavailable", model.SeverityMedium,
			fmt.Sprintf("MTA-STS policy for %s answers %d", r.zone, resp.Status),
			fmt.Sprintf("The _mta-sts.%s record announces a policy, but %s answers HTTP %d. Senders cannot load the policy, so MTA-STS is not in effect, and servers that cached an earlier policy keep applying it until it expires.", r.zone, u, resp.Status),
			"Serve the policy at "+u+" over HTTPS with a certificate valid for mta-sts."+r.zone+" (a DNS record for the mta-sts name and a web server behind it), or remove the _mta-sts TXT record if you do not want MTA-STS.",
			ev, "mta-sts"))
		return ""
	case resp.Status != http.StatusOK || resp.Truncated:
		r.note("mta_sts_error", fmt.Sprintf("policy fetch answered %d (truncated: %v)", resp.Status, resp.Truncated))
		return ""
	}
	p := parseSTS(string(resp.Body))
	if len(p.Problems) > 0 {
		r.obs["mta_sts"] = "invalid"
		ev["problems"] = p.Problems
		r.add(finding("mta-sts-policy-invalid", model.SeverityMedium,
			"MTA-STS policy for "+r.zone+" is invalid",
			"The policy file cannot be used: "+strings.Join(p.Problems, "; ")+". Senders discard an invalid policy, so MTA-STS is not in effect.",
			"Fix the file at "+u+": it needs version: STSv1, mode: (none, testing or enforce), max_age: (seconds) and one mx: line per mail host (unless mode is none).",
			ev, "mta-sts"))
		return ""
	}
	r.obs["mta_sts"] = p.Mode
	ev["mode"], ev["max_age"], ev["mx_patterns"] = p.Mode, p.MaxAge, p.MX
	switch p.Mode {
	case "none":
		r.add(finding("mta-sts-mode-none", model.SeverityLow,
			"MTA-STS policy for "+r.zone+" is switched off (mode: none)",
			"mode: none tells senders to stop applying MTA-STS to this domain; incoming mail is again open to STARTTLS stripping.",
			"If this is not a deliberate wind-down, set mode: testing and then mode: enforce, and change the id in the _mta-sts TXT record.",
			ev, "mta-sts"))
		return p.Mode
	case "testing":
		r.add(finding("mta-sts-mode-testing", model.SeverityLow,
			"MTA-STS policy for "+r.zone+" only tests (mode: testing)",
			"In testing mode senders report problems (through TLS-RPT) but still deliver mail over unauthenticated or unencrypted connections, so an active attacker is not stopped.",
			"Review the TLS-RPT reports, make sure every mx: pattern and certificate is right, then set mode: enforce and change the id in the _mta-sts TXT record.",
			ev, "mta-sts"))
	}
	if floor := checkutil.Int(r.cfg, "min_max_age", DefaultMinMaxAge); p.MaxAge < floor {
		r.add(finding("mta-sts-max-age-short", model.SeverityLow,
			fmt.Sprintf("MTA-STS max_age for %s is only %d seconds", r.zone, p.MaxAge),
			fmt.Sprintf("Senders cache the policy for max_age seconds. At %d seconds (below the %d-second minimum) an attacker only has to block the policy fetch once the cache expires to downgrade delivery.", p.MaxAge, floor),
			fmt.Sprintf("Raise max_age to at least %d (31557600, about a year, is the maximum) once mode: enforce is stable.", floor),
			ev, "mta-sts"))
	}
	r.mxMismatch(p, ev)
	return p.Mode
}

// mxMismatch reports real MX hosts that no mx: pattern covers.
func (r *run) mxMismatch(p sts, ev map[string]any) {
	var bad []string
	for _, h := range r.mxHosts {
		covered := false
		for _, pat := range p.MX {
			if mxMatches(pat, h) {
				covered = true
				break
			}
		}
		if !covered {
			bad = append(bad, h)
		}
	}
	if len(bad) == 0 {
		return
	}
	sev, effect := model.SeverityLow, "In testing mode this only produces failure reports."
	if p.Mode == "enforce" {
		sev, effect = model.SeverityMedium, "In enforce mode sending servers refuse to deliver to those hosts, so mail to this domain is deferred or bounced when they are chosen."
	}
	e := map[string]any{}
	for k, v := range ev {
		e[k] = v
	}
	e["mx_hosts"], e["unmatched"] = r.mxHosts, bad
	r.add(finding("mta-sts-mx-mismatch", sev,
		fmt.Sprintf("MTA-STS policy for %s does not cover %s", r.zone, strings.Join(bad, ", ")),
		"The zone's MX records point at "+strings.Join(bad, ", ")+", which no mx: line of the policy matches. "+effect,
		"Add an mx: line for each of those hosts (for example mx: "+bad[0]+", or a wildcard such as mx: *."+r.zone+") to the policy file, then change the id in the _mta-sts TXT record so senders reload it.",
		e, "mta-sts"))
}
