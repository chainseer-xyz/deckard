// Package internetdb implements intel.internetdb: what the internet's scanners
// know about the operator's own public IP addresses, read from Shodan's
// key-free InternetDB through Target.Intel. It never contacts the IP itself.
//
// Applies to owned ip assets that are public addresses (private, loopback,
// link-local, CGNAT, documentation and other reserved ranges are skipped). One
// request per IP: https://internetdb.shodan.io/<ip>. The data is a snapshot
// Shodan refreshes about weekly, so it lags behind changes and a port or CVE
// that was fixed days ago can still be listed.
//
// Findings (stable keys):
//
//	cve:<id>              medium    InternetDB lists the CVE for this IP. Severity
//	                                is raised by the shared exploit-intelligence
//	                                enrichment (CISA KEV => critical and tag kev,
//	                                EPSS => high/medium), the same one cve.nuclei
//	                                findings go through; the check carries the id
//	                                in its evidence and has no feed of its own.
//	                                InternetDB infers CVEs from banners and CPEs,
//	                                so a match can be a false positive.
//	unexpected-port:<n>   medium    scanners saw port n open, but the latest
//	                                net.ports observation of this IP does not list
//	                                it. Needs a net.ports observation: without one
//	                                there is no port finding and the run is partial.
//	tag:<tag>             critical  InternetDB tags the IP compromised, malware,
//	                                c2 or botnet.
//
// Other tags (honeypot, cdn, self-signed, ...), hostnames and CPEs are evidence
// only. A 404 means the scanners know nothing about the IP: a clean result.
// A lookup that fails, is rate limited, blocked or unsupported, an unusable
// answer, a disabled or missing intel client, and a missing net.ports
// observation are never findings: the run records an observation and is
// partial, so nothing resolves on missing data.
//
// The observation holds only the lookup state, never the scanners' lists:
// those change with every Shodan refresh and would raise baseline drift
// findings that only repeat the real findings.
//
// Options (checks.intel.internetdb):
//
//	expected_ports  list of ports  ports that may be open although net.ports does
//	                               not list them (outside its scan range, or only
//	                               reachable from some networks)
//	max_cves        int            findings per IP are capped at this many CVEs
//	                               (default 200, 1..2000); a larger list is cut
//	                               after sorting and the run is partial
package internetdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

// Name is the check's registry name.
const Name = "intel.internetdb"

// DefaultInterval is the check's cadence: the data is a snapshot refreshed
// about weekly, so asking more often only repeats the cached answer.
const DefaultInterval = 24 * time.Hour

// DefaultMaxCVEs bounds the CVE findings of one IP.
const DefaultMaxCVEs = 200

const maxCVEsLimit = 2000

// portsCheck is the check whose observation defines the ports deckard itself
// sees open.
const portsCheck = "net.ports"

// Lookup states recorded in the observation.
const (
	StateOK          = "ok"
	StateNotFound    = "not_found"
	StateUnavailable = "unavailable"
	StateSkipped     = "skipped"
)

// badTags are the InternetDB tags that mean the IP is itself part of an attack.
var badTags = []string{"compromised", "malware", "c2", "botnet"}

// Check is the intel.internetdb check.
type Check struct{ base map[string]any }

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string                   { return Name }
func (*Check) Tier() model.Tier               { return model.TierPassive }
func (*Check) DefaultInterval() time.Duration { return DefaultInterval }

// BaselineChecks asks the engine for net.ports' learned observation.
func (*Check) BaselineChecks() []string { return []string{portsCheck} }

// Applies matches owned IPs that are public addresses.
func (*Check) Applies(a model.Asset) bool {
	if a.Kind != model.KindIP || a.Scope != model.ScopeOwned {
		return false
	}
	_, ok := publicAddr(a.Key)
	return ok
}

func publicAddr(key string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(key))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	return a, intel.IsPublicAddr(a)
}

// answer is the InternetDB response.
type answer struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

// Run asks InternetDB about the IP.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	addr, ok := publicAddr(t.Asset.Key)
	obs := map[string]any{"ip": strings.TrimSpace(t.Asset.Key)}
	res := &check.Result{}
	skip := func(state, note string) (*check.Result, error) {
		obs["internetdb"] = state
		obs["internetdb_note"] = note
		res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
		res.Partial = true // no answer proves nothing: nothing resolves, no baseline moves
		return res, nil
	}
	if !ok {
		return skip(StateSkipped, "not a public IP address")
	}
	if t.Intel == nil {
		return skip(StateSkipped, "metadata client not available")
	}
	ip := addr.String()
	resp, err := t.Intel.Get(ctx, intel.ServiceInternetDB, "https://internetdb.shodan.io/"+ip)
	switch {
	case errors.Is(err, intel.ErrNotFound):
		// The scanners know nothing about this IP: a clean result.
		obs["internetdb"] = StateNotFound
		res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
		return res, nil
	case err != nil:
		return skip(classify(err))
	}
	var a answer
	if err := json.Unmarshal(resp.Body, &a); err != nil {
		return skip(StateUnavailable, "unusable internetdb response: "+err.Error())
	}
	if a.IP != "" {
		if got, err := netip.ParseAddr(a.IP); err != nil || got.Unmap() != addr {
			return skip(StateUnavailable, "internetdb answered for a different address")
		}
	}
	obs["internetdb"] = StateOK

	ev := newEvidence(ip, &a)
	cves, truncated := cveIDs(a.Vulns, checkutil.Int(cfg, "max_cves", DefaultMaxCVEs))
	for _, id := range cves {
		res.Findings = append(res.Findings, cveFinding(ip, id, ev))
	}
	if truncated {
		res.Partial = true
		obs["cves_note"] = "more CVEs listed than max_cves; the rest are not reported"
	}
	res.Findings = append(res.Findings, tagFindings(ip, a.Tags, ev)...)

	own, have := ownPorts(t.Baseline[portsCheck])
	switch {
	case !have:
		res.Partial = true
		obs["ports_baseline"] = "missing"
		obs["ports_note"] = "no net.ports observation of this IP yet; open-port comparison skipped"
	default:
		res.Findings = append(res.Findings, portFindings(ip, a.Ports, own, expectedPorts(cfg), ev)...)
	}
	res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
	return res, nil
}

// classify maps an intel error onto an observation state and note. None of
// them is a finding.
func classify(err error) (string, string) {
	switch {
	case errors.Is(err, intel.ErrDisabled):
		return StateSkipped, "intel disabled (intel.enabled or intel.services.internetdb.enabled is false)"
	case errors.Is(err, intel.ErrRateLimited):
		return StateUnavailable, "rate limited: " + err.Error()
	}
	return StateUnavailable, err.Error()
}

func newEvidence(ip string, a *answer) map[string]any {
	return map[string]any{
		"ip":        ip,
		"source":    "shodan-internetdb",
		"ports":     portList(a.Ports),
		"cpes":      sortedStrings(a.CPEs),
		"hostnames": sortedStrings(a.Hostnames),
		"tags":      sortedStrings(a.Tags),
	}
}

func clone(ev map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(ev)+len(extra))
	for k, v := range ev {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func finding(key string, sev model.Severity, title, desc, remediation string, ev map[string]any, tags ...string) model.FindingInput {
	return model.FindingInput{Check: Name, Key: key, Severity: sev, Title: title, Description: desc,
		Remediation: remediation, Evidence: ev, Tags: append([]string{"intel", "internetdb"}, tags...)}
}

const snapshotNote = " The data is a snapshot that Shodan refreshes about weekly, so it can lag behind recent changes."

// cveIDs returns the distinct, well-formed CVE ids, sorted, cut to max. It
// reports whether anything was cut.
func cveIDs(vulns []string, limit int) ([]string, bool) {
	if limit < 1 || limit > maxCVEsLimit {
		limit = DefaultMaxCVEs
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range vulns {
		id := strings.ToUpper(strings.TrimSpace(v))
		if ids := vulnintel.ExtractCVEs(id); len(ids) == 1 && ids[0] == id && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	slices.Sort(out)
	if len(out) > limit {
		return out[:limit], true
	}
	return out, false
}

func cveFinding(ip, id string, ev map[string]any) model.FindingInput {
	return finding("cve:"+id, model.SeverityMedium,
		fmt.Sprintf("Internet scanners associate %s with %s", ip, id),
		fmt.Sprintf("Shodan InternetDB lists %s for %s, inferred from the service banners and software versions its scanners saw. "+
			"Such matches can be false positives (a fix backported without a version change, a hidden or misreported version, "+
			"a different host behind the same address).", id, ip)+snapshotNote,
		fmt.Sprintf("Find the service behind the listed ports and CPEs and confirm its running version. If %s applies, patch or upgrade it, "+
			"or restrict the port to the networks that need it. If the match is wrong (for example the vendor backported the fix), "+
			"mark this finding false positive; acknowledge it while a fix is scheduled.", id),
		clone(ev, map[string]any{"cve": id}), "cve")
}

func tagFindings(ip string, tags []string, ev map[string]any) []model.FindingInput {
	var out []model.FindingInput
	seen := map[string]bool{}
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if !slices.Contains(badTags, tag) || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, finding("tag:"+tag, model.SeverityCritical,
			fmt.Sprintf("%s is flagged %q by internet scanners", ip, tag),
			fmt.Sprintf("Shodan InternetDB tags %s as %s: internet scanners saw it behaving like part of an attack "+
				"(compromised host, malware or command-and-control infrastructure, botnet member).", ip, tag)+snapshotNote,
			"Treat the host behind this address as compromised until shown otherwise: isolate it, preserve evidence, look for the "+
				"listed ports and services you did not deploy, rebuild from a known-good image and rotate its credentials. "+
				"If the address was recently reassigned to you, the tag may describe its previous holder: confirm what has run on it, "+
				"then mark this finding false positive.",
			clone(ev, map[string]any{"tag": tag}), "compromised"))
	}
	return out
}

// ownPorts reads the open ports from net.ports' observation. have is false
// when there is none (the check never ran or has no usable data), which is
// different from an empty list: a host with nothing open has an observation.
func ownPorts(b map[string]any) (ports []int, have bool) {
	raw, ok := b["ports"]
	if !ok {
		return nil, false
	}
	switch v := raw.(type) {
	case []int:
		return portList(v), true
	case []any:
		var out []int
		for _, e := range v {
			if p, ok := toPort(e); ok {
				out = append(out, p)
			}
		}
		return portList(out), true
	case nil:
		return []int{}, true
	}
	return nil, false
}

func toPort(v any) (int, bool) {
	var n int
	switch x := v.(type) {
	case int:
		n = x
	case int64:
		n = int(x)
	case float64:
		n = int(x)
	case string:
		p, err := strconv.Atoi(strings.TrimSuffix(x, "/tcp"))
		if err != nil {
			return 0, false
		}
		n = p
	default:
		return 0, false
	}
	return n, n >= 1 && n <= 65535
}

// portList returns the valid ports, sorted and distinct, never nil.
func portList(in []int) []int {
	out := []int{}
	for _, p := range in {
		if p >= 1 && p <= 65535 {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func expectedPorts(cfg map[string]any) []int {
	return portList(checkutil.Ints(cfg, "expected_ports", nil))
}

func portFindings(ip string, seen, own, expected []int, ev map[string]any) []model.FindingInput {
	var out []model.FindingInput
	for _, p := range portList(seen) {
		if slices.Contains(own, p) || slices.Contains(expected, p) {
			continue
		}
		out = append(out, finding(fmt.Sprintf("unexpected-port:%d", p), model.SeverityMedium,
			fmt.Sprintf("Internet scanners saw port %d open on %s; deckard's own scan does not list it", p, ip),
			fmt.Sprintf("Shodan InternetDB lists %d/tcp as open on %s, but the latest net.ports observation of this address does not. "+
				"Either the port is open to the internet and outside what net.ports scans (it covers the top 1000 ports by default), "+
				"it is only reachable from some networks, or it has been closed since the scanners last looked.", p, ip)+snapshotNote,
			fmt.Sprintf("Find out what listens on port %d of %s. If it is unintended, close it or restrict it with a firewall or security group. "+
				"If it is intended, add %d to checks.net.ports.ports so deckard scans it, or to checks.intel.internetdb.expected_ports "+
				"to accept it here.", p, ip, p),
			clone(ev, map[string]any{"port": p, "own_ports": own}), "exposure"))
	}
	return out
}

func sortedStrings(in []string) []string {
	out := slices.Clone(in)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
