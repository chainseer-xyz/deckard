package internetdb

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	fnd "github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

const testIP = "1.2.3.4"

// fakeIntel scripts Get. Unscripted URLs answer ErrNotFound, like a 404.
type fakeIntel struct {
	mu     sync.Mutex
	bodies map[string]string
	errs   map[string]error
	calls  []string
}

func newFakeIntel() *fakeIntel {
	return &fakeIntel{bodies: map[string]string{}, errs: map[string]error{}}
}

func (f *fakeIntel) RDAPBase(context.Context, string) (string, error) { return "", intel.ErrBlocked }

func (f *fakeIntel) Get(_ context.Context, service, u string) (intel.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, service+" "+u)
	f.mu.Unlock()
	if service != intel.ServiceInternetDB {
		return intel.Response{}, intel.ErrBlocked
	}
	if err := f.errs[u]; err != nil {
		return intel.Response{}, err
	}
	b, ok := f.bodies[u]
	if !ok {
		return intel.Response{Status: 404}, intel.ErrNotFound
	}
	return intel.Response{Status: 200, Body: []byte(b)}, nil
}

func url(ip string) string { return "https://internetdb.shodan.io/" + ip }

func ipAsset(ip string) model.Asset {
	return model.Asset{Kind: model.KindIP, Key: ip, Scope: model.ScopeOwned}
}

// run executes the check against ip with the scripted intel client and a
// net.ports baseline holding own (nil own = no baseline).
func run(t *testing.T, f check.Intel, own any, cfg map[string]any) *check.Result {
	t.Helper()
	tg := checktest.NewTarget(ipAsset(testIP), checktest.WithConfig(cfg))
	if f != nil {
		tg.Intel = f
	}
	tg.Baseline = map[string]map[string]any{}
	if own != nil {
		tg.Baseline[portsCheck] = map[string]any{"ports": own}
	}
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func answerJSON(ports string, vulns, tags string) string {
	return fmt.Sprintf(`{"ip":%q,"ports":%s,"cpes":["cpe:/a:apache:http_server:2.4.49","cpe:/a:openbsd:openssh:8.2"],`+
		`"hostnames":["www.example.com"],"tags":%s,"vulns":%s}`, testIP, ports, tags, vulns)
}

func byKey(res *check.Result) map[string]model.FindingInput {
	m := map[string]model.FindingInput{}
	for _, f := range res.Findings {
		m[f.Key] = f
	}
	return m
}

func keys(res *check.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Key)
	}
	slices.Sort(out)
	return out
}

func obsOf(t *testing.T, res *check.Result) map[string]any {
	t.Helper()
	if len(res.Observations) != 1 || res.Observations[0].Check != Name {
		t.Fatalf("observations = %+v", res.Observations)
	}
	return res.Observations[0].Data
}

func TestApplies(t *testing.T) {
	c := New(nil)
	for _, tc := range []struct {
		a    model.Asset
		want bool
	}{
		{ipAsset("1.2.3.4"), true},
		{ipAsset("93.184.216.34"), true},
		{ipAsset("2606:4700:4700::1111"), true},
		{ipAsset("::ffff:1.2.3.4"), true}, // v4-mapped: the v4 address
		{ipAsset("10.1.2.3"), false},      // private
		{ipAsset("172.20.0.1"), false},
		{ipAsset("192.168.1.1"), false},
		{ipAsset("127.0.0.1"), false}, // loopback
		{ipAsset("::1"), false},
		{ipAsset("169.254.10.10"), false}, // link-local
		{ipAsset("fe80::1"), false},
		{ipAsset("100.64.1.1"), false},   // CGNAT
		{ipAsset("192.0.2.10"), false},   // documentation
		{ipAsset("198.51.100.7"), false}, // documentation
		{ipAsset("203.0.113.9"), false},
		{ipAsset("2001:db8::1"), false},
		{ipAsset("224.0.0.1"), false}, // multicast
		{ipAsset("0.0.0.0"), false},
		{ipAsset("fe80::1%eth0"), false}, // zoned
		{ipAsset("not-an-ip"), false},
		{ipAsset(""), false},
		{model.Asset{Kind: model.KindIP, Key: "1.2.3.4", Scope: model.ScopeExternal}, false},
		{model.Asset{Kind: model.KindIP, Key: "1.2.3.4", Scope: model.ScopeShared}, false},
		{model.Asset{Kind: model.KindHostname, Key: "1.2.3.4", Scope: model.ScopeOwned}, false},
		{model.Asset{Kind: model.KindService, Key: "1.2.3.4:443/tcp", Scope: model.ScopeOwned}, false},
	} {
		if got := c.Applies(tc.a); got != tc.want {
			t.Errorf("Applies(%s %q %s) = %v, want %v", tc.a.Kind, tc.a.Key, tc.a.Scope, got, tc.want)
		}
	}
	if c.Name() != "intel.internetdb" || c.Tier() != model.TierPassive || c.DefaultInterval() != DefaultInterval {
		t.Errorf("identity = %s %s %s", c.Name(), c.Tier(), c.DefaultInterval())
	}
	if !reflect.DeepEqual(c.BaselineChecks(), []string{"net.ports"}) {
		t.Errorf("BaselineChecks = %v", c.BaselineChecks())
	}
	var _ check.WantsBaselines = c
	var _ check.DefaultIntervaler = c
}

// Every finding path in one answer: CVEs, an unexpected port, bad tags and
// evidence-only tags.
func TestFindings(t *testing.T) {
	f := newFakeIntel()
	f.bodies[url(testIP)] = answerJSON(`[22,80,443,8443]`, `["CVE-2021-41773","CVE-2021-42013"]`,
		`["compromised","cdn","honeypot","botnet","C2","malware"]`)
	res := run(t, f, []any{22.0, 80.0, 443.0}, nil)

	if want := []string{
		"cve:CVE-2021-41773", "cve:CVE-2021-42013", "tag:botnet", "tag:c2", "tag:compromised", "tag:malware", "unexpected-port:8443",
	}; !reflect.DeepEqual(keys(res), want) {
		t.Fatalf("keys = %v, want %v", keys(res), want)
	}
	if res.Partial {
		t.Error("a complete answer must not be partial")
	}
	if len(f.calls) != 1 || f.calls[0] != "internetdb "+url(testIP) {
		t.Fatalf("calls = %v, want exactly one internetdb request", f.calls)
	}

	m := byKey(res)
	cve := m["cve:CVE-2021-41773"]
	if cve.Check != Name || cve.Severity != model.SeverityMedium {
		t.Errorf("cve = %s %s", cve.Check, cve.Severity)
	}
	if cve.Evidence["cve"] != "CVE-2021-41773" || cve.Evidence["ip"] != testIP || cve.Evidence["source"] != "shodan-internetdb" {
		t.Errorf("cve evidence = %v", cve.Evidence)
	}
	if !reflect.DeepEqual(cve.Evidence["ports"], []int{22, 80, 443, 8443}) ||
		!reflect.DeepEqual(cve.Evidence["cpes"], []string{"cpe:/a:apache:http_server:2.4.49", "cpe:/a:openbsd:openssh:8.2"}) {
		t.Errorf("cve evidence = %v", cve.Evidence)
	}
	for _, want := range []string{"false positive", "weekly"} {
		if !strings.Contains(cve.Description, want) {
			t.Errorf("cve description lacks %q: %s", want, cve.Description)
		}
	}
	for _, want := range []string{"patch", "restrict", "false positive", "acknowledge"} {
		if !strings.Contains(strings.ToLower(cve.Remediation), want) {
			t.Errorf("cve remediation lacks %q: %s", want, cve.Remediation)
		}
	}

	port := m["unexpected-port:8443"]
	if port.Severity != model.SeverityMedium || port.Evidence["port"] != 8443 ||
		!reflect.DeepEqual(port.Evidence["own_ports"], []int{22, 80, 443}) {
		t.Errorf("port finding = %s %v", port.Severity, port.Evidence)
	}
	for _, want := range []string{"close it", "checks.net.ports.ports", "expected_ports"} {
		if !strings.Contains(port.Remediation, want) {
			t.Errorf("port remediation lacks %q: %s", want, port.Remediation)
		}
	}

	for _, tag := range []string{"compromised", "malware", "c2", "botnet"} {
		fn := m["tag:"+tag]
		if fn.Severity != model.SeverityCritical || fn.Evidence["tag"] != tag {
			t.Errorf("tag:%s = %s %v", tag, fn.Severity, fn.Evidence)
		}
		if !strings.Contains(fn.Title, "flagged") || fn.Remediation == "" {
			t.Errorf("tag:%s title/remediation: %q / %q", tag, fn.Title, fn.Remediation)
		}
	}
	if _, ok := m["tag:cdn"]; ok {
		t.Error("evidence-only tags must not raise findings")
	}
	if got := m["tag:compromised"].Evidence["tags"]; !reflect.DeepEqual(got, []string{"C2", "botnet", "cdn", "compromised", "honeypot", "malware"}) {
		t.Errorf("the other tags are evidence: %v", got)
	}
	for _, f := range res.Findings {
		if f.Description == "" || f.Remediation == "" || f.Title == "" || len(f.Tags) < 2 || f.Tags[0] != "intel" {
			t.Errorf("finding %s is incomplete: %+v", f.Key, f)
		}
	}

	o := obsOf(t, res)
	if o["internetdb"] != StateOK || o["ip"] != testIP {
		t.Errorf("observation = %v", o)
	}
}

// The observation carries no scanner lists: they would drift on every Shodan
// refresh and raise baseline findings that only repeat the real ones.
func TestObservationIsStable(t *testing.T) {
	var prev map[string]any
	for _, body := range []string{
		answerJSON(`[22]`, `[]`, `[]`),
		answerJSON(`[22,80,8080]`, `["CVE-2021-41773"]`, `["compromised"]`),
	} {
		f := newFakeIntel()
		f.bodies[url(testIP)] = body
		o := obsOf(t, run(t, f, []any{22.0, 80.0, 8080.0}, nil))
		if prev != nil && !reflect.DeepEqual(prev, o) {
			t.Errorf("observation changed with the scanner data: %v vs %v", prev, o)
		}
		prev = o
	}
}

func TestCleanResultWhenScannersKnowNothing(t *testing.T) {
	f := newFakeIntel() // unscripted: 404
	res := run(t, f, []any{22.0}, nil)
	if len(res.Findings) != 0 || res.Partial {
		t.Fatalf("404 is a clean result: findings=%v partial=%v", keys(res), res.Partial)
	}
	if o := obsOf(t, res); o["internetdb"] != StateNotFound {
		t.Errorf("observation = %v", o)
	}
	// Also clean without a net.ports observation: nothing to compare.
	if res := run(t, f, nil, nil); len(res.Findings) != 0 || res.Partial {
		t.Errorf("404 without net.ports: findings=%v partial=%v", keys(res), res.Partial)
	}
}

func TestPortsBaselineShapes(t *testing.T) {
	body := answerJSON(`[22,80,8443]`, `[]`, `[]`)
	for _, tc := range []struct {
		name string
		own  any
		want []string
	}{
		{"json numbers", []any{22.0, 80.0}, []string{"unexpected-port:8443"}},
		{"strings", []any{"22", "80/tcp"}, []string{"unexpected-port:8443"}},
		{"ints", []int{22, 80, 8443}, nil},
		{"all open ports known", []any{22.0, 80.0, 8443.0}, nil},
		{"empty list is an observation: nothing open", []any{}, []string{"unexpected-port:22", "unexpected-port:80", "unexpected-port:8443"}},
		{"garbage entries are ignored", []any{22.0, "x", true, 80.0, 70000.0}, []string{"unexpected-port:8443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIntel()
			f.bodies[url(testIP)] = body
			res := run(t, f, tc.own, nil)
			if got := keys(res); len(got)+len(tc.want) > 0 && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("keys = %v, want %v", got, tc.want)
			}
			if res.Partial {
				t.Error("an observed port list makes the run complete")
			}
		})
	}
}

func TestNoNetPortsObservation(t *testing.T) {
	f := newFakeIntel()
	f.bodies[url(testIP)] = answerJSON(`[22,8443]`, `["CVE-2021-41773"]`, `["malware"]`)
	res := run(t, f, nil, nil)
	if got := keys(res); !reflect.DeepEqual(got, []string{"cve:CVE-2021-41773", "tag:malware"}) {
		t.Fatalf("keys = %v: CVE and tag findings stay, port findings need net.ports", got)
	}
	if !res.Partial {
		t.Error("without a net.ports observation the run is partial")
	}
	o := obsOf(t, res)
	if o["ports_baseline"] != "missing" || o["ports_note"] == nil || o["internetdb"] != StateOK {
		t.Errorf("observation = %v", o)
	}

	// A baseline of another shape (no "ports" key) is no observation either.
	tg := checktest.NewTarget(ipAsset(testIP))
	tg.Intel = f
	tg.Baseline = map[string]map[string]any{portsCheck: {"_pending": map[string]any{}}, "other": {"ports": []any{22.0}}}
	r, err := New(nil).Run(context.Background(), tg)
	if err != nil || !r.Partial || slices.Contains(keys(r), "unexpected-port:22") {
		t.Errorf("err=%v partial=%v keys=%v", err, r != nil && r.Partial, keys(r))
	}
}

func TestExpectedPortsOption(t *testing.T) {
	f := newFakeIntel()
	f.bodies[url(testIP)] = answerJSON(`[22,2222,8443]`, `[]`, `[]`)
	res := run(t, f, []any{22.0}, map[string]any{"expected_ports": []any{2222, 8443}})
	if len(res.Findings) != 0 {
		t.Errorf("expected ports are accepted: %v", keys(res))
	}
	res = run(t, f, []any{22.0}, map[string]any{"expected_ports": []any{2222}})
	if got := keys(res); !reflect.DeepEqual(got, []string{"unexpected-port:8443"}) {
		t.Errorf("keys = %v", got)
	}
}

func TestMalformedCVEIdsAreIgnored(t *testing.T) {
	f := newFakeIntel()
	f.bodies[url(testIP)] = answerJSON(`[]`, `["cve-2020-1472"," CVE-2020-1472","CVE-2020-1472","CVE-2020","not a cve","CVE-2019-0708 CVE-2019-0709","","../../x"]`, `[]`)
	res := run(t, f, []any{}, nil)
	if got := keys(res); !reflect.DeepEqual(got, []string{"cve:CVE-2020-1472"}) {
		t.Errorf("keys = %v, want one normalised, deduplicated id", got)
	}
}

func TestMaxCVEs(t *testing.T) {
	var ids []string
	for i := 1; i <= 7; i++ {
		ids = append(ids, fmt.Sprintf(`"CVE-2020-%04d"`, i))
	}
	f := newFakeIntel()
	f.bodies[url(testIP)] = answerJSON(`[]`, "["+strings.Join(ids, ",")+"]", `[]`)
	res := run(t, f, []any{}, map[string]any{"max_cves": 3})
	if got := keys(res); !reflect.DeepEqual(got, []string{"cve:CVE-2020-0001", "cve:CVE-2020-0002", "cve:CVE-2020-0003"}) {
		t.Errorf("keys = %v", got)
	}
	if !res.Partial || obsOf(t, res)["cves_note"] == nil {
		t.Error("a cut list proves nothing about the rest: partial with a note")
	}
	if res := run(t, f, []any{}, map[string]any{"max_cves": 7}); res.Partial || len(res.Findings) != 7 {
		t.Errorf("exactly max_cves is complete: partial=%v n=%d", res.Partial, len(res.Findings))
	}
	for _, bad := range []any{0, -1, 5000} { // out of range falls back to the default
		if res := run(t, f, []any{}, map[string]any{"max_cves": bad}); res.Partial || len(res.Findings) != 7 {
			t.Errorf("max_cves=%v: partial=%v n=%d", bad, res.Partial, len(res.Findings))
		}
	}
}

// A lookup that fails, is limited, blocked or unsupported never resolves a
// finding and never raises one.
func TestUnavailablePaths(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		state string
	}{
		{"disabled", intel.ErrDisabled, StateSkipped},
		{"wrapped disabled", fmt.Errorf("x: %w", intel.ErrDisabled), StateSkipped},
		{"rate limited", intel.ErrRateLimited, StateUnavailable},
		{"blocked", intel.ErrBlocked, StateUnavailable},
		{"unsupported", intel.ErrUnsupported, StateUnavailable},
		{"upstream unavailable", intel.ErrUnavailable, StateUnavailable},
		{"too large", intel.ErrTooLarge, StateUnavailable},
		{"other", errors.New("connection reset"), StateUnavailable},
		{"context", context.DeadlineExceeded, StateUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIntel()
			f.errs[url(testIP)] = tc.err
			res := run(t, f, []any{22.0}, nil)
			if len(res.Findings) != 0 || !res.Partial {
				t.Fatalf("findings=%v partial=%v", keys(res), res.Partial)
			}
			o := obsOf(t, res)
			if o["internetdb"] != tc.state || o["internetdb_note"] == "" {
				t.Errorf("observation = %v, want state %s with a note", o, tc.state)
			}
		})
	}
}

func TestSkippedWithoutIntelClient(t *testing.T) {
	res := run(t, nil, []any{22.0}, nil)
	if len(res.Findings) != 0 || !res.Partial {
		t.Fatalf("findings=%v partial=%v", keys(res), res.Partial)
	}
	if o := obsOf(t, res); o["internetdb"] != StateSkipped {
		t.Errorf("observation = %v", o)
	}
}

func TestUnusableAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"not json":          `<html>`,
		"empty":             ``,
		"wrong shape":       `{"ports":"22"}`,
		"different address": `{"ip":"5.6.7.8","ports":[22],"vulns":["CVE-2021-41773"],"tags":["malware"]}`,
		"bad address":       `{"ip":"nope","ports":[22]}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeIntel()
			f.bodies[url(testIP)] = body
			res := run(t, f, []any{22.0}, nil)
			if len(res.Findings) != 0 || !res.Partial {
				t.Fatalf("findings=%v partial=%v", keys(res), res.Partial)
			}
			if o := obsOf(t, res); o["internetdb"] != StateUnavailable {
				t.Errorf("observation = %v", o)
			}
		})
	}
	// The answer may omit the ip field and may use null lists.
	f := newFakeIntel()
	f.bodies[url(testIP)] = `{"ports":null,"cpes":null,"hostnames":null,"tags":null,"vulns":null}`
	if res := run(t, f, []any{}, nil); len(res.Findings) != 0 || res.Partial {
		t.Errorf("null lists: findings=%v partial=%v", keys(res), res.Partial)
	}
}

// IPv6 answers are requested by their canonical form.
func TestIPv6AndMappedKeys(t *testing.T) {
	for key, want := range map[string]string{
		"2606:4700:4700:0:0:0:0:1111": "2606:4700:4700::1111",
		"::ffff:1.2.3.4":              "1.2.3.4",
		" 1.2.3.4 ":                   "1.2.3.4",
	} {
		f := newFakeIntel()
		f.bodies[url(want)] = fmt.Sprintf(`{"ip":%q,"ports":[22],"vulns":[],"tags":[]}`, want)
		tg := checktest.NewTarget(ipAsset(key))
		tg.Intel = f
		tg.Baseline = map[string]map[string]any{portsCheck: {"ports": []any{22.0}}}
		res, err := New(nil).Run(context.Background(), tg)
		if err != nil || res.Partial || len(res.Findings) != 0 || len(f.calls) != 1 || f.calls[0] != "internetdb "+url(want) {
			t.Errorf("key %q: err=%v partial=%v calls=%v", key, err, res != nil && res.Partial, f.calls)
		}
	}
}

// A non-public address reaching Run (Applies bypassed) makes no request.
func TestNonPublicAddressMakesNoRequest(t *testing.T) {
	f := newFakeIntel()
	tg := checktest.NewTarget(ipAsset("10.0.0.5"))
	tg.Intel = f
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil || !res.Partial || len(f.calls) != 0 || len(res.Findings) != 0 {
		t.Errorf("err=%v partial=%v calls=%v", err, res != nil && res.Partial, f.calls)
	}
}

type fakeFeeds struct {
	kev  map[string]vulnintel.KEVEntry
	epss map[string]float64
}

func (f fakeFeeds) KEV(c string) (vulnintel.KEVEntry, bool) { e, ok := f.kev[c]; return e, ok }
func (f fakeFeeds) EPSS(c string) (float64, float64, bool) {
	s, ok := f.epss[c]
	return s, 0.99, ok
}

// The findings carry the CVE id where the processor's exploit-intelligence
// enrichment looks for it, so KEV and EPSS raise them like any other CVE
// finding (the check has no feed of its own).
func TestEnrichmentFindsTheCVE(t *testing.T) {
	f := newFakeIntel()
	f.bodies[url(testIP)] = answerJSON(`[]`, `["CVE-2021-41773","CVE-2021-1111","CVE-2021-2222"]`, `[]`)
	res := run(t, f, []any{}, nil)
	feeds := fakeFeeds{
		kev:  map[string]vulnintel.KEVEntry{"CVE-2021-41773": {CVE: "CVE-2021-41773", DateAdded: "2021-11-03"}},
		epss: map[string]float64{"CVE-2021-1111": 0.95, "CVE-2021-2222": 0.01},
	}
	got := map[string]model.FindingInput{}
	for _, in := range res.Findings {
		e := fnd.ApplyIntel(in, feeds, fnd.DefaultIntelPolicy())
		got[e.Key] = e
	}
	if k := got["cve:CVE-2021-41773"]; k.Severity != model.SeverityCritical || !slices.Contains(k.Tags, "kev") {
		t.Errorf("KEV listing: %s %v", k.Severity, k.Tags)
	}
	if k := got["cve:CVE-2021-1111"]; k.Severity != model.SeverityHigh {
		t.Errorf("high EPSS: %s", k.Severity)
	}
	if k := got["cve:CVE-2021-2222"]; k.Severity != model.SeverityMedium {
		t.Errorf("low EPSS stays medium: %s", k.Severity)
	}
}

func TestChecksWiring(t *testing.T) {
	cs := Checks(map[string]map[string]any{Name: {"expected_ports": []any{22}}})
	if len(cs) != 1 || cs[0].Name() != Name {
		t.Fatalf("Checks = %v", cs)
	}
	f := newFakeIntel()
	f.bodies[url(testIP)] = answerJSON(`[22]`, `[]`, `[]`)
	tg := checktest.NewTarget(ipAsset(testIP))
	tg.Intel = f
	tg.Baseline = map[string]map[string]any{portsCheck: {"ports": []any{}}}
	res, err := cs[0].Run(context.Background(), tg)
	if err != nil || len(res.Findings) != 0 {
		t.Errorf("global config not applied: err=%v findings=%v", err, res.Findings)
	}
}
