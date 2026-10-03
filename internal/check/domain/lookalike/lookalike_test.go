package lookalike

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	perm "github.com/chainseer-xyz/deckard/internal/lookalike"
	"github.com/chainseer-xyz/deckard/internal/model"
)

var fixedNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func zone(key string) model.Asset {
	return model.Asset{ID: 1, Kind: model.KindZone, Key: key, Scope: model.ScopeOwned}
}

// baseCfg keeps the candidate set small and known: the label "example" with
// three TLDs.
func baseCfg(extra map[string]any) map[string]any {
	cfg := map[string]any{"tlds": []any{"net", "org", "io"}}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

type outcome struct {
	res  *check.Result
	keys map[string]model.Severity
	obs  map[string]any
	by   map[string]model.FindingInput
}

func execute(t *testing.T, apex string, cfg map[string]any, opts ...checktest.Option) outcome {
	t.Helper()
	c := New(nil)
	c.now = func() time.Time { return fixedNow }
	return executeWith(t, c, context.Background(), apex, cfg, opts...)
}

func executeWith(t *testing.T, c *Check, ctx context.Context, apex string, cfg map[string]any, opts ...checktest.Option) outcome {
	t.Helper()
	opts = append([]checktest.Option{checktest.WithConfig(cfg)}, opts...)
	res, err := c.Run(ctx, checktest.NewTarget(zone(apex), opts...))
	if err != nil {
		t.Fatalf("Run returned an error (lookup problems must never be errors): %v", err)
	}
	o := outcome{res: res, keys: map[string]model.Severity{}, by: map[string]model.FindingInput{}}
	for _, f := range res.Findings {
		if f.Check != Name {
			t.Errorf("finding %s has check %q", f.Key, f.Check)
		}
		o.keys[f.Key] = f.Severity
		o.by[f.Key] = f
	}
	if len(res.Observations) != 1 || res.Observations[0].Check != Name {
		t.Fatalf("observations = %+v", res.Observations)
	}
	o.obs = res.Observations[0].Data
	return o
}

func (o outcome) state() string { s, _ := o.obs["lookalike"].(string); return s }

// estate is a scripted resolver with a few registered lookalikes of
// example.com, the unregistered rest answering NXDOMAIN.
func estate() *checktest.DNS {
	return checktest.NewDNS().Add(
		"exmple.com. 60 IN A 192.0.2.10",
		"exmple.com. 60 IN MX 10 mail.evil.example.",
		"exmple.com. 60 IN NS ns1.evil.example.",
		"exampel.com. 60 IN A 192.0.2.20",
		"exampel.com. 60 IN AAAA 2001:db8::20",
		"example.net. 60 IN NS ns1.parking.example.",
		"example.org. 60 IN A 192.0.2.30",
		"example.org. 60 IN MX 0 .", // null MX: accepts no mail
	).Exists("examp1e.com") // exists without data: not registered
}

func TestFindingsSeveritiesAndEvidence(t *testing.T) {
	dnsf := estate()
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(dnsf))

	want := map[string]model.Severity{
		"registered:exmple.com":  model.SeverityMedium, // MX: can receive mail
		"registered:exampel.com": model.SeverityLow,    // resolves only
		"registered:example.net": model.SeverityLow,    // delegates only (parked)
		"registered:example.org": model.SeverityLow,    // null MX is not a mail server
	}
	if len(o.keys) != len(want) {
		t.Errorf("findings = %v, want %v", o.keys, want)
	}
	for k, sev := range want {
		if o.keys[k] != sev {
			t.Errorf("%s = %q, want %q", k, o.keys[k], sev)
		}
	}
	if _, ok := o.keys["registered:examp1e.com"]; ok {
		t.Error("a name that exists without data is not a registration")
	}
	if o.res.Partial {
		t.Errorf("a fully answered run must not be partial: %v", o.obs)
	}

	f := o.by["registered:exmple.com"]
	if f.Title == "" || f.Description == "" || f.Remediation == "" || len(f.Tags) == 0 {
		t.Errorf("finding lacks text: %+v", f)
	}
	for _, s := range []string{"DMARC", "RDAP", "abuse"} {
		if !strings.Contains(f.Remediation, s) {
			t.Errorf("mail-capable remediation lacks %q: %s", s, f.Remediation)
		}
	}
	if !strings.Contains(f.Description, "never connected") || !strings.Contains(f.Description, "omission") {
		t.Errorf("description: %s", f.Description)
	}
	ev := f.Evidence
	if ev["domain"] != "exmple.com" || ev["zone"] != "example.com" || ev["technique"] != "omission" || ev["first_seen"] != "2026-10-03T12:00:00Z" {
		t.Errorf("evidence = %v", ev)
	}
	if !slices.Equal(ev["a"].([]string), []string{"192.0.2.10"}) || !slices.Equal(ev["mx"].([]string), []string{"10 mail.evil.example"}) ||
		!slices.Equal(ev["ns"].([]string), []string{"ns1.evil.example"}) {
		t.Errorf("answers in evidence = %v", ev)
	}
	if ev2 := o.by["registered:exampel.com"].Evidence; !slices.Equal(ev2["aaaa"].([]string), []string{"2001:db8::20"}) || ev2["technique"] != "transposition" {
		t.Errorf("exampel evidence = %v", ev2)
	}
	if _, has := o.by["registered:example.org"].Evidence["mx"]; has {
		t.Error("a null MX must not be reported as a mail server")
	}
	if o.by["registered:example.net"].Evidence["technique"] != "tld-swap" {
		t.Errorf("example.net technique = %v", o.by["registered:example.net"].Evidence["technique"])
	}
	if !strings.Contains(o.by["registered:example.net"].Description, "parked") {
		t.Errorf("an NS-only delegation should be described as parked: %s", o.by["registered:example.net"].Description)
	}
}

func TestQueryVolumeAndOrder(t *testing.T) {
	dnsf := estate()
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(dnsf))
	n := o.obs["candidates"].(int)
	// Every candidate costs one NS query. A name that exists (a registration,
	// or examp1e.com, which exists without data) costs three more: A, AAAA, MX.
	registered := len(o.keys)
	if want := n + 3*(registered+1); o.obs["queries"] != want || len(dnsf.Calls) != want {
		t.Errorf("queries = %v (resolver saw %d), want %d (%d candidates, %d registered, 1 empty non-terminal)", o.obs["queries"], len(dnsf.Calls), want, n, registered)
	}
	if o.obs["checked"] != n || o.obs["registered"] != registered || o.obs["unknown"] != 0 {
		t.Errorf("observation = %v", o.obs)
	}
	// The sweep is deterministic: a second run asks the same questions.
	dns2 := estate()
	execute(t, "example.com", baseCfg(nil), checktest.WithLookup(dns2))
	a, b := slices.Clone(dnsf.Calls), slices.Clone(dns2.Calls)
	slices.Sort(a)
	slices.Sort(b)
	if !slices.Equal(a, b) {
		t.Error("two runs asked different questions")
	}
}

func TestOwnedExcludedAndOriginalNamesAreNeverQueried(t *testing.T) {
	dnsf := estate()
	cfg := baseCfg(map[string]any{"exclude": []any{"exampel.com", "*.Partner.example.org."}})
	o := execute(t, "example.com", cfg, checktest.WithLookup(dnsf),
		checktest.WithOwnedZones("example.com", "example.io", "ample.com", "corp.example.com"))
	for _, c := range dnsf.Calls {
		name := c[strings.IndexByte(c, ' ')+1:]
		for _, bad := range []string{"example.com", "example.io", "ample.com", "exampel.com", "partner.example.org"} {
			if name == bad || strings.HasSuffix(name, "."+bad) {
				t.Errorf("queried %q, inside protected zone %q", name, bad)
			}
		}
	}
	if _, ok := o.keys["registered:exampel.com"]; ok {
		t.Error("an excluded name raised a finding")
	}
	if _, ok := o.keys["registered:exmple.com"]; !ok {
		t.Error("an unrelated lookalike was lost")
	}
	// Control: the same run without the protection does query them.
	ctl := estate()
	execute(t, "example.com", baseCfg(nil), checktest.WithLookup(ctl))
	seen := strings.Join(ctl.Calls, " ")
	for _, want := range []string{"NS example.io", "NS ex.ample.com", "NS exampel.com"} {
		if !strings.Contains(seen, want) {
			t.Errorf("control run never asked %q", want)
		}
	}
}

func TestOtherOwnedApexesAreNotLookalikes(t *testing.T) {
	// The estate owns example.net and example.org; both would otherwise be
	// tld-swap hits for example.com.
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(estate()),
		checktest.WithOwnedZones("example.com", "example.net", "example.org"))
	for _, k := range []string{"registered:example.net", "registered:example.org"} {
		if _, ok := o.keys[k]; ok {
			t.Errorf("%s: the estate's own apex was reported", k)
		}
	}
	if _, ok := o.keys["registered:exmple.com"]; !ok {
		t.Error("a real lookalike was lost")
	}
}

func TestExcludedZoneIsNotSweptAndWinsOverZones(t *testing.T) {
	dnsf := estate()
	o := execute(t, "brand-example.com", baseCfg(map[string]any{
		"zones":         []any{"brand-example.com"},
		"exclude_zones": []any{"BRAND-EXAMPLE.COM.", "bad name"},
	}), checktest.WithLookup(dnsf))
	if o.state() != StateExcluded || o.res.Partial || len(o.keys) != 0 {
		t.Fatalf("excluded zone result = state=%s partial=%v findings=%v", o.state(), o.res.Partial, o.keys)
	}
	if len(dnsf.Calls) != 0 {
		t.Fatalf("excluded zone was queried: %v", dnsf.Calls)
	}
	notes, _ := o.obs["config_notes"].([]string)
	if !slices.Contains(notes, "exclude_zones: ignored invalid names [\"bad name\"]") {
		t.Errorf("invalid exclude_zones entry was not noted: %v", o.obs)
	}
}

func TestServfailAndTimeoutsAreUnknownAndMarkTheRunPartial(t *testing.T) {
	dnsf := estate().Servfail("exampl.com").Timeout("exmaple.com")
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(dnsf))
	if !o.res.Partial {
		t.Fatal("SERVFAIL and timeouts must make the run partial")
	}
	if o.obs["unknown"] != 2 {
		t.Errorf("unknown = %v, want 2", o.obs["unknown"])
	}
	sample := fmt.Sprint(o.obs["unknown_sample"])
	if !strings.Contains(sample, "exampl.com") || !strings.Contains(sample, "SERVFAIL") || !strings.Contains(sample, "exmaple.com") {
		t.Errorf("unknown_sample = %s", sample)
	}
	// An unknown is never read as "does not exist" and never as a finding.
	for _, k := range []string{"registered:exampl.com", "registered:exmaple.com"} {
		if _, ok := o.keys[k]; ok {
			t.Errorf("%s: an unknown answer raised a finding", k)
		}
	}
	// Findings from the answers we did get are still raised.
	if o.keys["registered:exmple.com"] != model.SeverityMedium {
		t.Errorf("findings = %v", o.keys)
	}
	// Every candidate was still asked: partial because of unknowns, not budget.
	if o.obs["checked"] != o.obs["candidates"] {
		t.Errorf("checked = %v of %v", o.obs["checked"], o.obs["candidates"])
	}
	if _, has := o.obs["budget_exhausted"]; has {
		t.Error("budget_exhausted set without a budget problem")
	}
}

// faultLookup answers like the inner lookup except that chosen "TYPE name"
// queries fail with SERVFAIL.
type faultLookup struct {
	inner check.Lookup
	fail  map[string]bool
}

func (f faultLookup) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	if f.fail[dns.TypeToString[qtype]+" "+name] {
		m := new(dns.Msg)
		m.Rcode = dns.RcodeServerFailure
		return dnsx.ParseMsg(m, name, qtype, "fake", false), nil
	}
	return f.inner.Query(ctx, name, qtype)
}

func TestAFailedFollowUpQueryKeepsTheFindingButMarksItIncomplete(t *testing.T) {
	lk := faultLookup{inner: estate(), fail: map[string]bool{"MX exampel.com": true}}
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(lk))
	if !o.res.Partial {
		t.Error("a SERVFAIL on the MX query must make the run partial: the severity may be understated")
	}
	f, ok := o.by["registered:exampel.com"]
	if !ok {
		t.Fatal("the registration was dropped because one follow-up query failed")
	}
	if f.Evidence["incomplete"] != true {
		t.Errorf("evidence = %v, want incomplete", f.Evidence)
	}
}

func TestSERVFAILOnTheFirstQueryDoesNotSayNXDOMAIN(t *testing.T) {
	// A name whose NS query fails is unknown even though every other type
	// would have answered.
	lk := faultLookup{inner: estate(), fail: map[string]bool{"NS exampel.com": true}}
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(lk))
	if _, ok := o.keys["registered:exampel.com"]; ok {
		t.Error("finding raised without an answer")
	}
	if !o.res.Partial || o.obs["unknown"] != 1 {
		t.Errorf("partial=%v unknown=%v", o.res.Partial, o.obs["unknown"])
	}
}

func TestAliasedNameCountsAsRegistered(t *testing.T) {
	dnsf := checktest.NewDNS().Add("ex.ample.com. 60 IN CNAME parked.example.net.")
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(dnsf))
	f, ok := o.by["registered:ex.ample.com"]
	if !ok || f.Severity != model.SeverityLow {
		t.Fatalf("findings = %v", o.keys)
	}
	if f.Evidence["cname"] != "parked.example.net" || f.Evidence["technique"] != "dot" {
		t.Errorf("evidence = %v", f.Evidence)
	}
}

func TestInternationalisedCandidatesCarryTheirUnicodeForm(t *testing.T) {
	var idn string
	for _, c := range perm.Generate("example", "com", perm.Options{TLDs: []string{}}) {
		if c.Technique == perm.Unicode {
			idn = c.Domain
			break
		}
	}
	if idn == "" {
		t.Fatal("no unicode candidate")
	}
	dnsf := checktest.NewDNS().Add(idn + ". 60 IN A 192.0.2.99")
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(dnsf))
	f, ok := o.by["registered:"+idn]
	if !ok {
		t.Fatalf("%s not found in %v", idn, o.keys)
	}
	if f.Evidence["technique"] != "unicode" {
		t.Errorf("technique = %v", f.Evidence["technique"])
	}
	if u, _ := f.Evidence["unicode"].(string); u == "" || u == idn || strings.HasPrefix(u, "xn--") {
		t.Errorf("unicode form = %q for %s", u, idn)
	}
}

func TestStableKeysNewAndDisappearingRegistrations(t *testing.T) {
	first := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(estate()))
	again := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(estate()))
	if fmt.Sprint(first.keys) != fmt.Sprint(again.keys) {
		t.Error("keys are not stable across identical runs")
	}
	for k := range first.keys {
		if !strings.HasPrefix(k, "registered:") || strings.Count(k, ":") != 1 {
			t.Errorf("key %q is not registered:<domain>", k)
		}
	}
	// A new registration opens a new finding with a new key.
	grown := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(estate().Add("exammple.com. 60 IN A 192.0.2.50")))
	if _, ok := grown.keys["registered:exammple.com"]; !ok || len(grown.keys) != len(first.keys)+1 {
		t.Errorf("grown = %v", grown.keys)
	}
	// One that disappears is simply absent from a complete (non-partial) run,
	// which is what lets the processor resolve it.
	shrunk := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(checktest.NewDNS().Add("exampel.com. 60 IN A 192.0.2.20")))
	if _, ok := shrunk.keys["registered:exmple.com"]; ok || shrunk.res.Partial {
		t.Errorf("shrunk = %v partial=%v", shrunk.keys, shrunk.res.Partial)
	}
}

func TestFirstSeenSurvivesARefresh(t *testing.T) {
	prev := check.OpenFinding{Evidence: map[string]any{"domain": "exmple.com", "first_seen": "2026-01-02T03:04:05Z"}}
	other := check.OpenFinding{Evidence: map[string]any{"domain": "gone.example.com"}}
	c := New(nil)
	c.now = func() time.Time { return fixedNow }
	res, err := c.Run(context.Background(), func() check.Target {
		tg := checktest.NewTarget(zone("example.com"), checktest.WithConfig(baseCfg(nil)), checktest.WithLookup(estate()))
		tg.OpenFindings = []check.OpenFinding{prev, other}
		return tg
	}())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, f := range res.Findings {
		got[f.Key] = f.Evidence["first_seen"]
	}
	if got["registered:exmple.com"] != "2026-01-02T03:04:05Z" {
		t.Errorf("first_seen of a known lookalike = %v", got["registered:exmple.com"])
	}
	if got["registered:exampel.com"] != "2026-10-03T12:00:00Z" {
		t.Errorf("first_seen of a new lookalike = %v", got["registered:exampel.com"])
	}
}

func TestFindingsCapKeepsTheMostSevereAndSaysSo(t *testing.T) {
	dnsf := checktest.NewDNS().Add(
		"exampel.com. 60 IN A 192.0.2.1",
		"exmple.com. 60 IN A 192.0.2.2",
		"exmple.com. 60 IN MX 10 mail.evil.example.",
		"exampe.com. 60 IN A 192.0.2.3",
		"example.net. 60 IN NS ns1.parking.example.",
		"example.org. 60 IN A 192.0.2.4",
		"example.org. 60 IN MX 10 mx.evil.example.",
	)
	o := execute(t, "example.com", baseCfg(map[string]any{"max_findings_per_zone": 2}), checktest.WithLookup(dnsf))
	if len(o.res.Findings) != 2 {
		t.Fatalf("findings = %v", o.keys)
	}
	if o.keys["registered:exmple.com"] != model.SeverityMedium || o.keys["registered:example.org"] != model.SeverityMedium {
		t.Errorf("the cap dropped a more severe finding: %v", o.keys)
	}
	if o.obs["findings_truncated"] != 3 || o.obs["registered"] != 5 {
		t.Errorf("truncation is not reported: %v", o.obs)
	}
	if note, _ := o.obs["findings_truncated_note"].(string); !strings.Contains(note, "max_findings_per_zone") {
		t.Errorf("note = %q", note)
	}
	// Ordering is by severity, then key, so the cut is deterministic.
	if o.res.Findings[0].Key != "registered:example.org" || o.res.Findings[1].Key != "registered:exmple.com" {
		t.Errorf("order = %s, %s", o.res.Findings[0].Key, o.res.Findings[1].Key)
	}
	// No truncation, no note.
	o = execute(t, "example.com", baseCfg(nil), checktest.WithLookup(dnsf))
	if _, has := o.obs["findings_truncated"]; has {
		t.Error("truncation reported although nothing was cut")
	}
}

func TestCandidateCapIsReportedAndRespected(t *testing.T) {
	dnsf := estate()
	o := execute(t, "example.com", baseCfg(map[string]any{"max_candidates_per_zone": 12}), checktest.WithLookup(dnsf))
	if o.obs["candidates_selected"] != 12 || o.obs["checked"] != 12 {
		t.Errorf("observation = %v", o.obs)
	}
	if dropped := o.obs["candidates_dropped_by_cap"].(int); dropped != o.obs["candidates"].(int)-12 || dropped <= 0 {
		t.Errorf("dropped = %v of %v", dropped, o.obs["candidates"])
	}
	if len(dnsf.Calls) < 12 || len(dnsf.Calls) > 12+3*4 {
		t.Errorf("a 12-candidate sweep sent %d queries", len(dnsf.Calls))
	}
	if _, has := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(estate())).obs["candidates_dropped_by_cap"]; has {
		t.Error("cap reported although it did not bite")
	}
}

func TestNeverConnectsToALookalike(t *testing.T) {
	d := &checktest.Dialer{}
	r := &checktest.Resolver{}
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(estate()), checktest.WithDialer(d), checktest.WithResolver(r))
	if len(o.keys) == 0 {
		t.Fatal("expected findings")
	}
	if len(d.Dialed) != 0 {
		t.Errorf("the check dialled %v", d.Dialed)
	}
	if len(r.Calls) != 0 {
		t.Errorf("the check used the guarded resolver for third-party names: %v", r.Calls)
	}
}

// ---- skipped / unsupported / disabled paths ----------------------------------

func TestNilLookupIsSkippedAndPartial(t *testing.T) {
	o := execute(t, "example.com", baseCfg(nil)) // no Lookup, no Intel
	if o.state() != StateSkipped || !o.res.Partial || len(o.res.Findings) != 0 {
		t.Errorf("nil lookup: state=%s partial=%v findings=%d", o.state(), o.res.Partial, len(o.res.Findings))
	}
	if note, _ := o.obs["lookalike_note"].(string); note == "" {
		t.Error("the skip must say why")
	}
}

func TestNilAndDisabledIntelDoNotMatter(t *testing.T) {
	// The check is DNS-only: Target.Intel (nil, or any value) is not consulted.
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(estate()), checktest.WithIntel(nil))
	if o.state() != StateOK || len(o.keys) == 0 {
		t.Errorf("state=%s findings=%v", o.state(), o.keys)
	}
}

func TestDisabledAndNotSelectedAreNotPartial(t *testing.T) {
	// Switching the check off (or away from an apex) is a decision, not a
	// failure: findings resolve normally.
	for name, tc := range map[string]struct {
		cfg   map[string]any
		state string
	}{
		"disabled":     {baseCfg(map[string]any{"enabled": false}), StateDisabled},
		"not selected": {baseCfg(map[string]any{"zones": []any{"other.example", "Another.com."}}), StateNotSelected},
	} {
		dnsf := estate()
		o := execute(t, "example.com", tc.cfg, checktest.WithLookup(dnsf))
		if o.state() != tc.state || o.res.Partial || len(o.res.Findings) != 0 || len(dnsf.Calls) != 0 {
			t.Errorf("%s: state=%s partial=%v findings=%d queries=%d", name, o.state(), o.res.Partial, len(o.res.Findings), len(dnsf.Calls))
		}
	}
	o := execute(t, "example.com", baseCfg(map[string]any{"zones": []any{"EXAMPLE.com"}}), checktest.WithLookup(estate()))
	if o.state() != StateOK || len(o.keys) == 0 {
		t.Errorf("a listed apex must run: %s %v", o.state(), o.keys)
	}
}

func TestShortAndInternationalisedLabelsAreSkipped(t *testing.T) {
	for apex, state := range map[string]string{
		"abcd.com":          StateShortLabel,
		"ab.co.uk":          StateShortLabel,
		"xn--bcher-kva.com": StateUnsupported,
	} {
		dnsf := estate()
		o := execute(t, apex, baseCfg(nil), checktest.WithLookup(dnsf))
		if o.state() != state || o.res.Partial || len(dnsf.Calls) != 0 {
			t.Errorf("%s: state=%s partial=%v queries=%d", apex, o.state(), o.res.Partial, len(dnsf.Calls))
		}
	}
	// min_label_length lowers the bar.
	o := execute(t, "abcd.com", baseCfg(map[string]any{"min_label_length": 4}), checktest.WithLookup(checktest.NewDNS()))
	if o.state() != StateOK || o.obs["candidates"].(int) == 0 {
		t.Errorf("min_label_length 4: %v", o.obs)
	}
}

func TestMultiLabelSuffixApex(t *testing.T) {
	dnsf := checktest.NewDNS().Add("exmple.co.uk. 60 IN A 192.0.2.7", "example.net. 60 IN A 192.0.2.8")
	o := execute(t, "example.co.uk", baseCfg(nil), checktest.WithLookup(dnsf))
	if o.keys["registered:exmple.co.uk"] != model.SeverityLow || o.keys["registered:example.net"] != model.SeverityLow {
		t.Errorf("findings = %v", o.keys)
	}
	for _, f := range o.res.Findings {
		if !strings.HasSuffix(f.Key, ".co.uk") && !strings.HasSuffix(f.Key, ".net") && !strings.HasSuffix(f.Key, ".org") && !strings.HasSuffix(f.Key, ".io") {
			t.Errorf("unexpected suffix in %s", f.Key)
		}
	}
}

// ---- budget and rate ----------------------------------------------------------

// slowLookup answers every query NXDOMAIN after delay, or until ctx ends.
type slowLookup struct {
	delay time.Duration
	mu    sync.Mutex
	n     int
}

func (s *slowLookup) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	m := new(dns.Msg)
	m.Rcode = dns.RcodeNameError
	return dnsx.ParseMsg(m, name, qtype, "fake", false), nil
}

func TestRunOutOfTimeIsPartialAndSaysHowMuchWasUnchecked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	c := New(nil)
	o := executeWith(t, c, ctx, "example.com", baseCfg(nil), checktest.WithLookup(&slowLookup{delay: 60 * time.Millisecond}))
	if !o.res.Partial {
		t.Fatal("a sweep that ran out of time must be partial: absence proves nothing")
	}
	un, _ := o.obs["unchecked"].(int)
	if o.obs["budget_exhausted"] != true || un <= 0 || un >= o.obs["candidates_selected"].(int) {
		t.Errorf("observation = %v", o.obs)
	}
	if o.obs["checked"].(int)+un != o.obs["candidates_selected"].(int) {
		t.Errorf("checked + unchecked != selected: %v", o.obs)
	}
	if ctx.Err() != nil {
		t.Error("the check overran the engine's deadline: its result would be discarded")
	}
	if note, _ := o.obs["lookalike_note"].(string); !strings.Contains(note, "unchecked") {
		t.Errorf("note = %q", note)
	}
}

func TestRateCeilingBoundsTheSweepAndMakesItPartial(t *testing.T) {
	q := &slowLookup{}
	lim := dnsx.NewLimited(q, 40) // one query every 25ms
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	o := executeWith(t, New(nil), ctx, "example.com", baseCfg(nil), checktest.WithLookup(lim))
	// The budget is ~750ms: at 40/s the limiter can have let through at most
	// 750ms*40 + 1 = 31 queries, far fewer than the ~190 candidates.
	if sent := lim.Sent(); sent > 32 || sent < 5 {
		t.Errorf("limiter let %d queries through in the budget", sent)
	}
	if !o.res.Partial || o.obs["budget_exhausted"] != true {
		t.Errorf("an unfinished sweep must be partial: %v", o.obs)
	}
	if got := o.obs["queries"].(int); got > 32 {
		t.Errorf("queries = %d: waiting for a token must not count as a query sent", got)
	}
	if o.obs["checked"].(int) > 32 {
		t.Errorf("checked = %v", o.obs["checked"])
	}
}

// blockAfterNS answers the NS query with a delegation and blocks the next
// query until the context ends.
type blockAfterNS struct{}

func (blockAfterNS) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	if qtype != dns.TypeNS {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	m := new(dns.Msg)
	rr, _ := dns.NewRR(name + ". 60 IN NS ns1.parking.example.")
	m.Answer = []dns.RR{rr}
	return dnsx.ParseMsg(m, name, qtype, "fake", false), nil
}

func TestBudgetEndingMidProbeKeepsWhatIsKnownButIsNotChecked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	o := executeWith(t, New(nil), ctx, "example.com", baseCfg(map[string]any{"max_candidates_per_zone": 1}), checktest.WithLookup(blockAfterNS{}))
	if len(o.res.Findings) != 1 || o.res.Findings[0].Evidence["incomplete"] != true {
		t.Fatalf("findings = %+v", o.res.Findings)
	}
	if !o.res.Partial || o.obs["checked"] != 0 || o.obs["unchecked"] != 1 {
		t.Errorf("observation = %v partial=%v", o.obs, o.res.Partial)
	}
}

func TestNoServersIsUnknownNotAnError(t *testing.T) {
	// dnsx.ErrNoServers and similar transport errors are lookup failures.
	o := execute(t, "example.com", baseCfg(nil), checktest.WithLookup(errLookup{dnsx.ErrNoServers}))
	if !o.res.Partial || len(o.res.Findings) != 0 || o.obs["unknown"] != o.obs["candidates"] {
		t.Errorf("partial=%v findings=%d obs=%v", o.res.Partial, len(o.res.Findings), o.obs)
	}
	if sample := fmt.Sprint(o.obs["unknown_sample"]); !strings.Contains(sample, "no recursive resolvers") {
		t.Errorf("sample = %s", sample)
	}
	if len(o.obs["unknown_sample"].([]string)) != unknownSample {
		t.Errorf("the sample must be capped at %d", unknownSample)
	}
}

type errLookup struct{ err error }

func (e errLookup) Query(context.Context, string, uint16) (*dnsx.Response, error) {
	return nil, fmt.Errorf("%w: boom", e.err)
}

// ---- config -------------------------------------------------------------------

func TestConfigValidationFallsBackAndNotes(t *testing.T) {
	cfg := map[string]any{
		"max_candidates_per_zone": 0,
		"max_findings_per_zone":   -3,
		"min_label_length":        500,
		"rate_per_second":         "fast",
		"zones":                   []any{"ok.com", "bad name"},
		"exclude":                 []any{"-x.com"},
		"tlds":                    []any{"net", "not_a_tld", ""},
	}
	o := parseOptions(cfg)
	if o.maxCandidates != DefaultMaxCandidates || o.maxFindings != DefaultMaxFindings || o.minLabel != perm.DefaultMinLabelLength || o.rate != DefaultRate {
		t.Errorf("defaults not applied: %+v", o)
	}
	if !slices.Equal(o.zones, []string{"ok.com"}) || len(o.exclude) != 0 || !slices.Equal(o.tlds, []string{"net"}) {
		t.Errorf("lists: zones=%v exclude=%v tlds=%v", o.zones, o.exclude, o.tlds)
	}
	joined := strings.Join(o.notes, "\n")
	for _, want := range []string{"max_candidates_per_zone", "max_findings_per_zone", "min_label_length", "rate_per_second", "zones: ignored", "exclude: ignored", "tlds: ignored"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes lack %q:\n%s", want, joined)
		}
	}
	// The notes reach the observation, and a run with a bad config still works.
	out := execute(t, "example.com", map[string]any{"max_candidates_per_zone": 99999, "rate_per_second": -1, "tlds": []any{"net"}}, checktest.WithLookup(estate()))
	notes, _ := out.obs["config_notes"].([]string)
	if len(notes) != 2 || out.state() != StateOK {
		t.Errorf("config_notes = %v state=%s", notes, out.state())
	}
}

func TestConfigDefaultsAndAcceptedValues(t *testing.T) {
	o := parseOptions(nil)
	if !o.enabled || o.maxCandidates != 600 || o.maxFindings != 50 || o.minLabel != 5 || o.rate != 20 || o.tlds != nil || len(o.notes) != 0 {
		t.Errorf("defaults = %+v", o)
	}
	o = parseOptions(map[string]any{"max_candidates_per_zone": int64(100), "max_findings_per_zone": 7.0, "min_label_length": uint64(3),
		"rate_per_second": 2.5, "tlds": []string{"net", "NET", ".org"}, "enabled": false})
	if o.enabled || o.maxCandidates != 100 || o.maxFindings != 7 || o.minLabel != 3 || o.rate != 2.5 || !slices.Equal(o.tlds, []string{"net", "org"}) || len(o.notes) != 0 {
		t.Errorf("parsed = %+v", o)
	}
	for in, want := range map[any]float64{20: 20, int64(5): 5, 0.5: 0.5, float32(2): 2, 0: DefaultRate, -1: DefaultRate, 5000: DefaultRate, "x": DefaultRate, nil: DefaultRate} {
		if got := RatePerSecond(map[string]any{"rate_per_second": in}); got != want {
			t.Errorf("RatePerSecond(%v) = %v, want %v", in, got, want)
		}
	}
	if RatePerSecond(nil) != DefaultRate {
		t.Error("RatePerSecond(nil)")
	}
}

func TestEmptyTLDListDisablesTLDSwap(t *testing.T) {
	dnsf := estate()
	o := execute(t, "example.com", map[string]any{"tlds": []any{}}, checktest.WithLookup(dnsf))
	for _, c := range dnsf.Calls {
		if strings.HasSuffix(strings.Fields(c)[1], ".net") || strings.HasSuffix(strings.Fields(c)[1], ".org") {
			t.Errorf("tld-swap still ran: %s", c)
		}
	}
	if _, ok := o.keys["registered:example.net"]; ok {
		t.Error("example.net reported")
	}
	// Absent key: the default list applies (about 25 suffixes).
	d2 := estate()
	execute(t, "example.com", nil, checktest.WithLookup(d2))
	if !strings.Contains(strings.Join(d2.Calls, " "), "NS example.xyz") {
		t.Error("the default TLD list was not used")
	}
}

// ---- identity -----------------------------------------------------------------

func TestIdentityAndApplies(t *testing.T) {
	c := New(nil)
	if c.Name() != "domain.lookalike" || c.Tier() != model.TierPassive || c.DefaultInterval() != 7*24*time.Hour || c.DefaultTimeout() != 30*time.Minute {
		t.Fatal("identity")
	}
	var _ check.DefaultIntervaler = c
	var _ check.DefaultTimeouter = c
	var _ check.WantsOwnedZones = c
	var _ check.WantsOpenFindings = c
	if !c.WantsOwnedZones() || !c.WantsOpenFindings() {
		t.Error("the check needs the owned zones and its open findings")
	}
	for _, tc := range []struct {
		a    model.Asset
		want bool
	}{
		{zone("example.com"), true},
		{zone("example.co.uk"), true},
		{zone("corp.example.com"), false}, // a subzone shares the apex's brand
		{zone("co.uk"), false},
		{zone("example.internal"), false},
		{model.Asset{Kind: model.KindHostname, Key: "example.com", Scope: model.ScopeOwned}, false},
		{model.Asset{Kind: model.KindZone, Key: "example.com", Scope: model.ScopeExternal}, false},
	} {
		if got := c.Applies(tc.a); got != tc.want {
			t.Errorf("Applies(%s %s %s) = %v", tc.a.Kind, tc.a.Key, tc.a.Scope, got)
		}
	}
	if got := Checks(map[string]map[string]any{Name: {"enabled": true}}); len(got) != 1 || got[0].Name() != Name {
		t.Errorf("Checks = %v", got)
	}
	if budgetFor(context.Background()) != DefaultTimeout {
		t.Error("without a deadline the budget is the default timeout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if b := budgetFor(ctx); b >= 30*time.Minute || b < 26*time.Minute {
		t.Errorf("budget for a 30m deadline = %v: it must leave the engine time to store the result", b)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel2()
	if b := budgetFor(ctx2); b >= 8*time.Second || b < 3*time.Second {
		t.Errorf("budget for an 8s deadline = %v", b)
	}
}

func TestRunWithContextCancelledIsNotAnErrorFromTheCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := executeWith(t, New(nil), ctx, "example.com", baseCfg(nil), checktest.WithLookup(&slowLookup{delay: time.Second}))
	if !o.res.Partial || o.obs["unchecked"] != o.obs["candidates_selected"] {
		t.Errorf("a cancelled run: %v", o.obs)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("setup")
	}
}
