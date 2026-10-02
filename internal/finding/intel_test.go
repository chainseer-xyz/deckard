package finding_test

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

type fakeIntel struct {
	mu   sync.Mutex
	kev  map[string]vulnintel.KEVEntry
	epss map[string][2]float64
}

func newFakeIntel() *fakeIntel {
	return &fakeIntel{kev: map[string]vulnintel.KEVEntry{}, epss: map[string][2]float64{}}
}

func (f *fakeIntel) KEV(c string) (vulnintel.KEVEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.kev[c]
	return e, ok
}

func (f *fakeIntel) EPSS(c string) (float64, float64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.epss[c]
	return v[0], v[1], ok
}

func (f *fakeIntel) addKEV(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kev[c] = vulnintel.KEVEntry{CVE: c, DateAdded: "2021-12-10", RequiredAction: "Patch now.", Ransomware: true}
}

func cveInput(sev model.Severity) model.FindingInput {
	return model.FindingInput{
		Check: "nuclei", Key: "CVE-2021-44228", Severity: sev, Title: "Log4Shell", Description: "RCE in log4j.",
		Evidence: map[string]any{"matched": "https://x.example.com/"}, Tags: []string{"cve", "cve-2021-44228", "rce"},
	}
}

func TestCVEsOf(t *testing.T) {
	in := model.FindingInput{
		Key:      "cve-2020-0001",
		Tags:     []string{"CVE-2021-44228", "http", "cve-2021-44228"},
		Evidence: map[string]any{"cve": "CVE-2019-0708", "CVE-ID": "cve-2018-1000", "cves": []any{"CVE-2017-5638", 7}, "other": "CVE-2000-0001"},
	}
	got := finding.CVEsOf(in)
	want := []string{"CVE-2017-5638", "CVE-2018-1000", "CVE-2019-0708", "CVE-2020-0001", "CVE-2021-44228"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CVEsOf = %v, want %v", got, want)
	}
	if len(finding.CVEsOf(model.FindingInput{Key: "open-port-22", Tags: []string{"ssh"}})) != 0 {
		t.Fatal("non-CVE input matched")
	}
}

func TestApplyIntelKEV(t *testing.T) {
	fi := newFakeIntel()
	fi.addKEV("CVE-2021-44228")
	pol := finding.DefaultIntelPolicy()
	in := cveInput(model.SeverityMedium)
	out := finding.ApplyIntel(in, fi, pol)

	if out.Severity != model.SeverityCritical {
		t.Errorf("severity = %s", out.Severity)
	}
	if !contains(out.Tags, "kev") {
		t.Errorf("tags = %v", out.Tags)
	}
	ev := out.Evidence
	if ev["kev"] != true || ev["kev_date_added"] != "2021-12-10" || ev["kev_ransomware"] != true || ev["kev_required_action"] != "Patch now." {
		t.Errorf("evidence = %v", ev)
	}
	if ev["matched"] != "https://x.example.com/" {
		t.Error("original evidence lost")
	}
	if !strings.Contains(out.Description, "Known exploited (CISA KEV, added 2021-12-10)") || !strings.HasPrefix(out.Description, "RCE in log4j.") {
		t.Errorf("description = %q", out.Description)
	}
	// The input is untouched.
	if in.Severity != model.SeverityMedium || contains(in.Tags, "kev") || in.Evidence["kev"] != nil || len(in.Tags) != 3 {
		t.Errorf("input mutated: %+v", in)
	}
	// Deterministic, and idempotent on the description.
	again := finding.ApplyIntel(out, fi, pol)
	if again.Description != out.Description || !reflect.DeepEqual(again.Tags, out.Tags) {
		t.Errorf("not idempotent: %q", again.Description)
	}
	if !reflect.DeepEqual(finding.ApplyIntel(in, fi, pol), out) {
		t.Error("not deterministic")
	}
}

func TestApplyIntelCustomKEVFloor(t *testing.T) {
	fi := newFakeIntel()
	fi.addKEV("CVE-2021-44228")
	pol := finding.IntelPolicy{KEVFloor: model.SeverityHigh, EPSSHigh: 0.7, EPSSMedium: 0.3}
	if got := finding.ApplyIntel(cveInput(model.SeverityLow), fi, pol).Severity; got != model.SeverityHigh {
		t.Errorf("low -> %s", got)
	}
}

func TestApplyIntelEPSSRules(t *testing.T) {
	pol := finding.DefaultIntelPolicy()
	cases := []struct {
		name  string
		score float64
		in    model.Severity
		want  model.Severity
	}{
		{"high raises low", 0.7, model.SeverityLow, model.SeverityHigh},
		{"high raises info", 0.95, model.SeverityInfo, model.SeverityHigh},
		{"medium raises low", 0.3, model.SeverityLow, model.SeverityMedium},
		{"medium band keeps high", 0.5, model.SeverityHigh, model.SeverityHigh},
		{"below medium unchanged", 0.29, model.SeverityLow, model.SeverityLow},
		{"high never lowers critical", 0.99, model.SeverityCritical, model.SeverityCritical},
		{"medium never lowers high", 0.31, model.SeverityHigh, model.SeverityHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fi := newFakeIntel()
			fi.epss["CVE-2021-44228"] = [2]float64{tc.score, 0.9}
			out := finding.ApplyIntel(cveInput(tc.in), fi, pol)
			if out.Severity != tc.want {
				t.Errorf("severity = %s, want %s", out.Severity, tc.want)
			}
			if out.Evidence["epss"] != tc.score || out.Evidence["epss_percentile"] != 0.9 {
				t.Errorf("evidence = %v", out.Evidence)
			}
			if contains(out.Tags, "kev") || out.Evidence["kev"] != nil {
				t.Error("EPSS alone must not tag kev")
			}
			if !strings.Contains(out.Description, "EPSS") {
				t.Errorf("description = %q", out.Description)
			}
		})
	}
}

func TestApplyIntelNeverLowersAnySeverity(t *testing.T) {
	fi := newFakeIntel()
	fi.addKEV("CVE-2021-44228")
	fi.epss["CVE-2021-44228"] = [2]float64{0.5, 0.9}
	for _, sev := range []model.Severity{model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical} {
		if out := finding.ApplyIntel(cveInput(sev), fi, finding.DefaultIntelPolicy()); out.Severity.Rank() < sev.Rank() {
			t.Errorf("%s lowered to %s", sev, out.Severity)
		}
	}
	// A low KEV floor must not lower a critical finding.
	pol := finding.IntelPolicy{KEVFloor: model.SeverityLow, EPSSHigh: 0.7, EPSSMedium: 0.3}
	if out := finding.ApplyIntel(cveInput(model.SeverityCritical), fi, pol); out.Severity != model.SeverityCritical {
		t.Errorf("critical lowered to %s", out.Severity)
	}
}

func TestApplyIntelNoOps(t *testing.T) {
	in := cveInput(model.SeverityLow)
	if out := finding.ApplyIntel(in, nil, finding.DefaultIntelPolicy()); !reflect.DeepEqual(out, in) {
		t.Error("nil intel changed the finding")
	}
	if out := finding.ApplyIntel(in, newFakeIntel(), finding.DefaultIntelPolicy()); !reflect.DeepEqual(out, in) {
		t.Error("empty intel changed the finding")
	}
	fi := newFakeIntel()
	fi.addKEV("CVE-2021-44228")
	plain := model.FindingInput{Check: "net.ports", Key: "22", Severity: model.SeverityLow, Tags: []string{"ssh"}}
	if out := finding.ApplyIntel(plain, fi, finding.DefaultIntelPolicy()); !reflect.DeepEqual(out, plain) {
		t.Error("non-CVE finding changed")
	}
}

func TestApplyIntelMultipleCVEs(t *testing.T) {
	fi := newFakeIntel()
	fi.addKEV("CVE-2023-34362")
	fi.epss["CVE-2021-44228"] = [2]float64{0.4, 0.8}
	fi.epss["CVE-2023-34362"] = [2]float64{0.9, 0.99}
	in := model.FindingInput{Check: "x", Key: "k", Severity: model.SeverityLow, Tags: []string{"cve-2021-44228"}, Evidence: map[string]any{"cves": []string{"CVE-2023-34362"}}}
	out := finding.ApplyIntel(in, fi, finding.DefaultIntelPolicy())
	if out.Severity != model.SeverityCritical || out.Evidence["epss"] != 0.9 || !contains(out.Tags, "kev") {
		t.Fatalf("%+v", out)
	}
}

func TestFingerprintStableUnderEnrichment(t *testing.T) {
	fi := newFakeIntel()
	fi.addKEV("CVE-2021-44228")
	in := cveInput(model.SeverityLow)
	out := finding.ApplyIntel(in, fi, finding.DefaultIntelPolicy())
	if model.Fingerprint(in.Check, "a.example.com", in.Key) != model.Fingerprint(out.Check, "a.example.com", out.Key) {
		t.Fatal("fingerprint changed")
	}
}

func TestProcessorEnrichesAndUpgradesOpenFinding(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "www.example.com")
	clk := &clock{epoch}
	intel := newFakeIntel()
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 2, StableAfter: 2}, quiet,
		finding.WithClock(clk.now), finding.WithIntel(intel))
	in := cveInput(model.SeverityMedium)
	res := &check.Result{Findings: []model.FindingInput{in}}

	r1, err := p.Process(ctx, a, "nuclei", res)
	if err != nil || len(r1.Opened) != 1 {
		t.Fatalf("first run: %+v %v", r1, err)
	}
	fp := r1.Opened[0].Fingerprint
	if r1.Opened[0].Severity != model.SeverityMedium || contains(r1.Opened[0].Tags, "kev") {
		t.Fatalf("pre-KEV finding = %+v", r1.Opened[0])
	}
	if res.Findings[0].Severity != model.SeverityMedium {
		t.Fatal("processor mutated the caller's result")
	}

	// The CVE enters KEV; the next pass upgrades the still-open finding in place.
	intel.addKEV("CVE-2021-44228")
	clk.advance(5 * 60 * 1e9)
	r2, err := p.Process(ctx, a, "nuclei", res)
	if err != nil || len(r2.Updated) != 1 || len(r2.Opened) != 0 {
		t.Fatalf("second run: %+v %v", r2, err)
	}
	f := r2.Updated[0]
	if f.Fingerprint != fp {
		t.Fatalf("fingerprint changed: %s -> %s", fp, f.Fingerprint)
	}
	if f.Severity != model.SeverityCritical || !contains(f.Tags, "kev") || f.Evidence["kev"] != true || f.Status != model.StatusOpen {
		t.Fatalf("upgraded finding = %+v", f)
	}
	stored, err := st.GetFinding(ctx, f.ID)
	if err != nil || stored.Severity != model.SeverityCritical || !contains(stored.Tags, "kev") || stored.Evidence["kev_date_added"] != "2021-12-10" {
		t.Fatalf("stored = %+v %v", stored, err)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
