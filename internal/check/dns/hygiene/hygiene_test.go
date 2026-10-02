package hygiene

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func fixtureResolver(t *testing.T) *checktest.Resolver {
	t.Helper()
	raw, err := os.ReadFile("testdata/txt_records.json")
	if err != nil {
		t.Fatal(err)
	}
	r := &checktest.Resolver{TXTs: map[string][]string{}, Hosts: map[string][]string{}}
	if err := json.Unmarshal(raw, &r.TXTs); err != nil {
		t.Fatal(err)
	}
	return r
}

func keys(fs []model.FindingInput) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		m[f.Key] = f.Severity
	}
	return m
}

func runZone(t *testing.T, zone string, r *checktest.Resolver, cfg map[string]any) *checktestRes {
	t.Helper()
	c := New(nil)
	c.randLabel = func() string { return "probe" }
	tg := checktest.NewTarget(model.Asset{Kind: model.KindZone, Key: zone, Scope: model.ScopeOwned},
		checktest.WithResolver(r), checktest.WithConfig(cfg))
	res, err := c.Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	return &checktestRes{keys(res.Findings), res.Findings}
}

type checktestRes struct {
	keys map[string]model.Severity
	all  []model.FindingInput
}

func TestRunMatrix(t *testing.T) {
	r := fixtureResolver(t)
	cases := []struct {
		zone string
		cfg  map[string]any
		want map[string]model.Severity
	}{
		{"good.example.com", nil, map[string]model.Severity{}},
		{"open.example.com", nil, map[string]model.Severity{"spf-plus-all": model.SeverityHigh, "dmarc-p-none": model.SeverityLow}},
		{"neutral.example.com", nil, map[string]model.Severity{"spf-neutral-all": model.SeverityMedium, "dmarc-missing": model.SeverityMedium}},
		{"dupe.example.com", nil, map[string]model.Severity{"spf-multiple": model.SeverityMedium, "dmarc-missing": model.SeverityMedium}},
		{"deep.example.com", nil, map[string]model.Severity{"spf-too-many-lookups": model.SeverityMedium, "dmarc-missing": model.SeverityMedium}},
		{"bare.example.com", nil, map[string]model.Severity{"spf-missing": model.SeverityLow, "dmarc-missing": model.SeverityMedium}},
		{"bare.example.com", map[string]any{"expects_mail": true}, map[string]model.Severity{"spf-missing": model.SeverityMedium, "dmarc-missing": model.SeverityMedium}},
		{"nothing.example.com", nil, map[string]model.Severity{"spf-missing": model.SeverityLow, "dmarc-missing": model.SeverityMedium}},
	}
	for _, c := range cases {
		got := runZone(t, c.zone, r, c.cfg).keys
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v want %v", c.zone, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s = %q want %q (all %v)", c.zone, k, got[k], v, got)
			}
		}
	}
}

func TestWildcardDetection(t *testing.T) {
	r := fixtureResolver(t)
	r.Hosts["probe.good.example.com"] = []string{"192.0.2.7"}
	res := runZone(t, "good.example.com", r, nil)
	if _, ok := res.keys["wildcard-record"]; !ok {
		t.Errorf("expected wildcard finding: %v", res.keys)
	}
	if got := runZone(t, "good.example.com", r, map[string]any{"check_wildcard": false}).keys; len(got) != 0 {
		t.Errorf("wildcard probe should be disabled: %v", got)
	}
}

func TestCountLookupsCycleAndBudget(t *testing.T) {
	loop := map[string][]string{
		"a.example.net": {"v=spf1 include:b.example.net -all"},
		"b.example.net": {"v=spf1 include:a.example.net -all"},
	}
	lookup := func(_ context.Context, n string) ([]string, error) { return loop[n], nil }
	spf, _ := ParseSPF("v=spf1 include:a.example.net -all")
	if n := CountLookups(context.Background(), spf, lookup); n != 3 {
		t.Errorf("cycle count = %d, want 3", n)
	}
}

func TestParseSPF(t *testing.T) {
	cases := []struct {
		rec, all, redirect string
		mechs              int
	}{
		{"v=spf1 -all", "-", "", 1},
		{"v=SPF1 a mx ~all", "~", "", 3},
		{"v=spf1 all", "+", "", 1},
		{"v=spf1 redirect=_spf.example.net", "", "_spf.example.net", 0},
		{"v=spf1 ip4:192.0.2.0/24 exp=explain.example.com ?all", "?", "", 2},
	}
	for _, c := range cases {
		s, ok := ParseSPF(c.rec)
		if !ok || s.All != c.all || s.Redirect != c.redirect || len(s.Mechanisms) != c.mechs {
			t.Errorf("%q: %+v ok=%v", c.rec, s, ok)
		}
	}
	if _, ok := ParseSPF("v=spf10 -all"); ok {
		t.Error("v=spf10 is not SPF")
	}
}

func TestParseDMARC(t *testing.T) {
	d, ok := ParseDMARC("v=DMARC1; p=Quarantine; sp=none; pct=50; rua=mailto:x@example.com")
	if !ok || d.Policy != "quarantine" || d.SubdomainPolicy != "none" || d.Pct != 50 {
		t.Errorf("%+v", d)
	}
	if _, ok := ParseDMARC("v=spf1 -all"); ok {
		t.Error("not dmarc")
	}
}

func TestIdentity(t *testing.T) {
	c := New(nil)
	if c.Name() != "dns.hygiene" || c.Tier() != model.TierPassive {
		t.Error("identity")
	}
	if !c.Applies(model.Asset{Kind: model.KindZone, Scope: model.ScopeOwned}) || c.Applies(model.Asset{Kind: model.KindHostname, Scope: model.ScopeOwned}) {
		t.Error("Applies")
	}
}

func runDNSZone(t *testing.T, zone string, q *checktest.DNS, cfg map[string]any) (*checktestRes, map[string]any) {
	t.Helper()
	c := New(nil)
	c.randLabel = func() string { return "probe" }
	tg := checktest.NewTarget(model.Asset{Kind: model.KindZone, Key: zone, Scope: model.ScopeOwned},
		checktest.WithResolver(fixtureResolver(t)), checktest.WithDNS(q), checktest.WithConfig(cfg))
	res, err := c.Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	return &checktestRes{keys(res.Findings), res.Findings}, res.Observations[0].Data
}

func TestDNSExtrasHealthyZone(t *testing.T) {
	q := checktest.NewDNS().Add(
		"good.example.com. 60 IN SOA ns1.example.net. h.example.net. 1 2 3 4 5",
		"good.example.com. 60 IN MX 10 mail.example.net.",
		`good.example.com. 60 IN CAA 0 issue "letsencrypt.org"`,
		"good.example.com. 60 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
	)
	got, obs := runDNSZone(t, "good.example.com", q, nil)
	if len(got.keys) != 0 {
		t.Fatalf("%v", got.keys)
	}
	if obs["dnssec"].(map[string]any)["dnskey"] != true {
		t.Errorf("%v", obs)
	}
}

func TestDNSExtrasCAAAndDNSSEC(t *testing.T) {
	q := checktest.NewDNS().Add("good.example.com. 60 IN SOA ns1.example.net. h.example.net. 1 2 3 4 5")
	got, _ := runDNSZone(t, "good.example.com", q, nil)
	if got.keys["caa-missing"] != model.SeverityInfo || got.keys["dnssec-unsigned"] != model.SeverityLow || len(got.keys) != 2 {
		t.Fatalf("%v", got.keys)
	}
}

func TestDNSSECSkippedForNonApexAndUnknown(t *testing.T) {
	// Name exists but has no SOA of its own: not a zone apex.
	q := checktest.NewDNS().Exists("good.example.com")
	if got, _ := runDNSZone(t, "good.example.com", q, nil); got.keys["dnssec-unsigned"] != "" {
		t.Errorf("non-apex must not be reported: %v", got.keys)
	}
	// SERVFAIL on DNSKEY: unknown, no finding.
	q = checktest.NewDNS().Add("good.example.com. 60 IN SOA ns1.example.net. h.example.net. 1 2 3 4 5").Servfail("other")
	got, _ := runDNSZone(t, "good.example.com", q, nil)
	if got.keys["dnssec-unsigned"] == "" {
		t.Fatalf("baseline should report unsigned: %v", got.keys)
	}
	q2 := checktest.NewDNS().Servfail("good.example.com")
	got, obs := runDNSZone(t, "good.example.com", q2, nil)
	if len(got.keys) != 0 || obs["dns_unknown"] != true {
		t.Errorf("servfail must be unknown: %v %v", got.keys, obs)
	}
}

func TestMXWithoutSPF(t *testing.T) {
	q := checktest.NewDNS().Add("nothing.example.com. 60 IN MX 10 mail.example.net.").Servfail("never")
	got, _ := runDNSZone(t, "nothing.example.com", q, map[string]any{"check_axfr": false})
	if got.keys["mx-without-spf"] != model.SeverityMedium {
		t.Fatalf("%v", got.keys)
	}
	if _, dup := got.keys["spf-missing"]; dup {
		t.Errorf("spf-missing must be replaced: %v", got.keys)
	}
	// Null MX means no mail: back to the generic low finding.
	q = checktest.NewDNS().Add("nothing.example.com. 60 IN MX 0 .")
	got, _ = runDNSZone(t, "nothing.example.com", q, nil)
	if got.keys["spf-missing"] != model.SeverityLow || got.keys["mx-without-spf"] != "" {
		t.Errorf("null MX: %v", got.keys)
	}
	// MX with SPF present: nothing.
	q = checktest.NewDNS().Add("good.example.com. 60 IN MX 10 mail.example.net.")
	if got, _ = runDNSZone(t, "good.example.com", q, nil); got.keys["mx-without-spf"] != "" || got.keys["spf-missing"] != "" {
		t.Errorf("%v", got.keys)
	}
}

func TestAXFROpenAndSkipped(t *testing.T) {
	q := checktest.NewDNS().SetAXFR("good.example.com", dnsx.AXFRReport{Zone: "good.example.com", Attempts: []dnsx.AXFRAttempt{
		{NS: "ns1.example.net", Addr: "192.0.2.1:53", Outcome: dnsx.AXFROpen, Records: 42},
		{NS: "ns2.example.net", Addr: "203.0.113.9:53", Outcome: dnsx.AXFRSkipped, Note: "not owned"},
	}})
	got, obs := runDNSZone(t, "good.example.com", q, nil)
	if got.keys["axfr-open:ns1.example.net"] != model.SeverityCritical || len(obs["axfr"].([]map[string]any)) != 2 {
		t.Fatalf("%v %v", got.keys, obs["axfr"])
	}
	for k := range got.keys {
		if k == "axfr-open:ns2.example.net" {
			t.Error("skipped attempt must not be a finding")
		}
	}
	got, _ = runDNSZone(t, "good.example.com", q, map[string]any{"check_axfr": false})
	for k := range got.keys {
		if len(k) > 4 && k[:4] == "axfr" {
			t.Errorf("axfr disabled: %v", got.keys)
		}
	}
}
