package dangling

import (
	"context"
	"net"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestClassifyCNAME(t *testing.T) {
	cases := []struct {
		name        string
		nx, owned   bool
		wantKey     string
		wantNothing bool
	}{
		{"healthy", false, false, "", true},
		{"external nx", true, false, "cname-nxdomain", false},
		{"owned nx", true, true, "cname-owned-missing", false},
	}
	for _, c := range cases {
		f := ClassifyCNAME("a.example.com", "b.example.net", c.nx, c.owned)
		if c.wantNothing {
			if f != nil {
				t.Errorf("%s: unexpected finding", c.name)
			}
			continue
		}
		if f == nil || f.Key != c.wantKey || f.Severity != model.SeverityHigh || f.Remediation == "" {
			t.Errorf("%s: %+v", c.name, f)
		}
	}
	if ClassifyCNAME("a.example.com", "a.example.com", true, true) != nil {
		t.Error("self target is not a CNAME")
	}
}

func run(t *testing.T, r *checktest.Resolver, host string) (resFindings []model.FindingInput, c *Check, out any) {
	t.Helper()
	tg := checktest.NewTarget(checktest.Hostname(host, "example.com"), checktest.WithResolver(r))
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	return res.Findings, nil, res
}

func TestRunCNAMEToMissingExternal(t *testing.T) {
	r := &checktest.Resolver{CNAMEs: map[string]string{"blog.example.com": "gone.example.net"}}
	f, _, _ := run(t, r, "blog.example.com")
	if len(f) != 1 || f[0].Key != "cname-nxdomain" {
		t.Fatalf("findings: %+v", f)
	}
}

func TestRunCNAMEToMissingOwnedEmitsRelation(t *testing.T) {
	r := &checktest.Resolver{CNAMEs: map[string]string{"blog.example.com": "old.example.com"}}
	tg := checktest.NewTarget(checktest.Hostname("blog.example.com", "example.com"), checktest.WithResolver(r))
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 1 || res.Findings[0].Key != "cname-owned-missing" {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if len(res.Relations) != 1 || res.Relations[0].Type != model.RelCNAMETo || res.Relations[0].ToKey != "old.example.com" {
		t.Errorf("relations: %+v", res.Relations)
	}
	if len(res.Discovered) != 1 || res.Discovered[0].Key != "old.example.com" || res.Discovered[0].Zone != "example.com" {
		t.Errorf("discovered: %+v", res.Discovered)
	}
}

func TestRunHealthyExternalCNAMENoDiscovery(t *testing.T) {
	r := &checktest.Resolver{
		CNAMEs: map[string]string{"www.example.com": "lb.example.net"},
		Hosts:  map[string][]string{"lb.example.net": {"192.0.2.10"}},
	}
	tg := checktest.NewTarget(checktest.Hostname("www.example.com", "example.com"), checktest.WithResolver(r))
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 0 || len(res.Discovered) != 0 || len(res.Relations) != 0 {
		t.Errorf("expected nothing, got %+v", res)
	}
	chain := res.Observations[0].Data["cname_chain"].([]string)
	if len(chain) != 2 || chain[1] != "lb.example.net" {
		t.Errorf("chain: %v", chain)
	}
}

func TestRunARecordToNothingIsNotAFinding(t *testing.T) {
	r := &checktest.Resolver{Hosts: map[string][]string{"api.example.com": {"192.0.2.99"}}}
	f, _, _ := run(t, r, "api.example.com")
	if len(f) != 0 {
		t.Errorf("A record must not be a finding: %+v", f)
	}
}

func TestRunNSDelegationTakeover(t *testing.T) {
	r := &checktest.Resolver{
		NSs: map[string][]string{"sub.example.com": {"ns1.gone-dns.example.net.", "ns2.example.com."}},
		Hosts: map[string][]string{
			"ns2.example.com": {"198.51.100.2"},
		},
		CNAMEs: map[string]string{},
	}
	r.Hosts["sub.example.com"] = []string{"192.0.2.1"}
	f, _, _ := run(t, r, "sub.example.com")
	if len(f) != 1 || f[0].Key != "ns:ns1.gone-dns.example.net" || f[0].Severity != model.SeverityCritical {
		t.Fatalf("findings: %+v", f)
	}
}

func TestAppliesAndName(t *testing.T) {
	c := New(nil)
	if c.Tier() != model.TierPassive || c.Name() != "dns.dangling" {
		t.Error("identity")
	}
	if !c.Applies(model.Asset{Kind: model.KindHostname, Scope: model.ScopeOwned}) ||
		c.Applies(model.Asset{Kind: model.KindHostname, Scope: model.ScopeExternal}) ||
		c.Applies(model.Asset{Kind: model.KindIP, Scope: model.ScopeOwned}) {
		t.Error("Applies")
	}
}

func runDNS(t *testing.T, q *checktest.DNS, host string) *check.Result {
	t.Helper()
	tg := checktest.NewTarget(checktest.Hostname(host, "example.com"), checktest.WithDNS(q))
	tg.Resolver = nil // the DNS path must not touch the Resolver
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestDNSDanglingChainEndsNXDomainAtSecondHop(t *testing.T) {
	q := checktest.NewDNS().Add(
		"blog.example.com. 60 IN CNAME mid.example.net.",
		"mid.example.net. 60 IN CNAME gone.example.org.",
	)
	res := runDNS(t, q, "blog.example.com")
	if len(res.Findings) != 1 || res.Findings[0].Key != "cname-nxdomain" {
		t.Fatalf("findings: %+v", res.Findings)
	}
	ev := res.Findings[0].Evidence
	if ev["cname_target"] != "gone.example.org" || ev["nxdomain_at_hop"] != 2 {
		t.Errorf("evidence: %+v", ev)
	}
}

func TestDNSDanglingOwnedTarget(t *testing.T) {
	q := checktest.NewDNS().Add("blog.example.com. 60 IN CNAME old.example.com.")
	res := runDNS(t, q, "blog.example.com")
	if len(res.Findings) != 1 || res.Findings[0].Key != "cname-owned-missing" || len(res.Relations) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestDNSTransientServfailIsNotAFinding(t *testing.T) {
	for _, tc := range []struct {
		name string
		q    *checktest.DNS
	}{
		{"servfail at target", checktest.NewDNS().Add("blog.example.com. 60 IN CNAME t.example.net.").Servfail("t.example.net")},
		{"servfail at host", checktest.NewDNS().Servfail("blog.example.com")},
		{"timeout at target", checktest.NewDNS().Add("blog.example.com. 60 IN CNAME t.example.net.").Timeout("t.example.net")},
	} {
		res := runDNS(t, tc.q, "blog.example.com")
		if len(res.Findings) != 0 {
			t.Errorf("%s: false positive: %+v", tc.name, res.Findings)
		}
		if len(res.Observations) != 1 || res.Observations[0].Data["dns_unknown"] != true || res.Observations[0].Data["cname_state"] != "unknown" {
			t.Errorf("%s: observation: %+v", tc.name, res.Observations)
		}
		// Unknown is not clean: a clean run would count a miss against an
		// open finding, so a resolver outage would resolve it.
		if !res.Partial {
			t.Errorf("%s: unknown DNS outcome reported as a complete run", tc.name)
		}
	}
	ns := runDNS(t, checktest.NewDNS().Add("sub.example.com. 60 IN NS ns1.flaky.example.net.").Servfail("ns1.flaky.example.net"), "sub.example.com")
	if !ns.Partial {
		t.Errorf("unknown NS outcome reported as a complete run: %+v", ns.Observations)
	}
}

func TestRunResolverErrorsArePartial(t *testing.T) {
	servfail := &net.DNSError{Err: "server misbehaving", Name: "x", IsTemporary: true}
	for name, r := range map[string]*checktest.Resolver{
		"cname lookup fails": {Errs: map[string]error{"blog.example.com": servfail}},
		"target lookup fails": {CNAMEs: map[string]string{"blog.example.com": "t.example.net"},
			Errs: map[string]error{"t.example.net": servfail}},
		"ns host lookup fails": {Hosts: map[string][]string{"blog.example.com": {"192.0.2.1"}},
			NSs: map[string][]string{"blog.example.com": {"ns1.flaky.example.net"}}, Errs: map[string]error{"ns1.flaky.example.net": servfail}},
	} {
		_, _, out := run(t, r, "blog.example.com")
		if res := out.(*check.Result); !res.Partial || len(res.Findings) != 0 {
			t.Errorf("%s: unknown outcome reported as a clean run: %+v", name, res)
		}
	}
}

func TestDNSHealthyLoopAndNoCNAME(t *testing.T) {
	q := checktest.NewDNS().Add(
		"www.example.com. 60 IN CNAME lb.example.net.", "lb.example.net. 60 IN A 192.0.2.1",
		"a.example.com. 60 IN CNAME b.example.com.", "b.example.com. 60 IN CNAME a.example.com.",
		"plain.example.com. 60 IN A 192.0.2.2",
	)
	for _, h := range []string{"www.example.com", "a.example.com", "plain.example.com", "missing.example.com"} {
		if res := runDNS(t, q, h); len(res.Findings) != 0 {
			t.Errorf("%s: %+v", h, res.Findings)
		}
	}
}

func TestDNSNSDelegation(t *testing.T) {
	q := checktest.NewDNS().Add(
		"sub.example.com. 60 IN NS ns1.dead.example.net.",
		"sub.example.com. 60 IN NS ns2.ok.example.net.",
		"sub.example.com. 60 IN NS ns3.flaky.example.net.",
		"ns2.ok.example.net. 60 IN A 192.0.2.5",
	).Servfail("ns3.flaky.example.net")
	res := runDNS(t, q, "sub.example.com")
	if len(res.Findings) != 1 || res.Findings[0].Key != "ns:ns1.dead.example.net" || res.Findings[0].Severity != model.SeverityCritical {
		t.Fatalf("%+v", res.Findings)
	}
	st := res.Observations[0].Data["ns_status"].(map[string]string)
	if st["ns3.flaky.example.net"] != "error" || st["ns2.ok.example.net"] != "ok" {
		t.Errorf("%+v", st)
	}
}

func TestClassifyCNAMEServiceLabelIsLowNotTakeover(t *testing.T) {
	for _, host := range []string{"sel._domainkey.example.com", "_domainconnect.example.com", "_acme-challenge.www.example.com"} {
		for _, owned := range []bool{false, true} {
			f := ClassifyCNAME(host, "gone.example.net", true, owned)
			if f == nil || f.Severity != model.SeverityLow || f.Key != "cname-nxdomain-service" {
				t.Fatalf("%s owned=%v: %+v", host, owned, f)
			}
		}
	}
	if f := ClassifyCNAME("www.example.com", "gone.example.net", true, false); f == nil || f.Severity != model.SeverityHigh {
		t.Fatalf("a web CNAME must stay high: %+v", f)
	}
	if f := ClassifyCNAME("a_b.example.com", "gone.example.net", true, false); f == nil || f.Severity != model.SeverityHigh {
		t.Fatalf("an underscore inside a label is not a service label: %+v", f)
	}
}
