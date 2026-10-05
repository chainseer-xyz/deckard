package correlation

import (
	"context"
	"sort"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func host(name, zone string, attrs map[string]any) check.Neighbour {
	return check.Neighbour{
		Asset:    model.Asset{Kind: model.KindHostname, Key: name, Zone: zone, Scope: model.ScopeOwned, Source: "cloudflare", Attrs: attrs},
		Relation: model.RelResolvesTo,
	}
}

func originIP() model.Asset {
	return model.Asset{Kind: model.KindIP, Key: "44.55.66.77", Scope: model.ScopeOwned, Attrs: map[string]any{"origin": true}}
}

func TestRules(t *testing.T) {
	px := map[string]any{"proxied": true}
	un := map[string]any{"proxied": false}
	cases := []struct {
		name string
		ip   model.Asset
		ns   []check.Neighbour
		want map[string]model.Severity // finding key -> severity
	}{
		{"unproxied sibling in same zone", originIP(),
			[]check.Neighbour{host("api.example.com", "example.com", px), host("dev-api.example.com", "example.com", un)},
			map[string]model.Severity{"published:dev-api.example.com": model.SeverityHigh}},
		{"two proxied share origin", originIP(),
			[]check.Neighbour{host("a.example.com", "example.com", px), host("b.example.com", "example.com", px)},
			map[string]model.Severity{}},
		{"not an origin, many unproxied", model.Asset{Kind: model.KindIP, Key: "1.2.3.4", Scope: model.ScopeOwned, Attrs: map[string]any{"exposed": true}},
			[]check.Neighbour{host("a.example.com", "example.com", un), host("b.example.com", "example.com", un), host("c.other.org", "other.org", un)},
			map[string]model.Severity{}},
		{"unproxied other zone", originIP(),
			[]check.Neighbour{host("api.example.com", "example.com", px), host("legacy.other.org", "other.org", un)},
			map[string]model.Severity{"cross-zone:legacy.other.org": model.SeverityMedium}},
		{"discovered name", originIP(),
			[]check.Neighbour{host("api.example.com", "example.com", px), host("x.example.com", "example.com", map[string]any{"discovered_by": "ct"})},
			map[string]model.Severity{"discovered:x.example.com": model.SeverityMedium}},
		{"unknown proxied state ignored", originIP(),
			[]check.Neighbour{host("api.example.com", "example.com", px), host("m.example.com", "example.com", nil)},
			map[string]model.Severity{}},
		{"cname neighbours ignored", originIP(),
			[]check.Neighbour{host("api.example.com", "example.com", px),
				{Asset: model.Asset{Kind: model.KindHostname, Key: "c.example.com", Zone: "example.com", Attrs: un}, Relation: model.RelCNAMETo}},
			map[string]model.Severity{}},
		{"origin with no proxied host, unproxied other zone", originIP(),
			[]check.Neighbour{host("legacy.other.org", "other.org", un)},
			map[string]model.Severity{"cross-zone:legacy.other.org": model.SeverityMedium}},
		{"no neighbours", originIP(), nil, map[string]model.Severity{}},
	}
	c := New()
	for _, tc := range cases {
		res, err := c.Run(context.Background(), checktest.NewTarget(tc.ip, checktest.WithNeighbours(tc.ns...)))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := map[string]model.Severity{}
		for _, f := range res.Findings {
			got[f.Key] = f.Severity
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
			continue
		}
		for k, s := range tc.want {
			if got[k] != s {
				t.Errorf("%s: %s = %v want %v", tc.name, k, got[k], s)
			}
		}
	}
}

func TestHighEvidence(t *testing.T) {
	ns := []check.Neighbour{
		host("api.example.com", "example.com", map[string]any{"proxied": true}),
		host("dev-api.example.com", "example.com", map[string]any{"proxied": false}),
	}
	res, _ := New().Run(context.Background(), checktest.NewTarget(originIP(), checktest.WithNeighbours(ns...)))
	if len(res.Findings) != 1 {
		t.Fatal(res.Findings)
	}
	f := res.Findings[0]
	if f.Title != "Proxied origin IP is directly published by an unproxied DNS record" || f.Check != Name {
		t.Errorf("title/check: %q", f.Title)
	}
	px, _ := f.Evidence["proxied_hostnames"].([]string)
	up, _ := f.Evidence["unproxied_hostnames"].([]string)
	sort.Strings(px)
	if len(px) != 1 || px[0] != "api.example.com" || len(up) != 1 || up[0] != "dev-api.example.com" {
		t.Errorf("evidence: %v", f.Evidence)
	}
	if f.Evidence["sources"] == nil || f.Remediation == "" {
		t.Errorf("sources/remediation missing: %v", f.Evidence)
	}
}

func TestApplies(t *testing.T) {
	c := New()
	if !c.Applies(originIP()) {
		t.Error("origin ip should apply")
	}
	for i, a := range []model.Asset{
		{Kind: model.KindIP, Scope: model.ScopeOwned},
		{Kind: model.KindIP, Scope: model.ScopeShared, Attrs: map[string]any{"origin": true}},
		{Kind: model.KindHostname, Scope: model.ScopeOwned, Attrs: map[string]any{"origin": true}},
	} {
		if c.Applies(a) {
			t.Errorf("case %d", i)
		}
	}
	if c.Tier() != model.TierPassive || c.Name() != "origin.correlation" {
		t.Error("name/tier")
	}
}

func TestPublishHelper(t *testing.T) {
	ns := []check.Neighbour{
		host("api.example.com", "example.com", map[string]any{"proxied": true}),
		host("dev.example.com", "example.com", map[string]any{"proxied": false}),
	}
	p := Publish(ns)
	if len(p.Proxied) != 1 || len(p.Unproxied) != 1 {
		t.Errorf("%+v", p)
	}
}

func TestSecondarySourceOriginFacts(t *testing.T) {
	ip := model.Asset{Kind: model.KindIP, Key: "44.55.66.77", Scope: model.ScopeOwned, Source: "aws",
		Reporters: []string{"aws", "cf"}, SourceFacts: map[string]model.SourceFact{
			"aws": {Attrs: map[string]any{"owned": true}},
			"cf":  {Attrs: map[string]any{"origin": true}},
		}}
	neighbour := func(name string, proxied bool) check.Neighbour {
		return check.Neighbour{Relation: model.RelResolvesTo, Asset: model.Asset{
			Kind: model.KindHostname, Key: name, Source: "cluster", Reporters: []string{"cluster", "cf"},
			SourceFacts: map[string]model.SourceFact{
				"cluster": {Attrs: map[string]any{"namespace": "web"}},
				"cf":      {Zone: "example.com", Attrs: map[string]any{"proxied": proxied}},
			},
		}}
	}
	ns := []check.Neighbour{neighbour("api.example.com", true), neighbour("dev.example.com", false)}
	res, err := New().Run(context.Background(), checktest.NewTarget(ip, checktest.WithNeighbours(ns...)))
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Severity != model.SeverityHigh {
		t.Fatalf("secondary DNS/AWS facts failed: %+v, %v", res, err)
	}
	sources := res.Findings[0].Evidence["sources"].(map[string]string)
	if sources["api.example.com"] != "cf" || sources["dev.example.com"] != "cf" {
		t.Fatalf("proxy evidence misattributed to canonical source: %v", sources)
	}
	ip.Scope = model.ScopeShared
	if New().Applies(ip) {
		t.Fatal("origin evidence must not establish ownership")
	}
	ip.Scope, ip.Reporters = model.ScopeOwned, []string{"aws"}
	if New().Applies(ip) {
		t.Fatal("retired source must not retain origin evidence")
	}
	ns[0].Asset.SourceFacts["cluster"] = model.SourceFact{Attrs: map[string]any{"proxied": false}}
	if p := Publish(ns); len(p.Proxied) != 0 || len(p.Unproxied) != 1 {
		t.Fatalf("conflicting proxy claims selected an arbitrary winner: %+v", p)
	}
	ip.Reporters = []string{"aws", "cf"}
	res, err = New().Run(context.Background(), checktest.NewTarget(ip, checktest.WithNeighbours(ns...)))
	if err != nil || !res.Partial {
		t.Fatalf("conflicting proxy claims must not produce a clean observation: %+v %v", res, err)
	}
}
