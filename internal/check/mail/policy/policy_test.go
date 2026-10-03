package policy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const zone = "example.com"

const goodPolicy = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 604800\n"

// env scripts one mail zone: DNS answers, the TXT resolver and the policy
// server. The zero value built by newEnv is a clean, fully configured zone.
type env struct {
	dns     *checktest.DNS
	res     *checktest.Resolver
	status  int
	body    string
	headers map[string]string
	redir   bool
	noHTTP  bool
	noRoute bool // the policy host is not reachable
	noDNS   bool
	hits    atomic.Int64
	cfg     map[string]any
}

func newEnv() *env {
	return &env{
		dns: checktest.NewDNS().Add(
			"example.com. 300 IN MX 10 mx1.example.com.",
			"example.com. 300 IN MX 20 mx2.example.com.",
		),
		res: &checktest.Resolver{TXTs: map[string][]string{
			"example.com":            {"v=spf1 mx -all"},
			"_dmarc.example.com":     {"v=DMARC1; p=reject; rua=mailto:reports@example.com"},
			"_mta-sts.example.com":   {"v=STSv1; id=20260101T000000"},
			"_smtp._tls.example.com": {"v=TLSRPTv1; rua=mailto:tls@example.com"},
		}},
		status: http.StatusOK,
		body:   goodPolicy,
	}
}

func (e *env) txt(name string, recs ...string) *env {
	if len(recs) == 0 {
		delete(e.res.TXTs, name)
	} else {
		e.res.TXTs[name] = recs
	}
	return e
}

func (e *env) with(k string, v any) *env {
	if e.cfg == nil {
		e.cfg = map[string]any{}
	}
	e.cfg[k] = v
	return e
}

func zoneAsset(name string) model.Asset {
	return model.Asset{Kind: model.KindZone, Key: name, Scope: model.ScopeOwned}
}

func (e *env) run(t *testing.T) *check.Result {
	t.Helper()
	return e.runZone(t, zone)
}

func (e *env) runZone(t *testing.T, name string) *check.Result {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		if e.redir && r.URL.Path == "/.well-known/mta-sts.txt" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		if r.URL.Path != "/.well-known/mta-sts.txt" && r.URL.Path != "/elsewhere" {
			http.NotFound(w, r)
			return
		}
		for k, v := range e.headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(e.status)
		_, _ = w.Write([]byte(e.body))
	}))
	t.Cleanup(srv.Close)
	opts := []checktest.Option{checktest.WithResolver(e.res), checktest.WithConfig(e.cfg)}
	if !e.noHTTP {
		routes := map[string]*httptest.Server{}
		if !e.noRoute {
			routes["mta-sts."+name+":443"] = srv
		}
		opts = append(opts, checktest.WithHTTP(checktest.HostClient(routes)))
	}
	tg := checktest.NewTarget(zoneAsset(name), opts...)
	if !e.noDNS {
		tg.DNS = e.dns
	}
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func keys(res *check.Result) []string {
	out := []string{}
	for _, f := range res.Findings {
		out = append(out, f.Key)
	}
	slices.Sort(out)
	return out
}

func byKey(res *check.Result) map[string]model.FindingInput {
	m := map[string]model.FindingInput{}
	for _, f := range res.Findings {
		m[f.Key] = f
	}
	return m
}

func obs(t *testing.T, res *check.Result) map[string]any {
	t.Helper()
	if len(res.Observations) != 1 || res.Observations[0].Check != Name {
		t.Fatalf("observations = %+v", res.Observations)
	}
	return res.Observations[0].Data
}

// want asserts the exact finding keys and whether the run is partial.
func want(t *testing.T, res *check.Result, partial bool, keys_ ...string) {
	t.Helper()
	if keys_ == nil {
		keys_ = []string{}
	}
	slices.Sort(keys_)
	if got := keys(res); !reflect.DeepEqual(got, keys_) {
		t.Errorf("keys = %v, want %v", got, keys_)
	}
	if res.Partial != partial {
		t.Errorf("partial = %v, want %v (observation %v)", res.Partial, partial, res.Observations)
	}
}

func TestApplies(t *testing.T) {
	c := New(nil)
	for _, tc := range []struct {
		a    model.Asset
		want bool
	}{
		{zoneAsset("example.com"), true},
		{zoneAsset("Example.COM."), true},
		{zoneAsset("example.co.uk"), true},
		{zoneAsset("corp.example.com"), false}, // subzone: inherits the organisational domain
		{zoneAsset("co.uk"), false},
		{zoneAsset("example.internal"), false},
		{model.Asset{Kind: model.KindZone, Key: "example.com", Scope: model.ScopeExternal}, false},
		{model.Asset{Kind: model.KindZone, Key: "example.com", Scope: model.ScopeShared}, false},
		{model.Asset{Kind: model.KindHostname, Key: "example.com", Scope: model.ScopeOwned}, false},
	} {
		if got := c.Applies(tc.a); got != tc.want {
			t.Errorf("Applies(%s %s %s) = %v", tc.a.Kind, tc.a.Key, tc.a.Scope, got)
		}
	}
	if c.Name() != "mail.policy" || c.Tier() != model.TierPassive {
		t.Errorf("identity = %s %s", c.Name(), c.Tier())
	}
	if cs := Checks(map[string]map[string]any{Name: {"expects_mail": true}}); len(cs) != 1 || cs[0].Name() != Name {
		t.Errorf("Checks = %v", cs)
	}
}

func TestCleanZone(t *testing.T) {
	e := newEnv()
	res := e.run(t)
	want(t, res, false)
	o := obs(t, res)
	for k, v := range map[string]any{"zone": zone, "mail": "yes", "mta_sts": "enforce", "tls_rpt": true, "dmarc_policy": "reject", "spf_all": "-"} {
		if o[k] != v {
			t.Errorf("observation[%s] = %v, want %v (%v)", k, o[k], v, o)
		}
	}
	if e.hits.Load() != 1 {
		t.Errorf("policy fetched %d times, want once", e.hits.Load())
	}
}

func TestMTASTSMissing(t *testing.T) {
	res := newEnv().txt("_mta-sts.example.com").run(t)
	want(t, res, false, "mta-sts-missing")
	f := byKey(res)["mta-sts-missing"]
	if f.Severity != model.SeverityLow || !strings.Contains(f.Remediation, "_mta-sts.example.com") || !strings.Contains(f.Remediation, "mta-sts.example.com/.well-known/mta-sts.txt") {
		t.Errorf("finding = %s %q", f.Severity, f.Remediation)
	}
	if obs(t, res)["mta_sts"] != "absent" {
		t.Errorf("observation = %v", obs(t, res))
	}
	// Opt out.
	e := newEnv().txt("_mta-sts.example.com").with("check_mta_sts", false)
	want(t, e.run(t), false)
	e = newEnv().with("check_mta_sts", false)
	e.status = 404
	res = e.run(t)
	want(t, res, false)
	if e.hits.Load() != 0 {
		t.Error("check_mta_sts: false must not fetch the policy")
	}
}

func TestMTASTSTXT(t *testing.T) {
	for name, recs := range map[string][]string{
		"multiple":  {"v=STSv1; id=1", "v=STSv1; id=2"},
		"no id":     {"v=STSv1"},
		"empty id":  {"v=STSv1; id="},
		"bad id":    {"v=STSv1; id=2026-01-01"},
		"long id":   {"v=STSv1; id=" + strings.Repeat("a", 33)},
		"other key": {"v=STSv1; ID2=5"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv().txt("_mta-sts.example.com", recs...)
			res := e.run(t)
			want(t, res, false, "mta-sts-txt-invalid")
			if f := byKey(res)["mta-sts-txt-invalid"]; f.Severity != model.SeverityMedium || f.Remediation == "" {
				t.Errorf("finding = %+v", f)
			}
			if e.hits.Load() != 0 {
				t.Error("an unusable TXT record must not trigger a policy fetch")
			}
		})
	}
	// Other TXT records at the name are ignored.
	res := newEnv().txt("_mta-sts.example.com", "unrelated", "V=STSV1; ID=abc123").run(t)
	want(t, res, false)
}

func TestMTASTSPolicyHTTP(t *testing.T) {
	t.Run("404 is a definite finding", func(t *testing.T) {
		for _, st := range []int{404, 410, 403, 401} {
			e := newEnv()
			e.status = st
			res := e.run(t)
			want(t, res, false, "mta-sts-policy-unavailable")
			f := byKey(res)["mta-sts-policy-unavailable"]
			if f.Severity != model.SeverityMedium || f.Evidence["status"] != st || !strings.Contains(f.Title, fmt.Sprint(st)) {
				t.Errorf("status %d: %s %v %q", st, f.Severity, f.Evidence, f.Title)
			}
			if obs(t, res)["mta_sts"] != "unavailable" {
				t.Errorf("observation = %v", obs(t, res))
			}
		}
	})
	t.Run("transient answers prove nothing", func(t *testing.T) {
		for _, st := range []int{500, 502, 503, 429, 408} {
			e := newEnv()
			e.status = st
			res := e.run(t)
			want(t, res, true)
			if obs(t, res)["mta_sts_error"] == nil {
				t.Errorf("status %d: no note in %v", st, obs(t, res))
			}
		}
	})
	t.Run("unexpected 2xx is not a policy but not a finding", func(t *testing.T) {
		e := newEnv()
		e.status = 204
		want(t, e.run(t), true)
	})
	t.Run("redirect", func(t *testing.T) {
		e := newEnv()
		e.redir = true
		res := e.run(t)
		want(t, res, false, "mta-sts-policy-redirect")
		if f := byKey(res)["mta-sts-policy-redirect"]; f.Severity != model.SeverityMedium || !strings.Contains(f.Remediation, "no redirect") {
			t.Errorf("finding = %+v", f)
		}
	})
	t.Run("unreachable policy host", func(t *testing.T) {
		e := newEnv()
		e.noRoute = true
		res := e.run(t)
		want(t, res, true)
		if obs(t, res)["mta_sts_error"] == nil {
			t.Errorf("observation = %v", obs(t, res))
		}
	})
	t.Run("no http client", func(t *testing.T) {
		e := newEnv()
		e.noHTTP = true
		res := e.run(t)
		want(t, res, true)
	})
	t.Run("oversized policy", func(t *testing.T) {
		e := newEnv()
		e.body = goodPolicy + strings.Repeat("x: y\n", 20000)
		want(t, e.run(t), true)
	})
}

func TestMTASTSPolicyContent(t *testing.T) {
	for name, tc := range map[string]struct{ body, problem string }{
		"empty":            {"", "version is not STSv1"},
		"wrong version":    {strings.Replace(goodPolicy, "STSv1", "STSv2", 1), "version is not STSv1"},
		"no mode":          {"version: STSv1\nmx: mx1.example.com\nmax_age: 604800\n", "mode is missing"},
		"bad mode":         {strings.Replace(goodPolicy, "enforce", "strict", 1), `mode "strict"`},
		"no max_age":       {"version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\n", "max_age is missing"},
		"text max_age":     {strings.Replace(goodPolicy, "604800", "a-week", 1), "max_age"},
		"negative max_age": {strings.Replace(goodPolicy, "604800", "-1", 1), "max_age"},
		"huge max_age":     {strings.Replace(goodPolicy, "604800", "99999999999", 1), "max_age"},
		"no mx":            {"version: STSv1\nmode: testing\nmax_age: 604800\n", "no mx: pattern"},
		"not key value":    {goodPolicy + "garbage line\n", "not key: value"},
		"html":             {"<html><body>404</body></html>", "version is not STSv1"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv()
			e.body = tc.body
			res := e.run(t)
			want(t, res, false, "mta-sts-policy-invalid")
			f := byKey(res)["mta-sts-policy-invalid"]
			if f.Severity != model.SeverityMedium || !strings.Contains(f.Description, tc.problem) {
				t.Errorf("finding = %s %q, want problem %q", f.Severity, f.Description, tc.problem)
			}
			if probs, _ := f.Evidence["problems"].([]string); len(probs) == 0 {
				t.Errorf("evidence = %v", f.Evidence)
			}
		})
	}
}

func TestMTASTSModes(t *testing.T) {
	policy := func(mode string) string { return strings.Replace(goodPolicy, "enforce", mode, 1) }
	e := newEnv()
	e.body = policy("none")
	res := e.run(t)
	want(t, res, false, "mta-sts-mode-none")
	if f := byKey(res)["mta-sts-mode-none"]; f.Severity != model.SeverityLow || obs(t, res)["mta_sts"] != "none" {
		t.Errorf("none: %s %v", f.Severity, obs(t, res))
	}

	// mode none carries no mx lines and no max_age check.
	e = newEnv()
	e.body = "version: STSv1\nmode: none\nmax_age: 60\n"
	want(t, e.run(t), false, "mta-sts-mode-none")

	e = newEnv()
	e.body = policy("testing")
	res = e.run(t)
	want(t, res, false, "mta-sts-mode-testing")
	if f := byKey(res)["mta-sts-mode-testing"]; f.Severity != model.SeverityLow || !strings.Contains(f.Remediation, "mode: enforce") {
		t.Errorf("testing: %s %q", f.Severity, f.Remediation)
	}

	// Mode and key names are case-insensitive; CRLF line ends are fine.
	e = newEnv()
	e.body = "Version: STSv1\r\nMode: Enforce\r\nMX: mx1.example.com\r\nmx: MX2.example.com.\r\nMax_Age: 604800\r\n"
	want(t, e.run(t), false)
}

func TestMTASTSMaxAge(t *testing.T) {
	e := newEnv()
	e.body = strings.Replace(goodPolicy, "604800", "86400", 1)
	res := e.run(t)
	want(t, res, false, "mta-sts-max-age-short")
	f := byKey(res)["mta-sts-max-age-short"]
	if f.Severity != model.SeverityLow || f.Evidence["max_age"] != 86400 || !strings.Contains(f.Title, "86400") {
		t.Errorf("finding = %s %v %q", f.Severity, f.Evidence, f.Title)
	}
	// min_max_age moves the line.
	e.with("min_max_age", 3600)
	want(t, e.run(t), false)
	e = newEnv().with("min_max_age", 2592000)
	want(t, e.run(t), false, "mta-sts-max-age-short")
}

func TestMTASTSMXMismatch(t *testing.T) {
	policy := func(mode string, mx ...string) string {
		var b strings.Builder
		fmt.Fprintf(&b, "version: STSv1\nmode: %s\nmax_age: 604800\n", mode)
		for _, m := range mx {
			fmt.Fprintf(&b, "mx: %s\n", m)
		}
		return b.String()
	}
	e := newEnv()
	e.body = policy("enforce", "mx1.example.com")
	res := e.run(t)
	want(t, res, false, "mta-sts-mx-mismatch")
	f := byKey(res)["mta-sts-mx-mismatch"]
	if f.Severity != model.SeverityMedium || !reflect.DeepEqual(f.Evidence["unmatched"], []string{"mx2.example.com"}) ||
		!strings.Contains(f.Description, "refuse") || !strings.Contains(f.Remediation, "mx: mx2.example.com") {
		t.Errorf("enforce: %s %v %q", f.Severity, f.Evidence, f.Description)
	}

	e = newEnv()
	e.body = policy("testing", "mx1.example.com")
	res = e.run(t)
	want(t, res, false, "mta-sts-mx-mismatch", "mta-sts-mode-testing")
	if f := byKey(res)["mta-sts-mx-mismatch"]; f.Severity != model.SeverityLow {
		t.Errorf("testing mismatch severity = %s", f.Severity)
	}

	for name, mx := range map[string][]string{
		"wildcard":     {"*.example.com"},
		"mixed":        {"mx1.example.com", "*.example.com"},
		"case and dot": {"MX1.Example.com.", "mx2.example.com"},
		"all exact":    {"mx1.example.com", "mx2.example.com", "stale.example.com"},
	} {
		e = newEnv()
		e.body = policy("enforce", mx...)
		if got := keys(e.run(t)); len(got) != 0 {
			t.Errorf("%s: keys = %v", name, got)
		}
	}
	// A wildcard covers exactly one label; the bare domain is not covered.
	e = newEnv()
	e.dns = checktest.NewDNS().Add("example.com. 300 IN MX 10 a.b.example.com.", "example.com. 300 IN MX 10 example.com.")
	e.body = policy("enforce", "*.example.com")
	res = e.run(t)
	want(t, res, false, "mta-sts-mx-mismatch")
	if got := byKey(res)["mta-sts-mx-mismatch"].Evidence["unmatched"]; !reflect.DeepEqual(got, []string{"a.b.example.com", "example.com"}) {
		t.Errorf("unmatched = %v", got)
	}
}

func TestMXPatternMatching(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"mx.example.com", "mx.example.com", true},
		{"MX.example.com", "mx.EXAMPLE.com", true},
		{"mx.example.com", "mx2.example.com", false},
		{"*.example.com", "mx.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", ".example.com", false},
		{"*.example.com", "mx.example.org", false},
		{"*.example.com", "mxexample.com", false},
	} {
		if got := mxMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("mxMatches(%q, %q) = %v", tc.pattern, tc.host, got)
		}
	}
}

func TestTLSRPT(t *testing.T) {
	// Missing: info on its own, low when MTA-STS is in force.
	res := newEnv().txt("_smtp._tls.example.com").run(t)
	want(t, res, false, "tls-rpt-missing")
	f := byKey(res)["tls-rpt-missing"]
	if f.Severity != model.SeverityLow || !strings.Contains(f.Remediation, `"v=TLSRPTv1; rua=mailto:tls-reports@example.com"`) || !strings.Contains(f.Description, "unnoticed") {
		t.Errorf("with mta-sts: %s %q", f.Severity, f.Remediation)
	}
	if obs(t, res)["tls_rpt"] != false {
		t.Errorf("observation = %v", obs(t, res))
	}
	e := newEnv().txt("_smtp._tls.example.com").txt("_mta-sts.example.com")
	res = e.run(t)
	want(t, res, false, "mta-sts-missing", "tls-rpt-missing")
	if f := byKey(res)["tls-rpt-missing"]; f.Severity != model.SeverityInfo {
		t.Errorf("without mta-sts severity = %s", f.Severity)
	}
	e = newEnv().txt("_smtp._tls.example.com")
	e.body = "version: STSv1\nmode: none\nmax_age: 60\n"
	res = e.run(t)
	if f := byKey(res)["tls-rpt-missing"]; f.Severity != model.SeverityInfo {
		t.Errorf("mta-sts mode none severity = %s", f.Severity)
	}

	for name, recs := range map[string][]string{
		"two records":    {"v=TLSRPTv1; rua=mailto:a@example.com", "v=TLSRPTv1; rua=mailto:b@example.com"},
		"no rua":         {"v=TLSRPTv1"},
		"rua not a url":  {"v=TLSRPTv1; rua=reports@example.com"},
		"empty mailto":   {"v=TLSRPTv1; rua=mailto:"},
		"http not https": {"v=TLSRPTv1; rua=http://example.com/r"},
	} {
		res := newEnv().txt("_smtp._tls.example.com", recs...).run(t)
		want(t, res, false, "tls-rpt-invalid")
		if f := byKey(res)["tls-rpt-invalid"]; f.Severity != model.SeverityLow || f.Remediation == "" {
			t.Errorf("%s: %+v", name, f)
		}
	}
	for name, rec := range map[string]string{
		"https":  "v=TLSRPTv1; rua=https://example.com/tlsrpt",
		"list":   "v=TLSRPTv1; rua=mailto:a@example.com,https://example.com/r",
		"spaces": " V=TLSRPTv1 ;  RUA = mailto:a@example.com ",
	} {
		t.Log("valid record:", name)
		want(t, newEnv().txt("_smtp._tls.example.com", rec).run(t), false)
	}
	// Opt out.
	want(t, newEnv().txt("_smtp._tls.example.com").with("check_tls_rpt", false).run(t), false)
}

func TestDMARCStrength(t *testing.T) {
	dm := func(rec string) *env { return newEnv().txt("_dmarc.example.com", rec) }

	res := dm("v=DMARC1; p=quarantine; pct=25; rua=mailto:r@example.com").run(t)
	want(t, res, false, "dmarc-pct")
	f := byKey(res)["dmarc-pct"]
	if f.Severity != model.SeverityLow || !strings.Contains(f.Description, "pct=25") || f.Evidence["pct"] != 25 {
		t.Errorf("pct: %s %q %v", f.Severity, f.Description, f.Evidence)
	}

	res = dm("v=DMARC1; p=reject; sp=none; rua=mailto:r@example.com").run(t)
	want(t, res, false, "dmarc-sp-none")
	if f := byKey(res)["dmarc-sp-none"]; f.Severity != model.SeverityLow || !strings.Contains(f.Remediation, "sp=") {
		t.Errorf("sp: %+v", f)
	}

	res = dm("v=DMARC1; p=reject").run(t)
	want(t, res, false, "dmarc-no-rua")
	if f := byKey(res)["dmarc-no-rua"]; f.Severity != model.SeverityInfo || !strings.Contains(f.Remediation, "rua=mailto:") {
		t.Errorf("rua: %+v", f)
	}

	res = newEnv().txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:a@example.com", "v=DMARC1; p=none").run(t)
	want(t, res, false, "dmarc-multiple")
	if f := byKey(res)["dmarc-multiple"]; f.Severity != model.SeverityMedium {
		t.Errorf("multiple: %s", f.Severity)
	}
	if obs(t, res)["dmarc_policy"] != "multiple" {
		t.Errorf("observation = %v", obs(t, res))
	}

	// All three at once.
	res = dm("v=DMARC1; p=quarantine; pct=50; sp=none").run(t)
	want(t, res, false, "dmarc-pct", "dmarc-sp-none", "dmarc-no-rua")

	// pct and sp mean nothing for p=none, which dns.hygiene reports; only the
	// missing report address is added.
	res = dm("v=DMARC1; p=none; pct=10; sp=none").run(t)
	want(t, res, false, "dmarc-no-rua")
	// pct=100 and a missing pct are fine; an unparsable pct reads as 100.
	for _, rec := range []string{"v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com", "v=DMARC1; p=reject; pct=abc; rua=mailto:a@example.com"} {
		want(t, dm(rec).run(t), false)
	}
	// No DMARC record at all is dns.hygiene's finding.
	want(t, newEnv().txt("_dmarc.example.com").run(t), false)
}

func TestSPFSoftfail(t *testing.T) {
	soft := func(dmarc string) *env {
		e := newEnv().txt("example.com", "v=spf1 mx ~all")
		if dmarc == "" {
			return e.txt("_dmarc.example.com")
		}
		return e.txt("_dmarc.example.com", dmarc)
	}
	res := soft("v=DMARC1; p=none; rua=mailto:r@example.com").run(t)
	want(t, res, false, "spf-softfail")
	if f := byKey(res)["spf-softfail"]; f.Severity != model.SeverityLow || f.Evidence["dmarc_enforced"] != false || !strings.Contains(f.Remediation, `"-all"`) {
		t.Errorf("no enforcement: %s %v", f.Severity, f.Evidence)
	}
	res = soft("v=DMARC1; p=reject; rua=mailto:r@example.com").run(t)
	want(t, res, false, "spf-softfail")
	if f := byKey(res)["spf-softfail"]; f.Severity != model.SeverityInfo || f.Evidence["dmarc_enforced"] != true {
		t.Errorf("enforced: %s %v", f.Severity, f.Evidence)
	}
	res = soft("").run(t) // no DMARC at all
	if f := byKey(res)["spf-softfail"]; f.Severity != model.SeverityLow {
		t.Errorf("no dmarc: %+v", f)
	}
	// Everything else about SPF is dns.hygiene's: no finding here.
	for name, spf := range map[string][]string{
		"hardfail":  {"v=spf1 mx -all"},
		"plus all":  {"v=spf1 mx +all"},
		"neutral":   {"v=spf1 mx ?all"},
		"no all":    {"v=spf1 mx"},
		"multiple":  {"v=spf1 mx ~all", "v=spf1 a ~all"},
		"missing":   nil,
		"unrelated": {"google-site-verification=abc"},
	} {
		e := newEnv().txt("example.com", spf...)
		if got := keys(e.run(t)); len(got) != 0 {
			t.Errorf("%s: keys = %v", name, got)
		}
	}
}

// None of the findings dns.hygiene owns is ever produced here, even for a zone
// that trips every one of them.
func TestNeverRepeatsHygiene(t *testing.T) {
	hygieneKeys := []string{"spf-missing", "spf-multiple", "spf-plus-all", "spf-neutral-all", "spf-no-all", "spf-too-many-lookups",
		"mx-without-spf", "dmarc-missing", "dmarc-p-none", "caa-missing", "dnssec-unsigned", "wildcard-record"}
	for name, e := range map[string]*env{
		"worst mail zone": newEnv().txt("example.com", "v=spf1 +all", "v=spf1 ?all").txt("_dmarc.example.com", "v=DMARC1; p=none").txt("_mta-sts.example.com"),
		"no spf no dmarc": newEnv().txt("example.com").txt("_dmarc.example.com"),
		"parked":          {dns: checktest.NewDNS().Exists(zone), res: &checktest.Resolver{}},
	} {
		res := e.run(t)
		for _, k := range keys(res) {
			if slices.Contains(hygieneKeys, k) {
				t.Errorf("%s: produced %s, which dns.hygiene owns", name, k)
			}
		}
	}
}

func TestParkedZone(t *testing.T) {
	parked := func() *env {
		return &env{dns: checktest.NewDNS().Exists(zone), res: &checktest.Resolver{}, status: 200}
	}
	e := parked()
	res := e.run(t)
	want(t, res, false, "null-mx-missing")
	f := byKey(res)["null-mx-missing"]
	if f.Severity != model.SeverityInfo || !strings.Contains(f.Remediation, "example.com. IN MX 0 .") {
		t.Errorf("finding = %s %q", f.Severity, f.Remediation)
	}
	if obs(t, res)["mail"] != "no" {
		t.Errorf("observation = %v", obs(t, res))
	}
	// A parked zone is not asked about mail policies at all.
	if len(e.res.Calls) != 0 || e.hits.Load() != 0 {
		t.Errorf("resolver calls %v, policy hits %d", e.res.Calls, e.hits.Load())
	}

	// A null MX is the right answer.
	e = parked()
	e.dns = checktest.NewDNS().Add("example.com. 300 IN MX 0 .")
	want(t, e.run(t), false)

	// expects_mail turns the zone into a mail zone; without a real MX the
	// inbound-only checks (MTA-STS, TLS-RPT absence) stay quiet.
	e = parked().with("expects_mail", true)
	e.res.TXTs = map[string][]string{"example.com": {"v=spf1 include:mail.example.net ~all"}}
	res = e.run(t)
	want(t, res, false, "spf-softfail")
	if obs(t, res)["mail"] != "yes" {
		t.Errorf("observation = %v", obs(t, res))
	}
}

func TestMailZoneJudgedFromMX(t *testing.T) {
	// A null MX next to nothing else: no mail.
	e := newEnv()
	e.dns = checktest.NewDNS().Add("example.com. 300 IN MX 0 .")
	want(t, e.run(t), false)
}

func TestUnknownMX(t *testing.T) {
	t.Run("servfail", func(t *testing.T) {
		e := newEnv()
		e.dns = checktest.NewDNS().Servfail(zone)
		res := e.run(t)
		want(t, res, true)
		if o := obs(t, res); o["mx_error"] == nil || o["skipped"] == nil {
			t.Errorf("observation = %v", o)
		}
		if len(e.res.Calls) != 0 {
			t.Errorf("nothing may be judged without knowing the zone handles mail: %v", e.res.Calls)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		e := newEnv()
		e.dns = checktest.NewDNS().Timeout(zone)
		want(t, e.run(t), true)
	})
	t.Run("nxdomain", func(t *testing.T) {
		e := newEnv()
		e.dns = checktest.NewDNS()
		want(t, e.run(t), true)
	})
	t.Run("no dns querier", func(t *testing.T) {
		e := newEnv()
		e.noDNS = true
		want(t, e.run(t), true)
	})
	t.Run("expects_mail still judges what it can", func(t *testing.T) {
		e := newEnv().with("expects_mail", true).txt("_dmarc.example.com", "v=DMARC1; p=reject")
		e.dns = checktest.NewDNS().Servfail(zone)
		res := e.run(t)
		want(t, res, true, "dmarc-no-rua")
	})
}

// A lookup that fails marks the run partial and judges nothing from it.
func TestLookupErrors(t *testing.T) {
	boom := errors.New("servfail")
	for name, tc := range map[string]struct {
		name string
		keys []string
	}{
		"dmarc":   {"_dmarc.example.com", nil},
		"spf":     {"example.com", nil},
		"mta-sts": {"_mta-sts.example.com", nil},
		"tls-rpt": {"_smtp._tls.example.com", nil},
	} {
		e := newEnv()
		e.res.Errs = map[string]error{tc.name: boom}
		res := e.run(t)
		want(t, res, true, tc.keys...)
		found := false
		for k := range obs(t, res) {
			if strings.HasSuffix(k, "_error") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no error note in %v", name, obs(t, res))
		}
	}
	// The failed lookup does not hide findings from the others.
	e := newEnv().txt("_dmarc.example.com", "v=DMARC1; p=reject")
	e.res.Errs = map[string]error{"_smtp._tls.example.com": boom}
	want(t, e.run(t), true, "dmarc-no-rua")
}

func TestSubzoneAndNilResolver(t *testing.T) {
	res := newEnv().runZone(t, "corp.example.com")
	want(t, res, true)
	if obs(t, res)["skipped"] == nil {
		t.Errorf("observation = %v", obs(t, res))
	}
	tg := checktest.NewTarget(zoneAsset(zone))
	tg.Resolver = nil
	tg.DNS = checktest.NewDNS()
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	want(t, res, true)
}

// Whatever a zone looks like, findings are complete, stay between info and
// medium, and use stable, distinct keys.
func TestFindingQuality(t *testing.T) {
	policy := "version: STSv1\nmode: testing\nmx: other.example.net\nmax_age: 60\n"
	e := newEnv().txt("example.com", "v=spf1 mx ~all").
		txt("_dmarc.example.com", "v=DMARC1; p=quarantine; pct=10; sp=none").txt("_smtp._tls.example.com")
	e.body = policy
	res := e.run(t)
	if len(res.Findings) < 6 {
		t.Fatalf("keys = %v", keys(res))
	}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		if f.Check != Name || f.Title == "" || f.Description == "" || f.Remediation == "" || f.Evidence["zone"] != zone || len(f.Tags) < 2 {
			t.Errorf("incomplete finding %s: %+v", f.Key, f)
		}
		if f.Severity.AtLeast(model.SeverityHigh) {
			t.Errorf("%s is %s: mail.policy never reports above medium", f.Key, f.Severity)
		}
		if seen[f.Key] {
			t.Errorf("duplicate key %s", f.Key)
		}
		seen[f.Key] = true
	}
}

func TestParseSTS(t *testing.T) {
	p := parseSTS("version: STSv1\nmode: testing\nmx: *.mail.example.com\nmx: backup.example.com\nmax_age: 86400\nextra: ignored\n")
	if len(p.Problems) != 0 || p.Mode != "testing" || p.MaxAge != 86400 || !reflect.DeepEqual(p.MX, []string{"*.mail.example.com", "backup.example.com"}) {
		t.Errorf("parsed = %+v", p)
	}
	if p := parseSTS(strings.Repeat("a", 100)); len(p.Problems) == 0 || !strings.Contains(strings.Join(p.Problems, ";"), "...") {
		t.Errorf("long junk line must be shortened in the problem: %+v", p.Problems)
	}
}
