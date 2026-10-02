package takeover

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestEmbeddedDBLoads(t *testing.T) {
	fps := Default()
	if len(fps) < 20 {
		t.Fatalf("expected a full DB, got %d", len(fps))
	}
}

func TestMatchCNAME(t *testing.T) {
	fps := Default()
	cases := map[string]string{
		"bucket.s3-website-us-east-1.amazonaws.com": "AWS S3 website bucket",
		"bucket.s3-website.eu-west-1.amazonaws.com": "AWS S3 website bucket",
		"d111.cloudfront.net":                       "AWS CloudFront",
		"user.github.io":                            "GitHub Pages",
		"my-env.us-east-1.elasticbeanstalk.com":     "AWS Elastic Beanstalk",
		"app.azurewebsites.net":                     "Azure App Service",
		"x.trafficmanager.net":                      "Azure Traffic Manager",
		"shop.myshopify.com":                        "Shopify",
		"foo.herokuapp.com":                         "Heroku",
		"www.example.net":                           "",
		"evilgithub.io.example.net":                 "",
	}
	for target, want := range cases {
		got := MatchCNAME(fps, target)
		switch {
		case want == "" && got != nil:
			t.Errorf("%s: unexpected match %s", target, got.Provider)
		case want != "" && (got == nil || got.Provider != want):
			t.Errorf("%s: got %+v want %s", target, got, want)
		}
	}
}

func TestLoadValidation(t *testing.T) {
	bad := []string{
		"- provider: X\n  cname: ['(']\n  fingerprint: [a]\n  status: vulnerable\n",
		"- provider: X\n  cname: ['a$']\n  status: vulnerable\n",
		"- provider: X\n  cname: ['a$']\n  fingerprint: [a]\n  status: nope\n",
		"- cname: ['a$']\n  fingerprint: [a]\n  status: vulnerable\n",
	}
	for i, b := range bad {
		if _, err := Load([]byte(b)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func server(body string, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestRunBodyFingerprintMatch(t *testing.T) {
	srv := server("<h1>There isn't a GitHub Pages site here.</h1>", 404)
	defer srv.Close()
	r := &checktest.Resolver{CNAMEs: map[string]string{"docs.example.com": "acme.github.io"}}
	tg := checktest.NewTarget(checktest.Hostname("docs.example.com", "example.com"),
		checktest.WithResolver(r),
		checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{"docs.example.com:80": srv})))
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings: %+v obs=%+v", res.Findings, res.Observations)
	}
	f := res.Findings[0]
	// No HTTPS confirmation is possible (no dialer): edge-case providers cap at medium.
	if f.Title != "possible subdomain takeover via GitHub Pages" || f.Severity != model.SeverityMedium || f.Key != "takeover:github-pages" {
		t.Errorf("finding: %+v", f)
	}
	// Only the owned hostname may be contacted; no resolution of the provider host over HTTP.
	for _, c := range r.Calls {
		if c == "host acme.github.io" {
			t.Errorf("provider host must not even be resolved for body-fingerprint providers: %v", r.Calls)
		}
	}
}

func TestRunBodyNoMatch(t *testing.T) {
	srv := server("welcome to my site", 200)
	defer srv.Close()
	r := &checktest.Resolver{CNAMEs: map[string]string{"docs.example.com": "acme.github.io"}}
	tg := checktest.NewTarget(checktest.Hostname("docs.example.com", "example.com"),
		checktest.WithResolver(r),
		checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{"docs.example.com:80": srv})))
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 0 {
		t.Errorf("unexpected: %+v", res.Findings)
	}
}

func TestRunNXDomainProvider(t *testing.T) {
	r := &checktest.Resolver{CNAMEs: map[string]string{"app.example.com": "gone.azurewebsites.net"}}
	tg := checktest.NewTarget(checktest.Hostname("app.example.com", "example.com"), checktest.WithResolver(r))
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 1 || res.Findings[0].Severity != model.SeverityCritical {
		t.Fatalf("findings: %+v", res.Findings)
	}
	r.Hosts = map[string][]string{"gone.azurewebsites.net": {"203.0.113.5"}}
	res, _ = New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 0 {
		t.Errorf("resolving target is not a takeover: %+v", res.Findings)
	}
}

func TestRunSkipsOwnedAndUnknownTargets(t *testing.T) {
	r := &checktest.Resolver{CNAMEs: map[string]string{
		"a.example.com": "b.example.com", "c.example.com": "x.example.net",
	}}
	for _, h := range []string{"a.example.com", "c.example.com", "plain.example.com"} {
		res, err := New(nil).Run(context.Background(), checktest.NewTarget(checktest.Hostname(h, "example.com"), checktest.WithResolver(r)))
		if err != nil || len(res.Findings) != 0 {
			t.Errorf("%s: %+v %v", h, res, err)
		}
	}
}

const cloudfrontBody = "<h1>ERROR: The request could not be satisfied</h1>"

// tlsScenario wires an owned host: HTTP body on :80 and a TLS listener on :443
// presenting a certificate with the given SANs, issued by a test CA.
func tlsScenario(t *testing.T, host, cname, body string, sans []string) (*Check, check.Target) {
	t.Helper()
	ca := checktest.NewCA(t)
	cert, _ := ca.Issue(t, checktest.CertSpec{DNSNames: sans, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)})
	addr := checktest.ServeTLS(t, cert)
	srv := server(body, 403)
	t.Cleanup(srv.Close)
	r := &checktest.Resolver{CNAMEs: map[string]string{host: cname}}
	tg := checktest.NewTarget(checktest.Hostname(host, "example.com"),
		checktest.WithResolver(r),
		checktest.WithDialer(&checktest.Dialer{Routes: map[string]string{host + ":443": addr}}),
		checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{host + ":80": srv})))
	c := New(nil)
	c.roots = ca.Pool
	return c, tg
}

func TestRunValidCertForHostSuppressed(t *testing.T) {
	c, tg := tlsScenario(t, "mml.example.com", "d111.cloudfront.net", cloudfrontBody, []string{"mml.example.com"})
	res, err := c.Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("valid certificate for the host means the distribution has the alias: %+v", res.Findings)
	}
	if got := res.Observations[len(res.Observations)-1].Data["takeover_suppressed"]; got != "valid_cert_for_host" {
		t.Errorf("observation: %+v", res.Observations)
	}
}

func TestRunProviderDefaultCertConfirms(t *testing.T) {
	c, tg := tlsScenario(t, "assets.example.com", "d111.cloudfront.net", cloudfrontBody, []string{"*.cloudfront.net", "cloudfront.net"})
	res, _ := c.Run(context.Background(), tg)
	if len(res.Findings) != 1 {
		t.Fatalf("findings: %+v obs=%+v", res.Findings, res.Observations)
	}
	f := res.Findings[0]
	if f.Severity != model.SeverityHigh || f.Evidence["https_cert"] != "provider_default" {
		t.Errorf("want high + provider_default, got %s %+v", f.Severity, f.Evidence)
	}
}

func TestRunOtherMismatchedCertDoesNotSuppress(t *testing.T) {
	c, tg := tlsScenario(t, "assets.example.com", "d111.cloudfront.net", cloudfrontBody, []string{"unrelated.example.net"})
	res, _ := c.Run(context.Background(), tg)
	if len(res.Findings) != 1 || res.Findings[0].Evidence["https_cert"] == "valid_for_host" {
		t.Fatalf("findings: %+v", res.Findings)
	}
}

func TestRunHTTPOnlyEdgeCaseUnconfirmedIsMedium(t *testing.T) {
	srv := server(cloudfrontBody, 403)
	defer srv.Close()
	r := &checktest.Resolver{CNAMEs: map[string]string{"assets.example.com": "d111.cloudfront.net"}}
	tg := checktest.NewTarget(checktest.Hostname("assets.example.com", "example.com"), checktest.WithResolver(r),
		checktest.WithDialer(&checktest.Dialer{}), // no :443 route -> handshake fails
		checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{"assets.example.com:80": srv})))
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 1 {
		t.Fatalf("%+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != model.SeverityMedium || f.Evidence["https_cert"] != "unavailable" || !strings.Contains(f.Description, "unconfirmed") {
		t.Errorf("%s %+v %s", f.Severity, f.Evidence, f.Description)
	}
}

func TestRunVulnerableProviderWithoutTLSStaysCritical(t *testing.T) {
	srv := server("Fastly error: unknown domain: assets.example.com", 500)
	defer srv.Close()
	r := &checktest.Resolver{CNAMEs: map[string]string{"assets.example.com": "x.fastly.net"}}
	tg := checktest.NewTarget(checktest.Hostname("assets.example.com", "example.com"), checktest.WithResolver(r),
		checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{"assets.example.com:80": srv})))
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 1 || res.Findings[0].Severity != model.SeverityCritical {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestDefaultCertMatching(t *testing.T) {
	fp := MatchCNAME(Default(), "d1.cloudfront.net")
	if fp == nil {
		t.Fatal("no fp")
	}
	ca := checktest.NewCA(t)
	mk := func(sans ...string) *x509.Certificate {
		_, l := ca.Issue(t, checktest.CertSpec{DNSNames: sans, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
		return l
	}
	if !fp.IsDefaultCert(mk("*.cloudfront.net", "cloudfront.net")) {
		t.Error("provider wildcard should be default")
	}
	if fp.IsDefaultCert(mk("*.cloudfront.net", "mine.example.com")) {
		t.Error("mixed SANs are not the provider default")
	}
	if fp.IsDefaultCert(mk("evilcloudfront.net")) {
		t.Error("suffix must be label-aligned")
	}
	for _, p := range Default() {
		for _, d := range p.DefaultCert {
			if strings.Contains(d, "*") || strings.HasPrefix(d, ".") {
				t.Errorf("%s: default_cert entries are bare domains, got %q", p.Provider, d)
			}
		}
	}
}
