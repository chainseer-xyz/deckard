package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func keys(fs []model.FindingInput) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		m[f.Key] = f.Severity
	}
	return m
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestAnalyze(t *testing.T) {
	cfg := Config{Required: DefaultRequired, HSTSMinAge: 15552000}
	good := []string{
		"Strict-Transport-Security", "max-age=31536000", "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'",
		"X-Content-Type-Options", "nosniff", "Referrer-Policy", "no-referrer",
	}
	cases := []struct {
		name  string
		https bool
		h     http.Header
		want  map[string]model.Severity
	}{
		{"all good", true, hdr(good...), map[string]model.Severity{}},
		{"nothing https", true, hdr(), map[string]model.Severity{
			"missing-hsts": model.SeverityLow, "missing-csp": model.SeverityLow, "missing-x-content-type-options": model.SeverityLow,
			"missing-frame-protection": model.SeverityLow, "missing-referrer-policy": model.SeverityInfo}},
		{"nothing http (no hsts)", false, hdr(), map[string]model.Severity{
			"missing-csp": model.SeverityLow, "missing-x-content-type-options": model.SeverityLow,
			"missing-frame-protection": model.SeverityLow, "missing-referrer-policy": model.SeverityInfo}},
		{"xfo satisfies frame", true, hdr(append(good[:2:2], "X-Frame-Options", "DENY", "Content-Security-Policy", "default-src 'self'",
			"X-Content-Type-Options", "nosniff", "Referrer-Policy", "no-referrer")...), map[string]model.Severity{}},
		{"weak hsts", true, hdr(append([]string{}, good...)...), map[string]model.Severity{}},
		{"banner", true, hdr(append([]string{"Server", "nginx/1.18.0", "X-Powered-By", "Express"}, good...)...),
			map[string]model.Severity{"banner-disclosure": model.SeverityInfo}},
		{"generic server ok", true, hdr(append([]string{"Server", "nginx"}, good...)...), map[string]model.Severity{}},
		{"cors wildcard", true, hdr(append([]string{"Access-Control-Allow-Origin", "*", "Access-Control-Allow-Credentials", "true"}, good...)...),
			map[string]model.Severity{"cors-wildcard-credentials": model.SeverityMedium}},
		{"cors wildcard no creds", true, hdr(append([]string{"Access-Control-Allow-Origin", "*"}, good...)...), map[string]model.Severity{}},
		{"cors reflected", true, hdr(append([]string{"Access-Control-Allow-Origin", CORSProbeOrigin, "Access-Control-Allow-Credentials", "true"}, good...)...),
			map[string]model.Severity{"cors-reflected-origin": model.SeverityMedium}},
		{"cookies", true, hdr(append([]string{
			"Set-Cookie", "session=abc; Path=/",
			"Set-Cookie", "PHPSESSID=x; Secure; HttpOnly; SameSite=Lax",
			"Set-Cookie", "theme=dark",
			"Set-Cookie", "auth_token=y; Secure; HttpOnly",
		}, good...)...), map[string]model.Severity{"cookie:session": model.SeverityMedium, "cookie:auth_token": model.SeverityLow}},
	}
	for _, c := range cases {
		got := keys(Analyze(Input{URL: "https://app.example.com/", HTTPS: c.https, Header: c.h}, cfg))
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s = %q want %q", c.name, k, got[k], v)
			}
		}
	}
	// Weak HSTS.
	h := hdr(append([]string{"Strict-Transport-Security", "max-age=300"}, good[2:]...)...)
	if got := keys(Analyze(Input{URL: "https://x/", HTTPS: true, Header: h}, cfg)); got["weak-hsts"] != model.SeverityLow {
		t.Errorf("weak hsts: %v", got)
	}
}

func TestConfigurableRequiredList(t *testing.T) {
	got := keys(Analyze(Input{URL: "https://x/", HTTPS: true, Header: hdr()}, Config{Required: []string{"csp"}}))
	if len(got) != 1 || got["missing-csp"] == "" {
		t.Errorf("%v", got)
	}
}

func TestCookieFindingEvidenceHasNoValue(t *testing.T) {
	fs := Analyze(Input{URL: "https://x/", HTTPS: true, Header: hdr("Set-Cookie", "session=SUPERSECRET")}, Config{})
	for _, f := range fs {
		for _, v := range f.Evidence {
			if s, ok := v.(string); ok && s == "SUPERSECRET" {
				t.Error("cookie value leaked into evidence")
			}
		}
	}
}

func fetchTarget(t *testing.T, scheme string, h http.HandlerFunc) (model.Asset, *http.Client) {
	t.Helper()
	var srv *httptest.Server
	port := "80"
	if scheme == "https" {
		srv, port = httptest.NewTLSServer(h), "443"
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	a := model.Asset{Kind: model.KindURL, Key: scheme + "://app.example.com/", Zone: "example.com", Scope: model.ScopeOwned}
	return a, checktest.HostClient(map[string]*httptest.Server{"app.example.com:" + port: srv})
}

func TestRunHTTPSSendsProbeOriginAndFindsCORS(t *testing.T) {
	a, c := fetchTarget(t, "https", func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
	})
	res, err := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(res.Findings); got["cors-reflected-origin"] == "" || got["missing-hsts"] != "" {
		t.Errorf("findings: %v", got)
	}
}

func TestRunHTTPNoRedirect(t *testing.T) {
	a, c := fetchTarget(t, "http", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hi")) })
	res, _ := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
	if got := keys(res.Findings); got["no-https-redirect"] != model.SeverityLow {
		t.Errorf("findings: %v", got)
	}
}

func TestRunHTTPRedirectsToHTTPSIsClean(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("secure")) }))
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://app.example.com/", http.StatusMovedPermanently)
	}))
	defer tlsSrv.Close()
	defer plain.Close()
	c := checktest.HostClient(map[string]*httptest.Server{"app.example.com:443": tlsSrv, "app.example.com:80": plain})
	a := model.Asset{Kind: model.KindURL, Key: "http://app.example.com/", Zone: "example.com", Scope: model.ScopeOwned}
	res, _ := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
	if len(res.Findings) != 0 {
		t.Errorf("redirecting http must be clean (https URL asset is judged separately): %v", keys(res.Findings))
	}
}

func TestRunUnreachable(t *testing.T) {
	a := model.Asset{Kind: model.KindURL, Key: "https://app.example.com/", Scope: model.ScopeOwned}
	res, err := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(checktest.HostClient(nil))))
	if err != nil || len(res.Findings) != 0 || res.Observations[0].Data["error"] == nil {
		t.Errorf("%+v %v", res, err)
	}
}

func TestApplies(t *testing.T) {
	c := New(nil)
	if !c.Applies(model.Asset{Kind: model.KindURL, Scope: model.ScopeOwned}) || c.Applies(model.Asset{Kind: model.KindHostname, Scope: model.ScopeOwned}) {
		t.Error("Applies")
	}
}
