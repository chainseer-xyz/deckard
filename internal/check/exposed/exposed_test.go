package exposed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func urlAsset(u string) model.Asset {
	return model.Asset{Kind: model.KindURL, Key: u, Scope: model.ScopeOwned}
}

func run(t *testing.T, h http.Handler, cfg map[string]any) (*check.Result, string) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	res, err := (&exposedCheck{}).Run(context.Background(), check.Target{Asset: urlAsset(srv.URL + "/some/page"), HTTP: srv.Client(), Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return res, srv.URL
}

func byKey(r *check.Result) map[string]model.FindingInput {
	m := map[string]model.FindingInput{}
	for _, f := range r.Findings {
		m[f.Key] = f
	}
	return m
}

func notFoundExcept(routes map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := routes[r.URL.Path]; ok {
			_, _ = fmt.Fprint(w, body)
			return
		}
		http.NotFound(w, r)
	})
}

const envBody = "# prod\nAPP_ENV=production\nDB_PASSWORD=hunter2-super-secret\nAWS_SECRET_ACCESS_KEY=abcd1234EXAMPLEsecretvalue\nPORT=8080\n"

func TestRealExposuresDetectedAndRedacted(t *testing.T) {
	res, _ := run(t, notFoundExcept(map[string]string{
		"/.git/HEAD":         "ref: refs/heads/main\n",
		"/.env":              envBody,
		"/wp-config.php.bak": "<?php\ndefine('DB_NAME', 'wp');\ndefine( \"DB_PASSWORD\", 'wp-secret-pass' );\n",
		"/backup.zip":        "PK\x03\x04" + strings.Repeat("x", 200000),
		"/metrics":           "# HELP up whether up\n# TYPE up gauge\nup 1\n",
		"/actuator/env":      `{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment","properties":{"DB_PASS":{"value":"s3cret"}}}]}`,
		"/backup/":           "<html><head><title>Index of /backup/</title></head><body><h1>Index of /backup/</h1></body></html>",
	}), nil)
	got := byKey(res)
	want := map[string]model.Severity{
		"/.git/HEAD": model.SeverityHigh, "/.env": model.SeverityCritical, "/wp-config.php.bak": model.SeverityCritical,
		"/backup.zip": model.SeverityHigh, "/metrics": model.SeverityLow, "/actuator/env": model.SeverityHigh, "/backup/": model.SeverityMedium,
	}
	for k, sev := range want {
		f, ok := got[k]
		if !ok || f.Severity != sev || f.Remediation == "" || f.Check != "http.exposed" {
			t.Errorf("%s: %+v", k, f)
		}
	}
	if len(got) != len(want) {
		t.Errorf("extra findings: %v", got)
	}
	if ev := got["/.git/HEAD"].Evidence; ev["ref"] != "refs/heads/main" {
		t.Errorf("evidence: %v", ev)
	}
	// secret values must never appear anywhere in findings or observations
	dump := fmt.Sprintf("%+v %+v", res.Findings, res.Observations)
	for _, secret := range []string{"hunter2", "abcd1234", "wp-secret-pass", "s3cret"} {
		if strings.Contains(dump, secret) {
			t.Errorf("secret %q leaked into results", secret)
		}
	}
	env := got["/.env"].Evidence
	if env["key_count"] != 4 || env["sensitive_key_count"] != 2 {
		t.Errorf("env evidence: %v", env)
	}
	if got["/backup.zip"].Evidence["size"].(int) > maxBodySize {
		t.Error("body not capped at 64 KiB")
	}
}

func TestSoft404SiteYieldsNothing(t *testing.T) {
	// Catch-all returns the same page with 200 for every path.
	res, _ := run(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<html><body>ref: refs/heads/main DB_NAME PK Index of /</body></html>")
	}), nil)
	if len(res.Findings) != 0 {
		t.Fatalf("soft-404 produced findings: %v", byKey(res))
	}
	if res.Observations[0].Data["soft_404"] != true {
		t.Error("soft_404 not recorded")
	}
}

func TestSPAWithVariableBodyRejectedByValidators(t *testing.T) {
	// Catch-all whose body differs per path (echoes it), so soft-404 hashing
	// cannot save us; content validation must.
	res, _ := run(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "<html><title>App</title><body>page for %s ref: refs/heads/x\nFOO=bar</body></html>", r.URL.Path)
	}), nil)
	if len(res.Findings) != 0 {
		t.Fatalf("false positives: %v", byKey(res))
	}
}

func TestValidatorFalsePositives(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		body     string
		wantHit  bool
		testFunc func(*response) (map[string]any, bool)
	}{
		{"git HEAD html", "/.git/HEAD", "<html>ref: refs/heads/main</html>", false, validateGitHead},
		{"git HEAD detached sha", "/.git/HEAD", "3f786850e387550fdab836ed7e6dc881de23001b\n", false, validateGitHead},
		{"git HEAD ok", "/.git/HEAD", "ref: refs/heads/feature/x\n", true, validateGitHead},
		{"env prose", "/.env", "Welcome to our site. Contact us today.\nThanks\n", false, validateEnv},
		{"env html", "/.env", "<html>A=b</html>", false, validateEnv},
		{"env ok", "/.env", "A=1\nB=2\n", true, validateEnv},
		{"env comments only", "/.env", "# nothing here\n", false, validateEnv},
		{"zip text", "/backup.zip", "not a zip", false, validateZip},
		{"swagger without paths", "/swagger.json", `{"swagger":"2.0"}`, false, validateSwagger},
		{"swagger ok", "/swagger.json", `{"openapi":"3.0.0","paths":{}}`, true, validateSwagger},
		{"health bad status", "/actuator/health", `{"status":"hello"}`, false, validateActuatorHealth},
		{"health ok", "/actuator/health", `{"status":"UP"}`, true, validateActuatorHealth},
		{"admin plain", "/admin", "<html><title>Home</title></html>", false, validateAdmin},
		{"admin ok", "/admin", "<html><title>Admin Login</title></html>", true, validateAdmin},
		{"svn ok", "/.svn/entries", "12\n\ndir\n0\n", true, validateSVN},
		{"svn html", "/.svn/entries", "<html>12\n\ndir\n</html>", false, validateSVN},
		{"ds_store ok", "/.DS_Store", "\x00\x00\x00\x01Bud1\x00\x00", true, validateDSStore},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := tc.testFunc(&response{body: []byte(tc.body)}); ok != tc.wantHit {
				t.Errorf("hit=%v want %v", ok, tc.wantHit)
			}
		})
	}
}

func TestRedirectToLoginIsNotAHit(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			_, _ = fmt.Fprint(w, "ref: refs/heads/main\n")
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	res, _ := run(t, h, nil)
	if len(res.Findings) != 0 {
		t.Fatalf("%v", byKey(res))
	}
}

func TestExcludePathsAndPoliteSequential(t *testing.T) {
	seen := map[string]int{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path]++ // sequential => no data race under -race
		if r.URL.Path == "/.env" || r.URL.Path == "/.git/HEAD" {
			_, _ = fmt.Fprint(w, "A=1\n")
			return
		}
		http.NotFound(w, r)
	})
	res, _ := run(t, h, map[string]any{"exclude_paths": []any{"/.env"}})
	if seen["/.env"] != 0 {
		t.Error("excluded path requested")
	}
	if len(res.Findings) != 0 {
		t.Errorf("%v", byKey(res))
	}
}

func TestSendsOnlyGET(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		http.NotFound(w, r)
	})
	run(t, h, nil)
}

func TestAppliesAndErrors(t *testing.T) {
	c := &exposedCheck{}
	if !c.Applies(urlAsset("https://a.example.com")) || c.Applies(model.Asset{Kind: model.KindHostname}) || c.Tier() != model.TierActive {
		t.Error("applies/tier")
	}
	if _, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://a.example.com")}); err == nil {
		t.Error("expected error without HTTP client")
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := c.Run(context.Background(), check.Target{Asset: urlAsset("ftp://x"), HTTP: srv.Client()}); err == nil {
		t.Error("expected bad url error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Run(ctx, check.Target{Asset: urlAsset(srv.URL), HTTP: srv.Client()}); err == nil {
		t.Error("expected ctx error")
	}
	if len(Checks(nil)) != 1 {
		t.Error("Checks")
	}
}

// A probe that failed or was throttled saw nothing: reading it as "not
// exposed" would count a miss and, once a WAF starts rate-limiting the scan,
// resolve an open exposure finding. Such runs must be partial.
func TestThrottledProbesMakeRunPartial(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		res, _ := run(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.env" {
				w.WriteHeader(status)
				return
			}
			http.NotFound(w, r)
		}), nil)
		if !res.Partial {
			t.Errorf("status %d on a probe: run reported complete", status)
		}
	}
	if res, _ := run(t, notFoundExcept(nil), nil); res.Partial {
		t.Error("clean site reported partial")
	}
}
