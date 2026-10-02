package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestHTTPURLOnlyEvaluatedForRedirect(t *testing.T) {
	// Plain-HTTP 200 without security headers: only no-https-redirect; the
	// header set is judged on the https URL so it is not reported twice.
	a, c := fetchTarget(t, "http", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte("<html>hi</html>"))
	})
	res, _ := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
	got := keys(res.Findings)
	if len(got) != 1 || got["no-https-redirect"] != model.SeverityLow {
		t.Errorf("http URL findings: %v", got)
	}
}

func TestHTTPSURLStillEvaluated(t *testing.T) {
	a, c := fetchTarget(t, "https", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>hi</html>")) })
	res, _ := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
	if got := keys(res.Findings); got["missing-csp"] == "" || got["missing-hsts"] == "" {
		t.Errorf("https URL must keep header findings: %v", got)
	}
}

func TestRedirectResponsesSkipHeaderChecks(t *testing.T) {
	// A final 3xx (redirect not followed) carries no content to protect.
	a, _ := fetchTarget(t, "https", func(w http.ResponseWriter, r *http.Request) {})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	c := checktest.HostClient(map[string]*httptest.Server{"app.example.com:443": srv})
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, _ := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
	if len(res.Findings) != 0 {
		t.Errorf("3xx must not produce header findings: %v", keys(res.Findings))
	}
}

func TestErrorPagesStillEvaluated(t *testing.T) {
	a, c := fetchTarget(t, "https", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>no</html>"))
	})
	res, _ := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
	if got := keys(res.Findings); got["missing-csp"] == "" {
		t.Errorf("4xx HTML keeps header findings: %v", got)
	}
}

func TestMinSeverity(t *testing.T) {
	a, c := fetchTarget(t, "https", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte("<html>hi</html>"))
	})
	run := func(cfg map[string]any) map[string]model.Severity {
		res, _ := New(cfg).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
		return keys(res.Findings)
	}
	if got := run(nil); got["missing-referrer-policy"] != model.SeverityInfo || got["missing-csp"] == "" {
		t.Errorf("default shows info: %v", got)
	}
	got := run(map[string]any{"min_severity": "low"})
	if got["missing-referrer-policy"] != "" || got["banner-disclosure"] != "" || got["missing-csp"] != model.SeverityLow {
		t.Errorf("min_severity=low: %v", got)
	}
	if got := run(map[string]any{"min_severity": "medium"}); len(got) != 0 {
		t.Errorf("min_severity=medium: %v", got)
	}
}
