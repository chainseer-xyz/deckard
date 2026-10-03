package prowlerapp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest/prowlerapp"
	"github.com/chainseer-xyz/deckard/internal/ingest/prowlerapp/prowlerapptest"
)

const testKey = "pk-NEVER-PRINT-THIS-KEY-9d2c"

var clock = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

type sleeps struct{ d []time.Duration }

func (s *sleeps) sleep(_ context.Context, d time.Duration) error { s.d = append(s.d, d); return nil }

func newClient(t *testing.T, srv *prowlerapptest.Server, mod func(*prowlerapp.Config)) (*prowlerapp.Client, *sleeps) {
	t.Helper()
	sl := &sleeps{}
	cfg := prowlerapp.Config{BaseURL: srv.URL, APIKey: testKey, Now: func() time.Time { return clock }, Sleep: sl.sleep}
	if mod != nil {
		mod(&cfg)
	}
	c, err := prowlerapp.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, sl
}

func fiveProviders(srv *prowlerapptest.Server) {
	for i := 1; i <= 5; i++ {
		srv.Providers = append(srv.Providers, prowlerapptest.Provider{ID: fmt.Sprintf("p%d", i), Type: "aws", UID: fmt.Sprintf("12345678901%d", i), Connected: true})
	}
}

func TestAPIKeyAuthAndPagination(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	c, _ := newClient(t, srv, nil)
	ps, bad, err := c.Providers(context.Background())
	if err != nil || bad != 0 || len(ps) != 5 || ps[4].UID != "123456789015" {
		t.Fatalf("%+v %d %v", ps, bad, err)
	}
	if n := srv.Count("/api/v1/providers"); n != 3 {
		t.Fatalf("%d pages for 5 providers at 2 per page: %v", n, srv.Requests())
	}
	for _, h := range srv.Headers() {
		if h.Get("Authorization") != "Api-Key "+testKey || h.Get("Accept") != "application/vnd.api+json" {
			t.Fatalf("headers %v", h)
		}
	}
}

func TestJWTLoginPath(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.Email, srv.Password = "ops@example.com", "pw-NEVER-PRINT"
	fiveProviders(srv)
	c, err := prowlerapp.NewClient(prowlerapp.Config{BaseURL: srv.URL, Email: srv.Email, Password: srv.Password})
	if err != nil {
		t.Fatal(err)
	}
	if ps, _, err := c.Providers(context.Background()); err != nil || len(ps) != 5 {
		t.Fatalf("%d %v", len(ps), err)
	}
	if n := srv.Count("/api/v1/tokens"); n != 1 {
		t.Fatalf("logged in %d times", n)
	}
	hs := srv.Headers()
	if hs[0].Get("Authorization") != "" || hs[1].Get("Authorization") != "Bearer jwt-access-token" {
		t.Fatalf("login must be unauthenticated and later calls bearer: %v %v", hs[0], hs[1])
	}
}

func TestJWTIsRenewedOnceWhenItExpires(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.Email, srv.Password = "ops@example.com", "pw"
	fiveProviders(srv)
	srv.Intercept = func(r *http.Request, n int) *prowlerapptest.Reply {
		if r.URL.Path == "/api/v1/providers" && n == 2 {
			return &prowlerapptest.Reply{Status: 401, Body: `{"errors":[{"status":"401","code":"token_not_valid","detail":"expired"}]}`}
		}
		return nil
	}
	c, err := prowlerapp.NewClient(prowlerapp.Config{BaseURL: srv.URL, Email: srv.Email, Password: srv.Password})
	if err != nil {
		t.Fatal(err)
	}
	if ps, _, err := c.Providers(context.Background()); err != nil || len(ps) != 5 {
		t.Fatalf("%d %v", len(ps), err)
	}
	if srv.Count("/api/v1/tokens") != 2 {
		t.Fatalf("expected one re-login: %v", srv.Requests())
	}
}

func TestBadLoginAndBadKeyAreClearAndNeverEchoCredentials(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = "right-key"
	srv.EchoCredentials = true
	c, _ := newClient(t, srv, nil) // testKey is wrong
	_, _, err := c.Providers(context.Background())
	var he *prowlerapp.HTTPError
	if !errors.As(err, &he) || !he.Auth() || he.Status != 401 {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), testKey) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("credential in error: %v", err)
	}

	srv.Email, srv.Password = "ops@example.com", "pw"
	c2, err := prowlerapp.NewClient(prowlerapp.Config{BaseURL: srv.URL, Email: "ops@example.com", Password: "wrong-NEVER-PRINT"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c2.Providers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "wrong-NEVER-PRINT") {
		t.Fatalf("err %v", err)
	}
}

func TestRetryOn429And5xxHonoursRetryAfter(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	srv.Intercept = func(r *http.Request, n int) *prowlerapptest.Reply {
		switch n {
		case 1:
			return &prowlerapptest.Reply{Status: 429, Header: map[string]string{"Retry-After": "7"}, Body: `{"errors":[{"status":"429","code":"throttled","detail":"slow"}]}`}
		case 2:
			return &prowlerapptest.Reply{Status: 503, Body: "<html>busy</html>"}
		case 3:
			return &prowlerapptest.Reply{Status: 429, Header: map[string]string{"Retry-After": "86400"}}
		}
		return nil
	}
	c, sl := newClient(t, srv, nil)
	ps, _, err := c.Providers(context.Background())
	if err != nil || len(ps) != 5 {
		t.Fatalf("%d %v", len(ps), err)
	}
	// 7s as told, then the 2s backoff of the second attempt, then Retry-After
	// capped at a minute.
	want := []time.Duration{7 * time.Second, 2 * time.Second, time.Minute}
	if fmt.Sprint(sl.d) != fmt.Sprint(want) {
		t.Fatalf("sleeps %v want %v", sl.d, want)
	}
}

func TestRetryAfterHTTPDate(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	srv.Intercept = func(r *http.Request, n int) *prowlerapptest.Reply {
		if n == 1 {
			return &prowlerapptest.Reply{Status: 429, Header: map[string]string{"Retry-After": clock.Add(9 * time.Second).Format(http.TimeFormat)}}
		}
		return nil
	}
	c, sl := newClient(t, srv, nil)
	if _, _, err := c.Providers(context.Background()); err != nil || len(sl.d) != 1 || sl.d[0] != 9*time.Second {
		t.Fatalf("%v %v", sl.d, err)
	}
}

func TestPersistent5xxGivesUpAfterFourAttempts(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	srv.Intercept = func(*http.Request, int) *prowlerapptest.Reply {
		return &prowlerapptest.Reply{Status: 500, Body: `{"errors":[{"status":"500","code":"error","detail":"boom ` + testKey + `"}]}`}
	}
	c, sl := newClient(t, srv, nil)
	_, _, err := c.Providers(context.Background())
	var he *prowlerapp.HTTPError
	if !errors.As(err, &he) || he.Status != 500 || srv.Count("/api/v1/providers") != 4 || len(sl.d) != 3 {
		t.Fatalf("err %v requests %d sleeps %v", err, srv.Count("/api/v1/providers"), sl.d)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("key echoed by the server leaked: %v", err)
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	srv.Intercept = func(*http.Request, int) *prowlerapptest.Reply { return &prowlerapptest.Reply{Status: 404, Body: "{}"} }
	c, sl := newClient(t, srv, nil)
	if _, _, err := c.Providers(context.Background()); err == nil || srv.Count("/api/v1/providers") != 1 || len(sl.d) != 0 {
		t.Fatalf("err %v", err)
	}
}

func TestRequestBudget(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	c, _ := newClient(t, srv, func(c *prowlerapp.Config) { c.MaxRequests = 2 })
	_, _, err := c.Providers(context.Background())
	if !errors.Is(err, prowlerapp.ErrBudget) || c.Requests() != 2 {
		t.Fatalf("err %v after %d requests", err, c.Requests())
	}
}

func TestOversizeResponseIsRefused(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	c, _ := newClient(t, srv, func(c *prowlerapp.Config) { c.MaxResponseBytes = 300 })
	if _, _, err := c.Providers(context.Background()); !errors.Is(err, prowlerapp.ErrTooLarge) {
		t.Fatalf("err %v", err)
	}
}

func TestUndecodableResponseIsAnErrorWithoutTheBody(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	srv.Intercept = func(*http.Request, int) *prowlerapptest.Reply {
		return &prowlerapptest.Reply{Status: 200, Body: "<html>SENSITIVE-BODY</html>"}
	}
	c, _ := newClient(t, srv, nil)
	_, _, err := c.Providers(context.Background())
	if err == nil || strings.Contains(err.Error(), "SENSITIVE-BODY") {
		t.Fatalf("err %v", err)
	}
}

func TestPaginationLoopIsDetected(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	srv.Intercept = func(r *http.Request, n int) *prowlerapptest.Reply {
		self := "http://" + r.Host + r.URL.RequestURI()
		return &prowlerapptest.Reply{Status: 200, Body: `{"data":[],"links":{"next":"` + self + `"}}`}
	}
	c, _ := newClient(t, srv, nil)
	if _, _, err := c.Providers(context.Background()); err == nil || !strings.Contains(err.Error(), "loops") {
		t.Fatalf("err %v", err)
	}
}

func TestNextLinkNamingAnotherHostIsNeverContacted(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	srv.Intercept = func(r *http.Request, n int) *prowlerapptest.Reply {
		if n == 1 {
			return &prowlerapptest.Reply{Status: 200, Body: `{"data":[],"links":{"next":"https://evil.invalid/api/v1/providers?page%5Bnumber%5D=2"}}`}
		}
		return nil
	}
	c, _ := newClient(t, srv, nil)
	if _, _, err := c.Providers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.Count("/api/v1/providers") < 2 {
		t.Fatalf("the re-rooted link must hit the configured server: %v", srv.Requests())
	}
	srv.Intercept = func(r *http.Request, n int) *prowlerapptest.Reply {
		return &prowlerapptest.Reply{Status: 200, Body: `{"data":[],"links":{"next":"http://` + r.Host + `/admin/secrets"}}`}
	}
	c, _ = newClient(t, srv, nil)
	if _, _, err := c.Providers(context.Background()); err == nil || !strings.Contains(err.Error(), "does not point into the API") {
		t.Fatalf("err %v", err)
	}
}

func TestRedirects(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	srv.Intercept = func(r *http.Request, n int) *prowlerapptest.Reply {
		if r.URL.Path == "/api/v1/providers" && r.URL.Query().Get("moved") == "" {
			q := r.URL.Query()
			q.Set("moved", "1")
			return &prowlerapptest.Reply{Status: 302, Header: map[string]string{"Location": "/api/v1/providers?" + q.Encode()}}
		}
		return nil
	}
	c, _ := newClient(t, srv, nil)
	if ps, _, err := c.Providers(context.Background()); err != nil || len(ps) == 0 {
		t.Fatalf("same-origin redirect: %d %v", len(ps), err)
	}
	other := prowlerapptest.New(t)
	other.APIKey = testKey
	srv.Intercept = func(r *http.Request, n int) *prowlerapptest.Reply {
		return &prowlerapptest.Reply{Status: 302, Header: map[string]string{"Location": other.URL + "/api/v1/providers"}}
	}
	c, _ = newClient(t, srv, nil)
	_, _, err := c.Providers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "another origin") || len(other.Requests()) != 0 {
		t.Fatalf("cross-origin redirect followed: %v (%d requests reached the other host)", err, len(other.Requests()))
	}
}

func TestSecretsNeverReachTheLog(t *testing.T) {
	srv := prowlerapptest.New(t)
	srv.APIKey = testKey
	fiveProviders(srv)
	var log []string
	c, _ := newClient(t, srv, func(c *prowlerapp.Config) {
		c.Logf = func(f string, a ...any) { log = append(log, fmt.Sprintf(f, a...)) }
	})
	if _, _, err := c.Providers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(log) == 0 || strings.Contains(strings.Join(log, "\n"), testKey) {
		t.Fatalf("log: %v", log)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]prowlerapp.Config{
		"no url":            {APIKey: "k"},
		"not http":          {BaseURL: "ftp://h", APIKey: "k"},
		"credentials":       {BaseURL: "http://u:p@h", APIKey: "k"},
		"query":             {BaseURL: "http://h/?a=b", APIKey: "k"},
		"no credentials":    {BaseURL: "http://h"},
		"email only":        {BaseURL: "http://h", Email: "e"},
		"key and password":  {BaseURL: "http://h", APIKey: "k", Password: "p"},
		"key and email too": {BaseURL: "http://h", APIKey: "k", Email: "e", Password: "p"},
	} {
		if _, err := prowlerapp.NewClient(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for in, want := range map[string]string{
		"http://prowler-api.prowler.svc:8080":     "http://prowler-api.prowler.svc:8080",
		"https://prowler.example.com/":            "https://prowler.example.com",
		"https://prowler.example.com/api/v1/":     "https://prowler.example.com",
		"https://prowler.example.com/pr/api/v1":   "https://prowler.example.com/pr",
		"  http://prowler-api.prowler.svc:8080  ": "http://prowler-api.prowler.svc:8080",
	} {
		u, err := prowlerapp.ParseBaseURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%q: %v %v", in, u, err)
		}
	}
}
