package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/config"
)

var testSecret = strings.Repeat("k", 40)

// fakeIdP is an in-process OIDC provider that enforces PKCE S256.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu sync.Mutex
	// per-code state
	codes map[string]codeInfo
	// behaviours
	claims      map[string]any // extra claims merged into the id_token
	overrideNon string         // when set, id_token carries this nonce
	audience    string
}

type codeInfo struct{ challenge, nonce string }

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, codes: map[string]codeInfo{}, audience: "deckard-client",
		claims: map[string]any{"sub": "u-1", "email": "ada@example.com", "email_verified": true, "name": "Ada", "groups": []string{"sec", "other"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	ci, ok := f.codes[r.Form.Get("code")]
	delete(f.codes, r.Form.Get("code"))
	f.mu.Unlock()
	if !ok {
		http.Error(w, `{"error":"invalid_grant"}`, 400)
		return
	}
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ci.challenge {
		http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, 400)
		return
	}
	nonce := ci.nonce
	if f.overrideNon != "" {
		nonce = f.overrideNon
	}
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	cl := map[string]any{"iss": f.srv.URL, "aud": f.audience, "iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(), "nonce": nonce}
	for k, v := range f.claims {
		cl[k] = v
	}
	raw, err := jwt.Signed(sig).Claims(cl).Serialize()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
}

// authorize plays the browser+IdP: validates the redirect and mints a code.
func (f *fakeIdP) authorize(t *testing.T, loc string) (code, state string) {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, f.srv.URL+"/authorize") {
		t.Fatalf("bad authorize redirect %q", loc)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("PKCE S256 not requested: %v", q)
	}
	if q.Get("response_type") != "code" || q.Get("client_id") != "deckard-client" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatalf("missing params: %v", q)
	}
	code = "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.codes[code] = codeInfo{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	f.mu.Unlock()
	return code, q.Get("state")
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	idp   *fakeIdP
	oidc  *auth.OIDC
	h     http.Handler
	clock *fakeClock
}

func newRig(t *testing.T, mutate func(*config.OIDCConfig, *auth.Options)) *rig {
	t.Helper()
	idp := newIdP(t)
	clock := &fakeClock{t: time.Now()}
	cfg := config.OIDCConfig{Issuer: idp.srv.URL, ClientID: "deckard-client", ClientSecretEnv: "CS", AllowedGroups: []string{"sec"}}
	opts := auth.Options{
		BaseURL: "https://deckard.example.com", Clock: clock,
		Getenv: func(k string) string {
			return map[string]string{"DECKARD_SESSION_SECRET": testSecret, "CS": "client-secret"}[k]
		},
	}
	if mutate != nil {
		mutate(&cfg, &opts)
	}
	o, err := auth.NewOIDC(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	o.Mount(r)
	return &rig{idp: idp, oidc: o, h: r, clock: clock}
}

func (g *rig) do(method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, req)
	return rec
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// login performs /auth/login and returns tx cookie + code + state.
func (g *rig) login(t *testing.T, next string) (tx *http.Cookie, code, state string) {
	t.Helper()
	rec := g.do("GET", "/auth/login?next="+url.QueryEscape(next))
	if rec.Code != 302 {
		t.Fatalf("login = %d %s", rec.Code, rec.Body)
	}
	tx = cookieNamed(rec, "__Secure-deckard_oidc_tx")
	if tx == nil || !tx.HttpOnly || !tx.Secure || tx.SameSite != http.SameSiteLaxMode {
		t.Fatalf("bad tx cookie: %+v", tx)
	}
	code, state = g.idp.authorize(t, rec.Header().Get("Location"))
	return
}

func (g *rig) fullLogin(t *testing.T) *http.Cookie {
	t.Helper()
	tx, code, state := g.login(t, "/findings")
	rec := g.do("GET", "/auth/callback?code="+code+"&state="+state, tx)
	if rec.Code != 302 || rec.Header().Get("Location") != "/findings" {
		t.Fatalf("callback = %d loc=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	s := cookieNamed(rec, "__Host-deckard_session")
	if s == nil {
		t.Fatal("no session cookie")
	}
	return s
}

func TestOIDCActorRequiresVerifiedEmail(t *testing.T) {
	for name, tc := range map[string]struct {
		verified any // nil = claim absent
		want     func(iss string) string
	}{
		"verified bool":     {true, func(string) string { return "ada@example.com" }},
		"verified string":   {"true", func(string) string { return "ada@example.com" }},
		"unverified":        {false, func(iss string) string { return "u-1 (iss " + iss + ")" }},
		"claim absent":      {nil, func(iss string) string { return "u-1 (iss " + iss + ")" }},
		"garbage claim":     {"yes please", func(iss string) string { return "u-1 (iss " + iss + ")" }},
		"unverified string": {"false", func(iss string) string { return "u-1 (iss " + iss + ")" }},
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, nil)
			if tc.verified == nil {
				delete(g.idp.claims, "email_verified")
			} else {
				g.idp.claims["email_verified"] = tc.verified
			}
			s := g.fullLogin(t)
			req := httptest.NewRequest("GET", "/api/v1/me", nil)
			req.AddCookie(s)
			id, err := g.oidc.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := id.Actor(), tc.want(g.idp.srv.URL); got != want {
				t.Errorf("Actor = %q, want %q", got, want)
			}
		})
	}
}

func TestOIDCFullFlow(t *testing.T) {
	g := newRig(t, nil)
	s := g.fullLogin(t)
	if !s.HttpOnly || !s.Secure || s.SameSite != http.SameSiteLaxMode || s.MaxAge <= 0 || s.MaxAge > 24*3600 {
		t.Errorf("session cookie attrs wrong: %+v", s)
	}
	if strings.Contains(s.Value, "ada@example.com") || strings.Contains(s.Value, "u-1") {
		t.Error("session cookie must be encrypted, not merely signed")
	}
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.AddCookie(s)
	id, err := g.oidc.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "u-1" || id.Email != "ada@example.com" || id.Method != auth.MethodCookie || id.CSRFToken == "" ||
		len(id.Groups) != 1 || id.Groups[0] != "sec" || id.Actor() != "ada@example.com" {
		t.Errorf("identity = %+v", id)
	}
}

func TestOIDCTxCookieIsSingleUse(t *testing.T) {
	g := newRig(t, nil)
	tx, code, state := g.login(t, "/")
	rec := g.do("GET", "/auth/callback?code="+code+"&state="+state, tx)
	if c := cookieNamed(rec, "__Secure-deckard_oidc_tx"); c == nil || c.MaxAge >= 0 {
		t.Errorf("tx cookie not cleared: %+v", c)
	}
}

func TestOIDCCallbackFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(g *rig, tx *http.Cookie, code, state string) (target string, cookies []*http.Cookie)
		want   int
	}{
		{"state mismatch", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			return "/auth/callback?code=" + code + "&state=attacker", []*http.Cookie{tx}
		}, 400},
		{"missing state", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			return "/auth/callback?code=" + code, []*http.Cookie{tx}
		}, 400},
		{"no tx cookie", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			return "/auth/callback?code=" + code + "&state=" + state, nil
		}, 400},
		{"tampered tx cookie", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			c := *tx
			c.Value = flip(c.Value)
			return "/auth/callback?code=" + code + "&state=" + state, []*http.Cookie{&c}
		}, 400},
		{"expired tx", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			g.clock.Advance(11 * time.Minute)
			return "/auth/callback?code=" + code + "&state=" + state, []*http.Cookie{tx}
		}, 400},
		{"missing code", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			return "/auth/callback?state=" + state, []*http.Cookie{tx}
		}, 400},
		{"idp error", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			return "/auth/callback?error=access_denied&state=" + state, []*http.Cookie{tx}
		}, 403},
		{"bad code", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			return "/auth/callback?code=nope&state=" + state, []*http.Cookie{tx}
		}, 502},
		{"nonce mismatch", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			g.idp.overrideNon = "replayed"
			return "/auth/callback?code=" + code + "&state=" + state, []*http.Cookie{tx}
		}, 401},
		{"wrong audience", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			g.idp.audience = "someone-else"
			return "/auth/callback?code=" + code + "&state=" + state, []*http.Cookie{tx}
		}, 401},
		{"group denied", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			g.idp.claims["groups"] = []string{"interns"}
			return "/auth/callback?code=" + code + "&state=" + state, []*http.Cookie{tx}
		}, 403},
		{"no groups claim", func(g *rig, tx *http.Cookie, code, state string) (string, []*http.Cookie) {
			delete(g.idp.claims, "groups")
			return "/auth/callback?code=" + code + "&state=" + state, []*http.Cookie{tx}
		}, 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newRig(t, nil)
			tx, code, state := g.login(t, "/")
			target, cookies := tt.mutate(g, tx, code, state)
			rec := g.do("GET", target, cookies...)
			if rec.Code != tt.want {
				t.Fatalf("status %d want %d body=%s", rec.Code, tt.want, rec.Body)
			}
			if cookieNamed(rec, "__Host-deckard_session") != nil {
				t.Error("session cookie must not be issued on failure")
			}
			var e struct {
				Error struct{ Code, Message string }
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Error.Code == "" {
				t.Errorf("error body not JSON envelope: %s", rec.Body)
			}
		})
	}
}

func flip(s string) string {
	b := []byte(s)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func TestOIDCGroupClaimVariants(t *testing.T) {
	tests := []struct {
		name   string
		claim  string
		claims map[string]any
		allow  []string
		ok     bool
	}{
		{"custom claim list", "roles", map[string]any{"roles": []string{"sec"}}, []string{"sec"}, true},
		{"string claim", "groups", map[string]any{"groups": "sec"}, []string{"sec"}, true},
		{"no allowlist admits anyone", "groups", map[string]any{}, nil, true},
		{"default claim ignored when custom set", "roles", map[string]any{"groups": []string{"sec"}}, []string{"sec"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newRig(t, func(c *config.OIDCConfig, _ *auth.Options) { c.GroupsClaim = tt.claim; c.AllowedGroups = tt.allow })
			g.idp.claims = map[string]any{"sub": "u"}
			for k, v := range tt.claims {
				g.idp.claims[k] = v
			}
			tx, code, state := g.login(t, "/")
			rec := g.do("GET", "/auth/callback?code="+code+"&state="+state, tx)
			if got := rec.Code == 302; got != tt.ok {
				t.Fatalf("ok=%v want %v (%d %s)", got, tt.ok, rec.Code, rec.Body)
			}
		})
	}
}

func TestOIDCSessionExpiryAndTamper(t *testing.T) {
	g := newRig(t, func(_ *config.OIDCConfig, o *auth.Options) { o.SessionTTL = time.Hour })
	s := g.fullLogin(t)
	authn := func(c *http.Cookie) error {
		req := httptest.NewRequest("GET", "/", nil)
		if c != nil {
			req.AddCookie(c)
		}
		_, err := g.oidc.Authenticate(req)
		return err
	}
	if err := authn(s); err != nil {
		t.Fatalf("fresh session: %v", err)
	}
	tampered := *s
	tampered.Value = flip(s.Value)
	if err := authn(&tampered); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("tampered cookie accepted: %v", err)
	}
	if err := authn(&http.Cookie{Name: "__Host-deckard_session", Value: "garbage"}); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("garbage cookie accepted: %v", err)
	}
	if err := authn(nil); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("no cookie accepted: %v", err)
	}
	g.clock.Advance(61 * time.Minute)
	if err := authn(s); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("expired session accepted: %v", err)
	}
}

func TestOIDCTxCookieCannotBeUsedAsSession(t *testing.T) {
	g := newRig(t, nil)
	tx, _, _ := g.login(t, "/")
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-deckard_session", Value: tx.Value})
	if _, err := g.oidc.Authenticate(req); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("cross-cookie replay accepted: %v", err)
	}
}

func TestOIDCSessionFromOtherSecretRejected(t *testing.T) {
	a := newRig(t, nil)
	s := a.fullLogin(t)
	b := newRig(t, func(_ *config.OIDCConfig, o *auth.Options) {
		o.Getenv = func(k string) string {
			return map[string]string{"DECKARD_SESSION_SECRET": strings.Repeat("z", 40)}[k]
		}
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(s)
	if _, err := b.oidc.Authenticate(req); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("session accepted under a different secret: %v", err)
	}
}

func TestOIDCLogoutIsPostOnlyAndCSRFProtected(t *testing.T) {
	g := newRig(t, nil)
	s := g.fullLogin(t)

	if rec := g.do("GET", "/auth/logout", s); rec.Code != 405 {
		t.Errorf("GET logout = %d, want 405 (a cross-site GET must not end the session)", rec.Code)
	}

	post := func(csrf string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/auth/logout", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		rec := httptest.NewRecorder()
		g.h.ServeHTTP(rec, req)
		return rec
	}
	if rec := post("", s); rec.Code != 403 || cookieNamed(rec, "__Host-deckard_session") != nil {
		t.Errorf("logout without CSRF token = %d, must be refused", rec.Code)
	}
	if rec := post("wrong", s); rec.Code != 403 {
		t.Errorf("logout with wrong CSRF token = %d", rec.Code)
	}

	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.AddCookie(s)
	id, err := g.oidc.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := post(id.CSRFToken, s)
	if rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Errorf("logout = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if c := cookieNamed(rec, "__Host-deckard_session"); c == nil || c.MaxAge >= 0 {
		t.Errorf("logout did not clear cookie: %+v", c)
	}
	// Without a session there is nothing to forge; clearing is harmless.
	if rec := post(""); rec.Code != 303 {
		t.Errorf("sessionless logout = %d", rec.Code)
	}
}

func TestOIDCCookiePrefixFollowsScheme(t *testing.T) {
	g := newRig(t, nil)
	s := g.fullLogin(t)
	if s.Name != "__Host-deckard_session" || s.Path != "/" || !s.Secure || s.Domain != "" {
		t.Errorf("https session cookie violates __Host- rules: %+v", s)
	}
	h := newRig(t, func(_ *config.OIDCConfig, o *auth.Options) { o.BaseURL = "http://localhost:8080" })
	rec := h.do("GET", "/auth/login")
	if cookieNamed(rec, "deckard_oidc_tx") == nil {
		t.Errorf("http base URL must use unprefixed cookies (browsers reject prefixes without Secure): %v", rec.Result().Cookies())
	}
}

func TestOIDCEmptyAllowedGroupsWarnsLoudly(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	newRig(t, func(c *config.OIDCConfig, o *auth.Options) { c.AllowedGroups = nil; o.Logger = log })
	if out := buf.String(); !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, "allowed_groups") {
		t.Errorf("no loud warning for empty allowed_groups: %q", out)
	}
	buf.Reset()
	newRig(t, func(c *config.OIDCConfig, o *auth.Options) { o.Logger = log })
	if strings.Contains(buf.String(), "allowed_groups") {
		t.Errorf("unexpected warning with groups configured: %q", buf.String())
	}
}

func TestOIDCNextSanitised(t *testing.T) {
	for next, want := range map[string]string{
		"/findings?x=1":         "/findings?x=1",
		"//evil.com":            "/",
		"https://evil.io":       "/",
		"/\\evil.com":           "/",
		"":                      "/",
		"/a\r\nSet-Cookie: x=y": "/",
		"/\t/evil.com":          "/",
		"/\n/evil.com":          "/",
		"/\x00/evil.com":        "/",
		"/\x7f/evil.com":        "/",
		"/%09/evil.com":         "/",
		"/%0a/evil.com":         "/",
		"/%2f/evil.com":         "/",
		"/%5cevil.com":          "/",
		"/a\\b":                 "/",
		"/\\\\evil.com":         "/",
		"http://evil.com":       "/",
		"javascript:alert(1)":   "/",
		"/\u2215evil.com":       "/%e2%88%95evil.com",
		"/\u2044/evil.com":      "/%e2%81%84/evil.com",
		"evil.com":              "/",
		"/ok/path#frag":         "/ok/path#frag",
	} {
		g := newRig(t, nil)
		tx, code, state := g.login(t, next)
		rec := g.do("GET", "/auth/callback?code="+code+"&state="+state, tx)
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("next %q -> %q, want %q", next, got, want)
		}
	}
}

func TestOIDCDiscoveryFailureIsLazyAndRecovers(t *testing.T) {
	var fail = true
	var mu sync.Mutex
	var real *fakeIdP
	g := newRig(t, func(c *config.OIDCConfig, o *auth.Options) {
		o.Discover = func(ctx context.Context, issuer string) (auth.Provider, error) {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				return nil, errors.New("dial tcp: connection refused")
			}
			return auth.DefaultDiscoverer(ctx, issuer)
		}
	})
	real = g.idp
	_ = real
	if rec := g.do("GET", "/auth/login"); rec.Code != 502 {
		t.Fatalf("login with IdP down = %d", rec.Code)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	if rec := g.do("GET", "/auth/login"); rec.Code != 302 {
		t.Fatalf("login after recovery = %d", rec.Code)
	}
}

func TestOIDCCallbackDiscoveryFailure(t *testing.T) {
	g := newRig(t, nil)
	tx, code, state := g.login(t, "/")
	// New authenticator whose discovery is down, same secret/clock so tx opens.
	o2, err := auth.NewOIDC(config.OIDCConfig{Issuer: g.idp.srv.URL, ClientID: "deckard-client"}, auth.Options{
		BaseURL: "https://deckard.example.com", Clock: g.clock,
		Getenv:   func(string) string { return testSecret },
		Discover: func(context.Context, string) (auth.Provider, error) { return nil, errors.New("down") },
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	o2.Mount(r)
	req := httptest.NewRequest("GET", "/auth/callback?code="+code+"&state="+state, nil)
	req.AddCookie(tx)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 502 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestNewOIDCValidation(t *testing.T) {
	good := config.OIDCConfig{Issuer: "https://idp", ClientID: "c"}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	tests := []struct {
		name string
		cfg  config.OIDCConfig
		opts auth.Options
	}{
		{"no issuer", config.OIDCConfig{ClientID: "c"}, auth.Options{BaseURL: "https://x", Getenv: env(map[string]string{"DECKARD_SESSION_SECRET": testSecret})}},
		{"no secret", good, auth.Options{BaseURL: "https://x", Getenv: env(nil)}},
		{"short secret", good, auth.Options{BaseURL: "https://x", Getenv: env(map[string]string{"DECKARD_SESSION_SECRET": "short"})}},
		{"no redirect", good, auth.Options{Getenv: env(map[string]string{"DECKARD_SESSION_SECRET": testSecret})}},
	}
	for _, tt := range tests {
		if _, err := auth.NewOIDC(tt.cfg, tt.opts); err == nil {
			t.Errorf("%s: expected error", tt.name)
		}
	}
	// custom env name + explicit redirect URL + http (non-secure cookies)
	o, err := auth.NewOIDC(config.OIDCConfig{Issuer: "https://idp", ClientID: "c", RedirectURL: "http://localhost/auth/callback"},
		auth.Options{SessionSecretEnv: "MY_SECRET", Getenv: env(map[string]string{"MY_SECRET": testSecret})})
	if err != nil || o.Mode() != "oidc" {
		t.Fatalf("custom env: %v", err)
	}
}
