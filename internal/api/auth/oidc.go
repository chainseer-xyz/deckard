package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/chainseer-xyz/deckard/internal/config"
)

const (
	sessionCookie = "deckard_session"
	txCookie      = "deckard_oidc_tx"
	txTTL         = 10 * time.Minute
	maxGroups     = 50
)

// Provider is the part of an OIDC provider deckard needs. *oidc.Provider
// satisfies it; tests inject a fake through Options.Discover.
type Provider interface {
	Endpoint() oauth2.Endpoint
	Verifier(*oidc.Config) *oidc.IDTokenVerifier
}

// Discoverer resolves the provider for an issuer URL.
type Discoverer func(ctx context.Context, issuer string) (Provider, error)

// DefaultDiscoverer performs real OIDC discovery.
func DefaultDiscoverer(ctx context.Context, issuer string) (Provider, error) {
	return oidc.NewProvider(ctx, issuer)
}

// OIDC implements the Authorization Code + PKCE login flow and cookie
// sessions. Discovery is lazy so an unreachable issuer at startup does not
// prevent deckard from serving (login fails with 502 until it recovers).
type OIDC struct {
	cfg      config.OIDCConfig
	secret   string // client secret, may be empty for public clients
	redirect string
	secure   bool
	ttl      time.Duration
	sealer   *sealer
	discover Discoverer
	clock    Clock
	log      *slog.Logger

	mu       sync.Mutex
	provider Provider
}

// NewOIDC builds the OIDC authenticator. It fails when the session secret is
// missing or too short.
func NewOIDC(cfg config.OIDCConfig, opts Options) (*OIDC, error) {
	opts.defaults()
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("oidc issuer and client_id are required")
	}
	sec := opts.Getenv(opts.SessionSecretEnv)
	if sec == "" {
		return nil, fmt.Errorf("session secret env %q is empty", opts.SessionSecretEnv)
	}
	clock := opts.Clock
	s, err := newSealer(sec, clock.Now)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opts.SessionSecretEnv, err)
	}
	redirect := cfg.RedirectURL
	if redirect == "" {
		if opts.BaseURL == "" {
			return nil, errors.New("oidc redirect_url or server.base_url is required")
		}
		redirect = strings.TrimRight(opts.BaseURL, "/") + "/auth/callback"
	}
	disc := opts.Discover
	if disc == nil {
		disc = DefaultDiscoverer
	}
	o := &OIDC{
		cfg: cfg, redirect: redirect, secure: strings.HasPrefix(redirect, "https://"),
		ttl: opts.SessionTTL, sealer: s, discover: disc, clock: clock, log: opts.Logger,
	}
	if cfg.ClientSecretEnv != "" {
		o.secret = opts.Getenv(cfg.ClientSecretEnv)
	}
	if len(cfg.AllowedGroups) == 0 {
		o.log.Warn("auth.oidc.allowed_groups is empty: EVERY account at the issuer can sign in with full write access; set allowed_groups to restrict operators",
			"issuer", cfg.Issuer)
	}
	if !o.secure {
		o.log.Warn("OIDC redirect URL is not https: session cookies are not Secure and HSTS is off; use only for local development",
			"redirect_url", redirect)
	}
	return o, nil
}

// Mode implements Authenticator.
func (*OIDC) Mode() string { return "oidc" }

// Mount registers /auth/login, /auth/callback and /auth/logout.
func (o *OIDC) Mount(r chi.Router) {
	r.Get("/auth/login", o.login)
	r.Get("/auth/callback", o.callback)
	// POST only: a GET logout is triggerable cross-site (img tag, link).
	r.Post("/auth/logout", o.logout)
}

type session struct {
	Sub    string   `json:"sub"`
	Name   string   `json:"name,omitempty"`
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups,omitempty"`
	CSRF   string   `json:"csrf"`
	// EmailVerified and Iss are recorded at login (email_verified claim, issuer).
	EmailVerified bool   `json:"ev,omitempty"`
	Iss           string `json:"iss,omitempty"`
}

type loginTx struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
}

// Authenticate implements Authenticator using the session cookie.
func (o *OIDC) Authenticate(r *http.Request) (*Identity, error) {
	c, err := r.Cookie(o.cookieName(sessionCookie))
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var s session
	if err := o.sealer.open(sessionCookie, c.Value, &s); err != nil || s.Sub == "" {
		return nil, ErrUnauthenticated
	}
	return &Identity{
		Subject: s.Sub, Name: s.Name, Email: s.Email, Groups: s.Groups,
		EmailVerified: s.EmailVerified, Issuer: s.Iss,
		Method: MethodCookie, CSRFToken: s.CSRF,
	}, nil
}

func (o *OIDC) getProvider(ctx context.Context) (Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	p, err := o.discover(ctx, o.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	o.provider = p
	return p, nil
}

func (o *OIDC) oauthConfig(p Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: o.cfg.ClientID, ClientSecret: o.secret, Endpoint: p.Endpoint(),
		RedirectURL: o.redirect, Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
}

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// safeNext only allows same-site relative paths, preventing open redirects.
// Browsers strip tab/CR/LF from URLs before parsing, so "/\t/evil.com" would
// become "//evil.com"; any control byte, backslash, or encoded variant that
// decodes to one of those is therefore rejected outright.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") {
		return "/"
	}
	for _, v := range []string{next, unescapeOrSelf(next)} {
		if strings.HasPrefix(v, "//") || strings.ContainsRune(v, '\\') {
			return "/"
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] == 0x7f {
				return "/"
			}
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	return next
}

func unescapeOrSelf(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// cookieName applies a prefix browsers enforce when the site is https:
// __Host- (Secure, Path=/, no Domain) for the session, __Secure- for the
// transaction cookie, whose path is /auth. Over http the prefixes would make
// browsers drop the cookie, so the plain names are used.
func (o *OIDC) cookieName(logical string) string {
	if !o.secure {
		return logical
	}
	if logical == sessionCookie {
		return "__Host-" + logical
	}
	return "__Secure-" + logical
}

func (o *OIDC) setCookie(w http.ResponseWriter, name, val, path string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the https base_url (validated at startup)
		Name: o.cookieName(name), Value: val, Path: path, HttpOnly: true, Secure: o.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds()),
	})
}

func (o *OIDC) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the https base_url (validated at startup)
		Name: o.cookieName(name), Value: "", Path: path, HttpOnly: true, Secure: o.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (o *OIDC) login(w http.ResponseWriter, r *http.Request) {
	p, err := o.getProvider(r.Context())
	if err != nil {
		o.log.Error("oidc discovery failed", "err", err)
		writeErr(w, http.StatusBadGateway, "idp_unavailable", "identity provider unavailable")
		return
	}
	state, err1 := randString(32)
	nonce, err2 := randString(32)
	verifier := oauth2.GenerateVerifier()
	if err := errors.Join(err1, err2); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not start login")
		return
	}
	tx := loginTx{State: state, Nonce: nonce, Verifier: verifier, Next: safeNext(r.URL.Query().Get("next"))}
	sealed, err := o.sealer.seal(txCookie, tx, txTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not start login")
		return
	}
	o.setCookie(w, txCookie, sealed, "/auth", txTTL)
	u := o.oauthConfig(p).AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u, http.StatusFound)
}

func (o *OIDC) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// The transaction cookie is single-use regardless of outcome.
	o.clearCookie(w, txCookie, "/auth") // set before any write so it always ships

	c, err := r.Cookie(o.cookieName(txCookie))
	var tx loginTx
	if err != nil || o.sealer.open(txCookie, c.Value, &tx) != nil {
		writeErr(w, http.StatusBadRequest, "invalid_login", "login session missing or expired; start again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(tx.State)) != 1 || tx.State == "" {
		writeErr(w, http.StatusBadRequest, "invalid_state", "state mismatch")
		return
	}
	if e := q.Get("error"); e != "" {
		writeErr(w, http.StatusForbidden, "idp_error", "identity provider returned an error")
		return
	}
	code := q.Get("code")
	if code == "" {
		writeErr(w, http.StatusBadRequest, "invalid_login", "missing code")
		return
	}
	p, err := o.getProvider(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, "idp_unavailable", "identity provider unavailable")
		return
	}
	tok, err := o.oauthConfig(p).Exchange(r.Context(), code, oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		o.log.Warn("oidc code exchange failed", "err", err)
		writeErr(w, http.StatusBadGateway, "exchange_failed", "code exchange failed")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		writeErr(w, http.StatusBadGateway, "exchange_failed", "no id_token in response")
		return
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		o.log.Warn("id_token verification failed", "err", err)
		writeErr(w, http.StatusUnauthorized, "invalid_token", "id token verification failed")
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(tx.Nonce)) != 1 || tx.Nonce == "" {
		writeErr(w, http.StatusUnauthorized, "invalid_nonce", "nonce mismatch")
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_token", "unreadable claims")
		return
	}
	groups := o.groupsFrom(claims)
	if allowed := o.cfg.AllowedGroups; len(allowed) > 0 {
		groups = intersect(groups, allowed)
		if len(groups) == 0 {
			o.log.Warn("oidc login denied: no allowed group", "sub", idt.Subject)
			writeErr(w, http.StatusForbidden, "forbidden", "your account is not in an allowed group")
			return
		}
	}
	if len(groups) > maxGroups {
		groups = groups[:maxGroups]
	}
	csrf, err := randString(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not create session")
		return
	}
	s := session{Sub: idt.Subject, Name: str(claims["name"], claims["preferred_username"]), Email: str(claims["email"]), Groups: groups, CSRF: csrf,
		EmailVerified: truthy(claims["email_verified"]), Iss: idt.Issuer}
	sealed, err := o.sealer.seal(sessionCookie, s, o.ttl)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not create session")
		return
	}
	o.setCookie(w, sessionCookie, sealed, "/", o.ttl)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, safeNext(tx.Next), http.StatusFound)
}

func (o *OIDC) logout(w http.ResponseWriter, r *http.Request) {
	// A live session requires its CSRF token; without one there is nothing to
	// protect and clearing the (absent or invalid) cookie is harmless.
	if id, err := o.Authenticate(r); err == nil {
		got := r.Header.Get("X-CSRF-Token")
		if got == "" || id.CSRFToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(id.CSRFToken)) != 1 {
			writeErr(w, http.StatusForbidden, "csrf", "missing or invalid X-CSRF-Token")
			return
		}
	}
	o.clearCookie(w, sessionCookie, "/")
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (o *OIDC) groupsFrom(claims map[string]any) []string {
	name := o.cfg.GroupsClaim
	if name == "" {
		name = "groups"
	}
	switch v := claims[name].(type) {
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func intersect(have, allowed []string) []string {
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	var out []string
	for _, h := range have {
		if _, ok := set[h]; ok {
			out = append(out, h)
		}
	}
	return out
}

// truthy reads a boolean claim; some IdPs send it as the string "true".
func truthy(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true"
	}
	return false
}

func str(vals ...any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
