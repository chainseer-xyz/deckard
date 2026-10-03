// Package auth implements deckard's API authentication modes: none, static
// bearer token and OIDC (Authorization Code + PKCE) with cookie sessions.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chainseer-xyz/deckard/internal/config"
)

// Clock abstracts time for tests.
type Clock interface{ Now() time.Time }

// SystemClock is the wall clock.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// MinTokenBytes is the shortest static bearer token token mode accepts.
const MinTokenBytes = 32

// Authentication methods recorded on an Identity.
const (
	MethodNone   = "none"
	MethodToken  = "token"
	MethodCookie = "cookie"
)

// Identity is the authenticated caller.
type Identity struct {
	Subject string   `json:"subject"`
	Name    string   `json:"name,omitempty"`
	Email   string   `json:"email,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Method  string   `json:"method"`
	// EmailVerified reports whether the IdP vouched for Email (OIDC
	// email_verified). Only a verified email may name the audit actor.
	EmailVerified bool `json:"-"`
	// Issuer is the OIDC issuer that asserted Subject (empty for other modes).
	Issuer string `json:"-"`
	// CSRFToken is set for cookie sessions; state-changing requests must echo
	// it in X-CSRF-Token.
	CSRFToken string `json:"-"`
}

// Actor is the string recorded as the author of operator actions.
func (i Identity) Actor() string {
	switch {
	case i.Email != "" && i.EmailVerified:
		return i.Email
	case i.Subject != "" && i.Issuer != "":
		return i.Subject + " (iss " + i.Issuer + ")"
	case i.Subject != "":
		return i.Subject
	}
	return "unknown"
}

// ErrUnauthenticated means no valid credentials were presented.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator identifies the caller of an API request.
type Authenticator interface {
	Mode() string
	// Authenticate returns ErrUnauthenticated when credentials are missing or
	// invalid. It must not log credentials.
	Authenticate(r *http.Request) (*Identity, error)
}

// Router is implemented by authenticators that serve their own endpoints
// (the OIDC login flow).
type Router interface {
	Mount(r chi.Router)
}

// Options carries everything not in config.AuthConfig.
type Options struct {
	// SessionSecretEnv names the env var holding the cookie-encryption secret
	// (OIDC mode). Default DECKARD_SESSION_SECRET.
	SessionSecretEnv string
	// Getenv defaults to os.Getenv.
	Getenv func(string) string
	// Discover resolves the OIDC provider; defaults to real discovery.
	Discover Discoverer
	// BaseURL is the externally visible URL, used for the redirect URI and
	// to decide the Secure cookie attribute.
	BaseURL string
	Clock   Clock
	Logger  *slog.Logger
	// SessionTTL defaults to 8h.
	SessionTTL time.Duration
}

func (o *Options) defaults() {
	if o.SessionSecretEnv == "" {
		o.SessionSecretEnv = "DECKARD_SESSION_SECRET"
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Clock == nil {
		o.Clock = SystemClock{}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.SessionTTL <= 0 {
		o.SessionTTL = 8 * time.Hour
	}
}

// New builds the authenticator for cfg.Mode.
func New(cfg config.AuthConfig, opts Options) (Authenticator, error) {
	opts.defaults()
	switch cfg.Mode {
	case "none":
		opts.Logger.Warn("auth.mode=none: API is OPEN for reads AND writes; run only behind a trusted authenticating proxy")
		return None{}, nil
	case "token":
		if cfg.TokenEnv == "" {
			return nil, errors.New("auth.token_env is required for token mode")
		}
		tok := strings.TrimSpace(opts.Getenv(cfg.TokenEnv))
		if tok == "" {
			return nil, fmt.Errorf("auth token env %q is empty", cfg.TokenEnv)
		}
		if len(tok) < MinTokenBytes {
			return nil, fmt.Errorf("auth token in %q is too short: need at least %d bytes (generate one with: openssl rand -hex 32)", cfg.TokenEnv, MinTokenBytes)
		}
		return NewToken(tok), nil
	case "oidc":
		return NewOIDC(cfg.OIDC, opts)
	}
	return nil, fmt.Errorf("unknown auth mode %q", cfg.Mode)
}

// None allows everyone. Only safe behind a trusted proxy.
type None struct{}

// Mode implements Authenticator.
func (None) Mode() string { return "none" }

// Authenticate implements Authenticator.
func (None) Authenticate(*http.Request) (*Identity, error) {
	return &Identity{Subject: "anonymous", Method: MethodNone}, nil
}

// Token authenticates a static bearer token.
type Token struct{ digest [32]byte }

// NewToken builds a Token authenticator. Surrounding whitespace (a trailing
// newline from a file-backed secret) is ignored, as on the presented token.
func NewToken(tok string) *Token {
	return &Token{digest: sha256.Sum256([]byte(strings.TrimSpace(tok)))}
}

// Mode implements Authenticator.
func (*Token) Mode() string { return "token" }

// Authenticate implements Authenticator. Only the Authorization header is
// consulted, never the query string.
func (t *Token) Authenticate(r *http.Request) (*Identity, error) {
	h := r.Header.Get("Authorization")
	scheme, val, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, ErrUnauthenticated
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(val)))
	if subtle.ConstantTimeCompare(got[:], t.digest[:]) != 1 {
		return nil, ErrUnauthenticated
	}
	return &Identity{Subject: "token", Method: MethodToken}, nil
}

// Deny rejects everything; installed when auth is misconfigured so the API
// fails closed instead of open.
type Deny struct{ Err error }

// Mode implements Authenticator.
func (Deny) Mode() string { return "misconfigured" }

// Authenticate implements Authenticator.
func (Deny) Authenticate(*http.Request) (*Identity, error) { return nil, ErrUnauthenticated }
