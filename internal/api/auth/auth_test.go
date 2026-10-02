package auth_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/config"
)

func TestTokenAuth(t *testing.T) {
	a := auth.NewToken("s3cret-token")
	tests := []struct {
		name   string
		target string
		header string
		ok     bool
	}{
		{"valid", "/", "Bearer s3cret-token", true},
		{"scheme case-insensitive", "/", "bearer s3cret-token", true},
		{"wrong", "/", "Bearer nope", false},
		{"empty", "/", "", false},
		{"no scheme", "/", "s3cret-token", false},
		{"basic scheme", "/", "Basic s3cret-token", false},
		{"query param never accepted", "/?token=s3cret-token&access_token=s3cret-token", "", false},
		{"prefix of token", "/", "Bearer s3cret", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.target, nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			id, err := a.Authenticate(req)
			if tt.ok {
				if err != nil || id.Method != auth.MethodToken || id.Actor() != "token" {
					t.Fatalf("id=%+v err=%v", id, err)
				}
				return
			}
			if !errors.Is(err, auth.ErrUnauthenticated) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if a.Mode() != "token" {
		t.Error("mode")
	}
}

func TestNoneAndDeny(t *testing.T) {
	id, err := auth.None{}.Authenticate(httptest.NewRequest("GET", "/", nil))
	if err != nil || id.Actor() != "anonymous" || (auth.None{}).Mode() != "none" {
		t.Fatalf("none: %+v %v", id, err)
	}
	if _, err := (auth.Deny{}).Authenticate(httptest.NewRequest("GET", "/", nil)); err == nil {
		t.Fatal("deny must deny")
	}
	if (auth.Deny{}).Mode() == "" {
		t.Error("deny mode")
	}
}

func TestActor(t *testing.T) {
	for _, tt := range []struct {
		id   auth.Identity
		want string
	}{
		{auth.Identity{Email: "a@b", EmailVerified: true, Subject: "s"}, "a@b"},
		{auth.Identity{Email: "a@b", Subject: "s"}, "s"},
		{auth.Identity{Email: "a@b", Subject: "s", Issuer: "https://idp"}, "s (iss https://idp)"},
		{auth.Identity{Subject: "s"}, "s"},
		{auth.Identity{}, "unknown"},
	} {
		if got := tt.id.Actor(); got != tt.want {
			t.Errorf("%+v -> %q", tt.id, got)
		}
	}
}

func TestNewFromConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	a, err := auth.New(config.AuthConfig{Mode: "none"}, auth.Options{Logger: log})
	if err != nil || a.Mode() != "none" {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "OPEN") || !strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Errorf("none mode must warn loudly, log=%s", buf.String())
	}

	if _, err = auth.New(config.AuthConfig{Mode: "token", TokenEnv: "T"}, auth.Options{Getenv: env(map[string]string{"T": "abc"})}); err == nil ||
		!strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("short token must be refused with a clear error, got %v", err)
	}
	if _, err = auth.New(config.AuthConfig{Mode: "token", TokenEnv: "T"}, auth.Options{Getenv: env(map[string]string{"T": strings.Repeat("a", 31)})}); err == nil {
		t.Fatal("31-byte token must be refused")
	}
	a, err = auth.New(config.AuthConfig{Mode: "token", TokenEnv: "T"}, auth.Options{Getenv: env(map[string]string{"T": strings.Repeat("a", 32)})})
	if err != nil || a.Mode() != "token" {
		t.Fatal(err)
	}
	for name, cfg := range map[string]config.AuthConfig{
		"token no env name": {Mode: "token"},
		"token env empty":   {Mode: "token", TokenEnv: "T"},
		"unknown":           {Mode: "weird"},
		"oidc incomplete":   {Mode: "oidc"},
	} {
		if _, err := auth.New(cfg, auth.Options{Getenv: env(nil)}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	a, err = auth.New(config.AuthConfig{Mode: "oidc", OIDC: config.OIDCConfig{Issuer: "https://i", ClientID: "c"}},
		auth.Options{BaseURL: "https://b", Getenv: env(map[string]string{"DECKARD_SESSION_SECRET": testSecret})})
	if err != nil || a.Mode() != "oidc" {
		t.Fatal(err)
	}
	if _, ok := a.(auth.Router); !ok {
		t.Error("oidc must implement Router")
	}
	_ = http.StatusOK
}
