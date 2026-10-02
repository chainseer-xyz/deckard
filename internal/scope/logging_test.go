package scope

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

type logRec struct {
	Level  string `json:"level"`
	Msg    string `json:"msg"`
	Target string `json:"target"`
	Op     string `json:"op"`
}

func logGuard(t *testing.T, buf *bytes.Buffer, res *fakeResolver, rec *recordingDialer) *Guard {
	t.Helper()
	lg := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g, err := NewGuard(config.ScopeConfig{Exclude: []string{"secret.example.com"}},
		WithResolver(res), WithDialer(rec), WithLogger(lg))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	return g
}

func lastLog(t *testing.T, buf *bytes.Buffer) logRec {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var r logRec
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil {
		t.Fatalf("log line %q: %v", lines[len(lines)-1], err)
	}
	return r
}

func redirectReq(t *testing.T, raw string) (*http.Request, []*http.Request) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://app.example.com/", nil)
	return req, []*http.Request{orig}
}

func TestRedirectRefusalLogLevels(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		wantErr error
		level   string
	}{
		{"external host (normal SSO redirect)", "https://login.sso.example.net/authorize?token=SECRETTOKEN&sig=abc", ErrOutOfScope, "DEBUG"},
		{"excluded host", "https://secret.example.com/x?token=SECRETTOKEN", ErrExcluded, "WARN"},
		{"private ip literal", "http://10.1.2.3/admin?token=SECRETTOKEN", ErrOutOfScope, "WARN"},
		{"metadata ip literal", "http://169.254.169.254/latest/meta-data?token=SECRETTOKEN", ErrOutOfScope, "WARN"},
		{"non-http scheme", "ftp://files.example.net/x?token=SECRETTOKEN", ErrOutOfScope, "WARN"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		g := logGuard(t, &buf, newFakeResolver(nil), &recordingDialer{})
		req, via := redirectReq(t, c.target)
		err := g.checkRedirect(model.TierPassive, req, via)
		if !errors.Is(err, c.wantErr) {
			t.Errorf("%s: error %v want %v", c.name, err, c.wantErr)
		}
		if err != nil && strings.Contains(err.Error(), "SECRETTOKEN") {
			t.Errorf("%s: error text leaks query: %v", c.name, err)
		}
		if strings.Contains(buf.String(), "SECRETTOKEN") {
			t.Errorf("%s: log leaks query string: %s", c.name, buf.String())
		}
		if r := lastLog(t, &buf); r.Level != c.level || r.Msg != "scope refusal" || r.Op != "redirect" {
			t.Errorf("%s: log %+v want level %s", c.name, r, c.level)
		}
	}
}

func TestRedirectLogKeepsSchemeHostPath(t *testing.T) {
	var buf bytes.Buffer
	g := logGuard(t, &buf, newFakeResolver(nil), &recordingDialer{})
	req, via := redirectReq(t, "https://login.sso.example.net/cdn-cgi/access/login?kid=1#frag")
	_ = g.checkRedirect(model.TierPassive, req, via)
	if r := lastLog(t, &buf); r.Target != "https://login.sso.example.net/cdn-cgi/access/login" {
		t.Errorf("target: %q", r.Target)
	}
}

func TestDialRefusalsStayWarn(t *testing.T) {
	var buf bytes.Buffer
	res := newFakeResolver(nil)
	g := logGuard(t, &buf, res, &recordingDialer{})
	d := g.Dialer(model.TierPassive, model.ScopeOwned, nil)
	for _, addr := range []string{"10.1.2.3:80", "169.254.169.254:80", "secret.example.com:443", "app.example.net:443"} {
		buf.Reset()
		if _, err := d.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("%s: %v", addr, err)
		}
		if r := lastLog(t, &buf); r.Level != "WARN" {
			t.Errorf("%s: dial refusal must stay WARN, got %+v", addr, r)
		}
	}
}
