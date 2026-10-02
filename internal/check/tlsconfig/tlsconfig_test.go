package tlsconfig

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

type plainDialer struct{}

func (plainDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// serve runs a TLS server with cfg; non-TLS clients are dropped.
func serve(t *testing.T, cfg *tls.Config) int {
	t.Helper()
	cfg.Certificates = []tls.Certificate{selfSigned(t)}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.(*tls.Conn).HandshakeContext(context.Background())
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func svc(port int) model.Asset {
	return model.Asset{Kind: model.KindService, Key: "127.0.0.1:" + strconv.Itoa(port) + "/tcp", Scope: model.ScopeOwned,
		Attrs: map[string]any{"tls": true}}
}

func keys(r *check.Result) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range r.Findings {
		m[f.Key] = f.Severity
	}
	return m
}

func run(t *testing.T, a model.Asset) *check.Result {
	t.Helper()
	res, err := (&configCheck{}).Run(context.Background(), check.Target{Asset: a, Dialer: plainDialer{}, Config: map[string]any{"timeout": "3s"}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestLegacyServer(t *testing.T) {
	port := serve(t, &tls.Config{
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	})
	res := run(t, svc(port))
	got := keys(res)
	want := map[string]model.Severity{
		"proto/tls1.0":                         model.SeverityMedium,
		"proto/tls1.1":                         model.SeverityMedium,
		"proto/no-tls1.3":                      model.SeverityInfo,
		"cipher/TLS_RSA_WITH_3DES_EDE_CBC_SHA": model.SeverityMedium,
		"cipher/no-forward-secrecy":            model.SeverityLow,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all=%v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected extra findings: %v", got)
	}
	obs := res.Observations[0].Data
	if obs["tls"] != true || len(obs["cipher_suites"].([]string)) != 3 {
		t.Errorf("obs=%v", obs)
	}
}

func TestModernServerIsClean(t *testing.T) {
	port := serve(t, &tls.Config{MinVersion: tls.VersionTLS12})
	res := run(t, svc(port))
	if len(res.Findings) != 0 {
		t.Fatalf("findings: %v", keys(res))
	}
	vs := res.Observations[0].Data["versions"].([]string)
	if len(vs) != 2 || vs[1] != "TLS 1.3" {
		t.Errorf("versions=%v", vs)
	}
}

func TestTLS12OnlyReportsNo13(t *testing.T) {
	port := serve(t, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	got := keys(run(t, svc(port)))
	if len(got) != 1 || got["proto/no-tls1.3"] != model.SeverityInfo {
		t.Fatalf("%v", got)
	}
}

func TestNonTLSListener(t *testing.T) {
	l, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	res := run(t, svc(l.Addr().(*net.TCPAddr).Port))
	if res.Observations[0].Data["tls"] != false || len(res.Findings) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestClassifySuite(t *testing.T) {
	tests := []struct {
		name string
		sev  model.Severity
		weak bool
	}{
		{"TLS_ECDHE_RSA_WITH_RC4_128_SHA", model.SeverityHigh, true},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", model.SeverityMedium, true},
		{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", model.SeverityHigh, true},
		{"TLS_DH_anon_WITH_AES_128_CBC_SHA", model.SeverityHigh, true},
		{"TLS_RSA_WITH_NULL_SHA", model.SeverityHigh, true},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "", false},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", "", false},
	}
	for _, tc := range tests {
		w, ok := classifySuite(tc.name)
		if ok != tc.weak || w.severity != tc.sev {
			t.Errorf("%s: got %v %v", tc.name, w, ok)
		}
	}
}

func TestApplies(t *testing.T) {
	c := &configCheck{}
	tests := []struct {
		a    model.Asset
		want bool
	}{
		{model.Asset{Kind: model.KindService, Key: "192.0.2.1:443/tcp", Scope: model.ScopeOwned}, true},
		{model.Asset{Kind: model.KindService, Key: "192.0.2.1:22/tcp", Scope: model.ScopeOwned}, false},
		{model.Asset{Kind: model.KindService, Key: "192.0.2.1:22/tcp", Scope: model.ScopeOwned, Attrs: map[string]any{"tls": true}}, true},
		{model.Asset{Kind: model.KindHostname, Key: "a.example.com", Scope: model.ScopeOwned, Attrs: map[string]any{"https": true}}, true},
		{model.Asset{Kind: model.KindHostname, Key: "a.example.com", Scope: model.ScopeOwned}, false},
		{model.Asset{Kind: model.KindService, Key: "192.0.2.1:443/tcp", Scope: model.ScopeShared}, false},
		{model.Asset{Kind: model.KindURL, Key: "https://a.example.com"}, false},
	}
	for _, tc := range tests {
		if got := c.Applies(tc.a); got != tc.want {
			t.Errorf("%+v: got %v", tc.a, got)
		}
	}
}

func TestCancelAndNoDialer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&configCheck{}).Run(ctx, check.Target{Asset: svc(1), Dialer: plainDialer{}}); err == nil {
		t.Fatal("expected ctx error")
	}
	if _, err := (&configCheck{}).Run(context.Background(), check.Target{Asset: svc(1)}); err == nil {
		t.Fatal("expected dialer error")
	}
	if len(Checks(nil)) != 1 {
		t.Fatal("Checks")
	}
}
