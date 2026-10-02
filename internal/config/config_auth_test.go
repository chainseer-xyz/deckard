package config

import (
	"strings"
	"testing"
)

func TestOIDCRequiresHTTPSBaseURL(t *testing.T) {
	const oidc = "auth: {mode: oidc, oidc: {issuer: https://idp, client_id: c%s}}\n"
	for _, tc := range []struct {
		name, yaml, wantErr string
	}{
		{"http base_url rejected", "server: {base_url: http://deckard.example.com}\n" + sprintf(oidc, ""), "base_url"},
		{"empty base_url and redirect rejected", sprintf(oidc, ""), "https"},
		{"https base_url ok", "server: {base_url: https://deckard.example.com}\n" + sprintf(oidc, ""), ""},
		{"https redirect_url ok", sprintf(oidc, ", redirect_url: https://deckard.example.com/auth/callback"), ""},
		{"http redirect_url rejected", sprintf(oidc, ", redirect_url: http://deckard.example.com/auth/callback"), "redirect_url"},
		{"insecure opt-in", "server: {base_url: http://localhost:8080}\n" + sprintf(oidc, ", allow_insecure_base_url: true"), ""},
		{"token mode needs no https", "server: {base_url: http://x}\nauth: {mode: token, token_env: T}\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeCfg(t, tc.yaml), nil)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestMetricsTokenEnvLoads(t *testing.T) {
	cfg, err := Load(writeCfg(t, "server: {metrics_token_env: DECKARD_METRICS_TOKEN}\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MetricsTokenEnv != "DECKARD_METRICS_TOKEN" {
		t.Errorf("metrics_token_env = %q", cfg.Server.MetricsTokenEnv)
	}
	cfg, err = Load("", nil)
	if err != nil || cfg.Server.MetricsTokenEnv != "" || cfg.Server.MetricsAddr != ":9090" {
		t.Errorf("defaults: %+v %v", cfg.Server, err)
	}
}

func sprintf(f string, a ...any) string { return strings.Replace(f, "%s", a[0].(string), 1) }
