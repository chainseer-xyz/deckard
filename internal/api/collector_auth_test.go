package api_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/config"
)

const collectorToken = "collector-secret-not-an-administrator-0123456789"

func scopedConfig(t *testing.T) config.IngestConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("ingest:\n  credentials:\n    image-collector:\n      token_env: IMAGE_TOKEN\n      tools: [prowler]\n      scopes: ['"+scopeA+"']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Ingest
}

func TestCollectorTokenOnlyWritesItsExactProducerScope(t *testing.T) {
	e := newIngestEnv(t, func(d *api.Deps) {
		d.Ingest = scopedConfig(t)
		d.AuthOptions.Getenv = func(string) string { return collectorToken }
	})
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/api/v1/ingest", body("prowler", scopeA, false, t0, bucket("ok")), 200},
		{"POST", "/api/v1/ingest", body("prowler", "aws:other", false, t0, bucket("no")), 403},
		{"POST", "/api/v1/ingest", body("trivy", scopeA, false, t0), 403},
		{"GET", "/api/v1/assets", "", 403},
		{"GET", "/api/v1/stats", "", 403},
		{"POST", "/api/v1/sources/cloudflare/sync", "{}", 403},
		{"POST", "/api/v1/findings/1/suppress", `{"note":"no"}`, 403},
	} {
		r := e.do(tc.method, tc.path, tc.body, "Authorization", "Bearer "+collectorToken)
		if r.Code != tc.want {
			t.Fatalf("%s %s: got %d want %d: %s", tc.method, tc.path, r.Code, tc.want, r.Body)
		}
	}
	if r := e.get("/api/v1/assets"); r.Code != 200 {
		t.Fatalf("administrator lost access: %d", r.Code)
	}
	if strings.Contains(e.logs.String(), collectorToken) {
		t.Fatal("credential leaked to logs")
	}
}

func TestCollectorCredentialMissingFailsClosed(t *testing.T) {
	e := newIngestEnv(t, func(d *api.Deps) {
		d.Ingest = scopedConfig(t)
		d.AuthOptions.Getenv = func(string) string { return "short" }
	})
	if e.srv.Err() == nil {
		t.Fatal("missing/short producer credential did not fail startup")
	}
	if r := e.get("/api/v1/assets"); r.Code != 503 {
		t.Fatalf("misconfiguration opened API: %d", r.Code)
	}
}
