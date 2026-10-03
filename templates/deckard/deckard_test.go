package deckard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var expectedIDs = []string{
	"deckard-cors-credentials-reflection",
	"deckard-default-admin-pages",
	"deckard-directory-listing-sensitive",
	"deckard-docker-registry-catalogue",
	"deckard-exposed-alertmanager",
	"deckard-exposed-api-docs",
	"deckard-exposed-argocd",
	"deckard-exposed-config-backup",
	"deckard-exposed-env",
	"deckard-exposed-git-config",
	"deckard-exposed-grafana",
	"deckard-exposed-kubernetes-api",
	"deckard-exposed-prometheus",
	"deckard-graphql-introspection",
	"deckard-source-map-exposed",
	"deckard-spring-actuator-env",
	"deckard-spring-actuator-heapdump",
}

func TestDeckardTemplatesMatchVulnerableOnly(t *testing.T) {
	bin, err := exec.LookPath(os.Getenv("NUCLEI_BINARY"))
	if os.Getenv("NUCLEI_BINARY") == "" {
		bin, err = exec.LookPath("nuclei")
	}
	if err != nil {
		t.Skip("SKIP: nuclei binary unavailable; run with NUCLEI_BINARY or the full image")
	}

	serve := func(vulnerable bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if !vulnerable {
				http.NotFound(w, nil)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", "https://untrusted.example")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte(`# HELP process_cpu_seconds_total test
# TYPE process_cpu_seconds_total counter
[core] repositoryformatversion
APP_KEY=not-a-real-secret
password: redacted
Grafana grafana-app
clusterStatus silences
argocd Version gitVersion major minor
activeProfiles propertySources systemProperties
version sources mappings
__schema types name
{"repositories":["demo"]}
Index of / file.env server-status Server Status Active connections:
{"openapi":"3.0.0","swagger":"2.0","paths":{}}
{"version":3,"sources":["main.ts"],"mappings":"AAAA"}
`))
		}))
	}

	run := func(t *testing.T, target string) []string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin,
			"-u", target, "-t", ".", "-pt", "http", "-duc", "-silent", "-no-color",
			"-jsonl", "-rate-limit", "100", "-c", "4", "-timeout", "3")
		cmd.Dir = filepath.Join(".")
		out, err := cmd.CombinedOutput()
		if err != nil && ctx.Err() == nil {
			t.Fatalf("nuclei failed: %v\n%s", err, out)
		}
		var got []string
		for _, line := range strings.Split(string(out), "\n") {
			var event struct {
				ID string `json:"template-id"`
			}
			if json.Unmarshal([]byte(line), &event) == nil && event.ID != "" {
				got = append(got, event.ID)
			}
		}
		slices.Sort(got)
		return slices.Compact(got)
	}

	vulnerable := serve(true)
	defer vulnerable.Close()
	if got := run(t, vulnerable.URL); !slices.Equal(got, expectedIDs) {
		t.Fatalf("vulnerable response matched %v, want %v", got, expectedIDs)
	}
	safe := serve(false)
	defer safe.Close()
	if got := run(t, safe.URL); len(got) != 0 {
		t.Fatalf("safe response matched %v", got)
	}
}
