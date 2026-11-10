package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const kubescapeBatchScope = "k8s:uid:22222222-2222-4222-8222-222222222222"
const kubescapeBatchTime = "2026-10-03T07:00:00Z"
const kubescapeBatchToken = testIngestToken + "-kubescape-collector"

func kubescapeBatchFixture(t *testing.T, count int, description string) string {
	t.Helper()
	results := make([]any, count)
	for i := range results {
		results[i] = map[string]any{"resourceID": fmt.Sprintf("apps/v1/test/Deployment/api-%05d", i),
			"controls": []any{map[string]any{"controlID": "C-0001", "status": "failed", "name": "Test policy"}}}
	}
	data, err := json.Marshal(map[string]any{"clusterName": "test-cluster", "results": results,
		"summaryDetails": map[string]any{"controls": map[string]any{"C-0001": map[string]any{"description": description}}}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "kubescape.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func kubescapeBatchAPI() (*fakestore.Store, http.Handler) {
	st := fakestore.New()
	srv := api.New(api.Deps{
		Store: st, Authenticator: auth.NewToken(testIngestToken),
		AuthOptions: auth.Options{Getenv: func(string) string { return kubescapeBatchToken }},
		Ingester:    finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1}, nil),
		Ingest: config.IngestConfig{Enabled: true, RateLimit: "100/s", Burst: 100,
			Credentials: map[string]config.CollectorCredentialConfig{"posture": {
				TokenEnv: "DECKARD_KUBESCAPE_TEST_TOKEN", Tools: []string{"kubescape"}, Scopes: []string{kubescapeBatchScope},
			}}},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return st, srv.Handler()
}

func postKubescapeFixture(t *testing.T, file, endpoint string, extra ...string) (int, string, string) {
	t.Helper()
	t.Setenv("DECKARD_KUBESCAPE_TEST_TOKEN", kubescapeBatchToken)
	args := []string{"--tool", "kubescape", "--scope", kubescapeBatchScope, "--file", file,
		"--url", endpoint, "--token-env", "DECKARD_KUBESCAPE_TEST_TOKEN", "--observed-at", kubescapeBatchTime}
	return runI(t, append(args, extra...)...)
}

func TestKubescapeIncompleteBatchesThroughHTTP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count       int
		description string
	}{
		{"empty report", 0, ""},
		{"finding limit", ingest.MaxFindings + 1, ""},
		// HTML escaping expands this shared native description in the wire JSON.
		{"body limit", 1000, strings.Repeat("<", 4000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := kubescapeBatchFixture(t, tc.count, tc.description)
			st, handler := kubescapeBatchAPI()
			var mu sync.Mutex
			var bodies [][]byte
			hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				mu.Lock()
				bodies = append(bodies, body)
				mu.Unlock()
				handler.ServeHTTP(w, r)
			}))
			defer hs.Close()
			code, _, errs := postKubescapeFixture(t, file, hs.URL, "--incomplete")
			if code != ingestExitOK {
				t.Fatalf("exit %d: %s", code, errs)
			}
			mu.Lock()
			firstRun := append([][]byte(nil), bodies...)
			mu.Unlock()
			if len(firstRun) == 0 || tc.count > 0 && len(firstRun) < 2 {
				t.Fatalf("report was not split: %d requests", len(firstRun))
			}
			seen, digests, fingerprints := map[string]bool{}, map[string]bool{}, map[string]bool{}
			for _, body := range firstRun {
				req, err := ingest.Decode(body)
				if err != nil || len(body) > ingest.MaxBodyBytes || len(req.Findings) > ingest.MaxFindings || req.Complete ||
					req.Tool != "kubescape" || req.Scope != kubescapeBatchScope || req.ObservedAt.Format(time.RFC3339) != kubescapeBatchTime {
					t.Fatalf("invalid bounded incomplete request: %v", err)
				}
				digest := ingest.Digest(req)
				if digests[digest] {
					t.Fatal("different batches reused a replay identity")
				}
				digests[digest] = true
				for _, f := range req.Findings {
					if seen[f.Key] {
						t.Fatalf("finding delivered twice: %s", f.Key)
					}
					seen[f.Key] = true
					fingerprints[model.Fingerprint("ext.kubescape", kubescapeBatchScope, f.Key)] = true
				}
			}
			findings, total, err := st.ListFindings(context.Background(), store.FindingFilter{Check: "ext.kubescape"})
			if err != nil || len(seen) != tc.count || total != tc.count {
				t.Fatalf("findings lost: delivered=%d stored=%d want=%d err=%v", len(seen), total, tc.count, err)
			}
			for i := 0; i < tc.count; i++ {
				if !seen[fmt.Sprintf("C-0001:apps/v1/test/Deployment/api-%05d", i)] {
					t.Fatalf("native finding %d was not delivered", i)
				}
			}
			for _, f := range findings {
				if !fingerprints[f.Fingerprint] || f.Status != model.StatusOpen || f.MissedRuns != 0 || f.IngestScope != kubescapeBatchScope {
					t.Fatalf("batch changed identity or applied absence: %+v", f)
				}
			}
			// Rebuilding the same scan must produce identical batch digests.
			if code, _, errs := postKubescapeFixture(t, file, hs.URL, "--incomplete"); code != ingestExitOK {
				t.Fatalf("repeat exit %d: %s", code, errs)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(bodies) != 2*len(firstRun) {
				t.Fatalf("batch count changed on retry: %d", len(bodies))
			}
			for i := range firstRun {
				if string(firstRun[i]) != string(bodies[len(firstRun)+i]) {
					t.Fatalf("batch %d changed on retry", i+1)
				}
			}
		})
	}
}

func TestKubescapeBatchFailuresAndReplayThroughHTTP(t *testing.T) {
	file := kubescapeBatchFixture(t, ingest.MaxFindings+1, "")
	for _, tc := range []struct {
		name, receipt string
		status, want  int
	}{
		{"second request refused", `{"error":{"message":"denied"}}`, http.StatusForbidden, ingestExitRejected},
		{"second receipt malformed", `{}`, http.StatusOK, ingestExitRejected},
		{"second receipt short", `{"accepted":0,"complete":false,"rejected":[]}`, http.StatusOK, ingestExitRejected},
		{"applied first request retried", "", http.StatusServiceUnavailable, ingestExitOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backoffUnit = time.Millisecond
			t.Cleanup(func() { backoffUnit = time.Second })
			st, handler := kubescapeBatchAPI()
			var mu sync.Mutex
			calls := 0
			hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				if tc.want == ingestExitOK && n == 1 {
					// Apply it, then lose its response: the actual API returns a
					// zero-accepted replay receipt on the transport retry.
					handler.ServeHTTP(httptest.NewRecorder(), r)
					w.WriteHeader(tc.status)
					return
				}
				if tc.want != ingestExitOK && n == 2 {
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.receipt)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer hs.Close()
			code, _, errs := postKubescapeFixture(t, file, hs.URL, "--incomplete")
			if code != tc.want {
				t.Fatalf("exit %d want %d: %s", code, tc.want, errs)
			}
			wantStored, wantCalls := ingest.MaxFindings, 2
			if tc.want == ingestExitOK {
				wantStored, wantCalls = ingest.MaxFindings+1, 3
			}
			_, total, err := st.ListFindings(context.Background(), store.FindingFilter{Check: "ext.kubescape"})
			mu.Lock()
			defer mu.Unlock()
			if err != nil || total != wantStored || calls != wantCalls {
				t.Fatalf("unexpected partial delivery: stored=%d requests=%d err=%v", total, calls, err)
			}
		})
	}
}

func TestKubescapeBatchPreflightBeforeHTTP(t *testing.T) {
	file := kubescapeBatchFixture(t, ingest.MaxFindings+1, "")
	var calls atomic.Int64
	hs := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer hs.Close()
	// Complete reports keep their existing single-request validation boundary.
	if code, _, _ := postKubescapeFixture(t, file, hs.URL); code != ingestExitUsage || calls.Load() != 0 {
		t.Fatalf("complete report split or posted: exit=%d calls=%d", code, calls.Load())
	}
	original := ingestParsers["kubescape"]
	ingestParsers["kubescape"] = func(data []byte, opts ingest.ParseOptions) ([]ingest.Finding, error) {
		findings, err := original(data, opts)
		if err == nil {
			findings[len(findings)-1].Severity = "invalid"
		}
		return findings, err
	}
	t.Cleanup(func() { ingestParsers["kubescape"] = original })
	if code, _, errs := postKubescapeFixture(t, file, hs.URL, "--incomplete"); code != ingestExitUsage || calls.Load() != 0 || !strings.Contains(errs, "batch 2") {
		t.Fatalf("invalid later batch reached HTTP: exit=%d calls=%d %s", code, calls.Load(), errs)
	}
}
