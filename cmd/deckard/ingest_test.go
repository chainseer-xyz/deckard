package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const testIngestToken = "tok-NEVER-PRINT-ME-7f3a"

func prowlerFixture(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "internal", "ingest", "prowler", "testdata", "ocsf.json")
}

// runI runs `deckard ingest` with the test token in the environment and
// fails the test if the token shows up in any output.
func runI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("DECKARD_TEST_TOKEN", testIngestToken)
	var out, errb bytes.Buffer
	code := run(append([]string{"ingest"}, args...), &out, &errb)
	if strings.Contains(out.String()+errb.String(), testIngestToken) {
		t.Fatalf("token printed:\nstdout: %s\nstderr: %s", out.String(), errb.String())
	}
	return code, out.String(), errb.String()
}

func TestIngestDryRunPrintsAValidRequest(t *testing.T) {
	code, out, errs := runI(t, "--tool", "prowler", "--scope", "aws:123456789012:us-west-2", "--file", prowlerFixture(t),
		"--dry-run", "--token-env", "DECKARD_TEST_TOKEN", "--observed-at", "2026-10-03T07:00:00Z", "-v")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	r, err := ingest.Decode([]byte(out))
	if err != nil {
		t.Fatalf("dry-run output is not a request: %v\n%s", err, out)
	}
	if r.Tool != "prowler" || !r.Complete || len(r.Findings) != 3 || r.ObservedAt.UTC().Format("2006-01-02T15:04:05Z") != "2026-10-03T07:00:00Z" {
		t.Fatalf("request %+v", r)
	}
	if !strings.Contains(errs, "3 findings from") {
		t.Errorf("verbose output: %s", errs)
	}
}

func TestIngestReadsStdinAndHonoursIncompleteAndFormat(t *testing.T) {
	stdin = strings.NewReader(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[{"ruleId":"r1","message":{"text":"m"}}]}]}`)
	defer func() { stdin = os.Stdin }()
	code, out, errs := runI(t, "--tool", "semgrep", "--format", "sarif", "--scope", "github.com/example/app", "--incomplete", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var r ingest.Request
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Complete || r.Tool != "semgrep" || len(r.Findings) != 1 {
		t.Fatalf("request %+v err %v", r, err)
	}
}

func TestIngestUsageErrors(t *testing.T) {
	f := prowlerFixture(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no tool", []string{"--scope", "s", "--file", f, "--dry-run"}, "--tool must match"},
		{"bad tool", []string{"--tool", "Prowler", "--scope", "s", "--file", f, "--dry-run"}, "--tool must match"},
		{"unknown format", []string{"--tool", "zap", "--scope", "s", "--file", f, "--dry-run"}, "unknown --format \"zap\""},
		{"no scope", []string{"--tool", "prowler", "--file", f, "--dry-run"}, "--scope is required"},
		{"no url", []string{"--tool", "prowler", "--scope", "s", "--file", f, "--token-env", "DECKARD_TEST_TOKEN"}, "--url is required"},
		{"credentials in url", []string{"--tool", "prowler", "--scope", "s", "--file", f, "--token-env", "DECKARD_TEST_TOKEN", "--url", "https://u:" + testIngestToken + "@deckard.example.com"}, "must not contain credentials"},
		{"no token env", []string{"--tool", "prowler", "--scope", "s", "--file", f, "--url", "https://deckard.example.com"}, "--token-env is required"},
		{"empty token", []string{"--tool", "prowler", "--scope", "s", "--file", f, "--url", "https://deckard.example.com", "--token-env", "DECKARD_TEST_UNSET_VAR"}, "is empty or unset"},
		{"bad observed_at", []string{"--tool", "prowler", "--scope", "s", "--file", f, "--dry-run", "--observed-at", "yesterday"}, "--observed-at"},
		{"missing file", []string{"--tool", "prowler", "--scope", "s", "--file", "/nonexistent/x.json", "--dry-run"}, "open --file"},
		{"unknown flag", []string{"--bogus"}, "flag provided but not defined"},
		{"extra argument", []string{"--tool", "prowler", "--scope", "s", "extra"}, "unexpected argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errs := runI(t, tc.args...)
			if code != ingestExitUsage || !strings.Contains(errs, tc.want) {
				t.Fatalf("exit %d, stderr %q, want 1 and %q", code, errs, tc.want)
			}
		})
	}
	code, out, _ := runI(t, "--help")
	if code != 0 || !strings.Contains(out, "Exit codes") {
		t.Fatalf("--help: %d %s", code, out)
	}
}

func TestIngestParseErrorPostsNothing(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	bad := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(bad, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runI(t, "--tool", "prowler", "--scope", "s", "--file", bad, "--url", srv.URL, "--token-env", "DECKARD_TEST_TOKEN")
	if code != ingestExitUsage || !strings.Contains(errs, "empty") || hits.Load() != 0 {
		t.Fatalf("exit %d hits %d: %s", code, hits.Load(), errs)
	}
}

type fakeDeckard struct {
	t       *testing.T
	replies []func(w http.ResponseWriter)
	n       atomic.Int64
	bodies  [][]byte
}

func (f *fakeDeckard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i := int(f.n.Add(1)) - 1
	if r.URL.Path != "/base/api/v1/ingest" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+testIngestToken ||
		r.Header.Get("Content-Type") != "application/json" {
		f.t.Errorf("unexpected request %s %s auth=%v ct=%s", r.Method, r.URL.Path, r.Header.Get("Authorization") != "", r.Header.Get("Content-Type"))
	}
	b, _ := io.ReadAll(r.Body)
	f.bodies = append(f.bodies, b)
	if i >= len(f.replies) {
		i = len(f.replies) - 1
	}
	f.replies[i](w)
}

func reply(code int, body string, hdr ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

func postWith(t *testing.T, fd *fakeDeckard, extra ...string) (int, string, string) {
	t.Helper()
	backoffUnit = time.Millisecond
	t.Cleanup(func() { backoffUnit = time.Second })
	srv := httptest.NewServer(fd)
	defer srv.Close()
	args := append([]string{"--tool", "prowler", "--scope", "aws:123456789012:us-west-2", "--file", prowlerFixture(t),
		"--url", srv.URL + "/base/", "--token-env", "DECKARD_TEST_TOKEN", "--timeout", "20s"}, extra...)
	return runI(t, args...)
}

func TestIngestPostOutcomes(t *testing.T) {
	ok := `{"accepted":3,"opened":3,"reopened":0,"refreshed":0,"resolved_pending":0,"resolved":0,"complete":true,"replay":false,"rejected":[]}`
	t.Run("applied", func(t *testing.T) {
		fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){reply(200, ok)}}
		code, out, errs := postWith(t, fd)
		if code != ingestExitOK || !strings.Contains(out, "accepted=3 opened=3") {
			t.Fatalf("exit %d out %q err %q", code, out, errs)
		}
		if _, err := ingest.Decode(fd.bodies[0]); err != nil {
			t.Fatalf("posted body: %v", err)
		}
	})
	t.Run("replay is success", func(t *testing.T) {
		fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){reply(200, `{"accepted":0,"opened":0,"reopened":0,"refreshed":0,"resolved_pending":0,"resolved":0,"complete":false,"replay":true,"note":"same request","rejected":[]}`)}}
		if code, _, errs := postWith(t, fd); code != ingestExitOK {
			t.Fatalf("exit %d: %s", code, errs)
		}
	})
	t.Run("partial is a rejection", func(t *testing.T) {
		fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){reply(200, `{"accepted":2,"opened":2,"reopened":0,"refreshed":0,"resolved_pending":0,"resolved":0,"complete":false,"replay":false,"note":"1 item(s) rejected","rejected":[{"index":1,"reason":"asset.ref: no such asset"}]}`)}}
		code, _, errs := postWith(t, fd)
		if code != ingestExitRejected || !strings.Contains(errs, "findings[1]: asset.ref: no such asset") {
			t.Fatalf("exit %d: %s", code, errs)
		}
	})
	t.Run("422 lists every problem", func(t *testing.T) {
		fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){reply(422, `{"error":{"code":"invalid_request","message":"request rejected"},"rejected":[{"index":0,"reason":"bad severity"},{"index":-1,"reason":"scope is required"}]}`)}}
		code, _, errs := postWith(t, fd)
		if code != ingestExitRejected || !strings.Contains(errs, "findings[0]: bad severity") || !strings.Contains(errs, "scope is required") || fd.n.Load() != 1 {
			t.Fatalf("exit %d calls %d: %s", code, fd.n.Load(), errs)
		}
	})
	t.Run("a server echoing the token never gets it printed", func(t *testing.T) {
		fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){reply(401, `{"error":{"code":"unauthenticated","message":"bad token Bearer `+testIngestToken+`"}}`)}}
		code, _, errs := postWith(t, fd, "-v") // runI fails the test if the token appears
		if code != ingestExitRejected || !strings.Contains(errs, "[REDACTED]") {
			t.Fatalf("exit %d: %s", code, errs)
		}
	})
	t.Run("429 and 5xx are retried with the same body", func(t *testing.T) {
		fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){
			reply(429, `{"error":{"code":"rate_limited","message":"slow down"}}`, "Retry-After", "1"),
			reply(503, `{"error":{"code":"x","message":"y"}}`),
			reply(200, ok),
		}}
		code, _, errs := postWith(t, fd)
		if code != ingestExitOK || fd.n.Load() != 3 || !bytes.Equal(fd.bodies[0], fd.bodies[2]) {
			t.Fatalf("exit %d calls %d: %s", code, fd.n.Load(), errs)
		}
	})
	t.Run("persistent 5xx is a rejection", func(t *testing.T) {
		fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){reply(500, `{"error":{"code":"internal","message":"internal error"}}`)}}
		code, _, errs := postWith(t, fd, "--timeout", "30s")
		if code != ingestExitRejected || fd.n.Load() != 4 {
			t.Fatalf("exit %d calls %d: %s", code, fd.n.Load(), errs)
		}
	})
}

func TestIngestNetworkError(t *testing.T) {
	backoffUnit = time.Millisecond
	t.Cleanup(func() { backoffUnit = time.Second })
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	code, _, errs := runI(t, "--tool", "prowler", "--scope", "s", "--file", prowlerFixture(t), "--url", url,
		"--token-env", "DECKARD_TEST_TOKEN", "--timeout", "3s")
	if code != ingestExitNetwork || !strings.Contains(errs, "could not reach deckard") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestScrubber(t *testing.T) {
	var b bytes.Buffer
	s := &scrubber{w: &b, secret: "s3cr3t"}
	n, err := s.Write([]byte("a s3cr3t b s3cr3t"))
	if err != nil || n != len("a s3cr3t b s3cr3t") || b.String() != "a [REDACTED] b [REDACTED]" {
		t.Fatalf("%d %v %q", n, err, b.String())
	}
}

// Every parser's fixture, posted by the CLI, is accepted by the real API
// handler and lands as ext.<tool> findings: the CLI, the parsers and the
// server agree on the contract.
func TestIngestAgainstTheRealAPI(t *testing.T) {
	st := fakestore.New()
	srv := api.New(api.Deps{
		Store: st, Authenticator: auth.NewToken(testIngestToken), BaseURL: "https://deckard.example.com",
		Ingester: finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 2}, nil),
		Ingest:   config.IngestConfig{Enabled: true, RateLimit: "100/s", Burst: 100},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	fixtures := map[string]string{
		"prowler": "prowler/testdata/ocsf.json", "kubescape": "kubescape/testdata/results.json",
		"trufflehog": "trufflehog/testdata/git.jsonl", "gitleaks": "gitleaks/testdata/report.json",
		"s3scanner": "s3scanner/testdata/scan.jsonl", "sarif": "sarif/testdata/scan.sarif",
	}
	for tool, fx := range fixtures {
		code, out, errs := runI(t, "--tool", tool, "--scope", "scope-"+tool, "--file", filepath.Join("..", "..", "internal", "ingest", fx),
			"--url", hs.URL, "--token-env", "DECKARD_TEST_TOKEN")
		if code != ingestExitOK {
			t.Fatalf("%s: exit %d\n%s%s", tool, code, out, errs)
		}
		fs, _, err := st.ListFindings(context.Background(), store.FindingFilter{Check: "ext." + tool})
		if err != nil || len(fs) == 0 {
			t.Fatalf("%s: %d findings stored, err %v", tool, len(fs), err)
		}
		for _, f := range fs {
			if f.Source != "ingest:"+tool || f.IngestScope != "scope-"+tool {
				t.Fatalf("%s: finding %+v", tool, f)
			}
		}
	}
}
