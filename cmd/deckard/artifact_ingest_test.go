package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func artifactFixture(format string) string {
	return filepath.Join("..", "..", "internal", "ingest", format, "testdata", "image.json")
}

func TestArtifactDryRunRetainsGraph(t *testing.T) {
	for _, tool := range []string{"trivy", "cyclonedx"} {
		t.Run(tool, func(t *testing.T) {
			code, out, errs := runI(t, "--tool", tool, "--scope", "image:web", "--file", artifactFixture(tool), "--dry-run")
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errs)
			}
			r, err := ingest.Decode([]byte(out))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Artifacts) < 2 || len(r.Relations) == 0 || r.Artifacts[0].Kind != model.KindContainerImage {
				t.Fatalf("image/package graph discarded: %+v", r)
			}
			if tool == "cyclonedx" {
				if r.Complete || len(r.Findings) != 0 || !strings.Contains(errs, "SBOM") {
					t.Fatalf("SBOM claimed a CVE scan: %+v, %s", r, errs)
				}
			} else if !r.Complete || len(r.Findings) != 1 {
				t.Fatalf("Trivy run: %+v", r)
			}
			if strings.Contains(out+errs, "DO-NOT-RETAIN-TEST-MARKER") {
				t.Fatal("raw scanner metadata leaked")
			}
		})
	}
}

func TestCycloneDXPostsSuccessfullyWithoutResolvingFindings(t *testing.T) {
	var got *ingest.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		got, err = ingest.Decode(b)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+testIngestToken {
			t.Error("missing normal bearer authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(ingest.Response{Complete: false, Accepted: len(got.Findings), Rejected: []ingest.Rejection{}}); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	code, out, errs := runI(t, "--tool", "cyclonedx", "--scope", "image:web", "--file", artifactFixture("cyclonedx"), "--url", srv.URL, "--token-env", "DECKARD_TEST_TOKEN")
	if code != 0 || got == nil || got.Complete || len(got.Findings) != 0 || len(got.Artifacts) != 3 {
		t.Fatalf("SBOM posting exit=%d request=%+v output=%s error=%s", code, got, out, errs)
	}
}

func TestArtifactFormatCannotUseAnotherToolLifecycle(t *testing.T) {
	for _, tool := range []string{"trivy", "cyclonedx"} {
		for _, producer := range []string{"prowler", "sarif", "other"} {
			t.Run(tool+" as "+producer, func(t *testing.T) {
				code, _, errs := runI(t, "--tool", producer, "--format", tool, "--scope", "scope", "--file", artifactFixture(tool), "--dry-run")
				if code != ingestExitUsage || !strings.Contains(errs, "must match --tool") {
					t.Fatalf("exit %d: %s", code, errs)
				}
			})
		}
	}
	for _, tool := range []string{"trivy", "cyclonedx"} {
		code, _, errs := runI(t, "--tool", tool, "--format", "sarif", "--scope", "scope", "--file", prowlerFixture(t), "--dry-run")
		if code != ingestExitUsage || !strings.Contains(errs, "must match --tool") {
			t.Fatalf("native producer borrowed another format: exit=%d %s", code, errs)
		}
	}
}

func TestArtifactParserFailuresPostNothing(t *testing.T) {
	for _, tool := range []string{"trivy", "cyclonedx"} {
		t.Run(tool, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("failed input reached API")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			code, _, _ := runI(t, "--tool", tool, "--scope", "image:web", "--file", prowlerFixture(t), "--url", srv.URL, "--token-env", "DECKARD_TEST_TOKEN")
			if code != ingestExitUsage {
				t.Fatalf("invalid input exit=%d", code)
			}
		})
	}
}

func TestArtifactAgainstRealAPI(t *testing.T) {
	st := fakestore.New()
	srv := api.New(api.Deps{
		Store: st, Authenticator: auth.NewToken(testIngestToken), BaseURL: "https://deckard.example.com",
		Ingester: finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1}, nil),
		Ingest:   config.IngestConfig{Enabled: true, RateLimit: "100/s", Burst: 100},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	for _, tool := range []string{"trivy", "cyclonedx"} {
		code, out, errs := runI(t, "--tool", tool, "--scope", "image:web", "--file", artifactFixture(tool), "--url", hs.URL, "--token-env", "DECKARD_TEST_TOKEN")
		if code != 0 {
			t.Fatalf("%s exit=%d: %s%s", tool, code, out, errs)
		}
	}
	ctx := context.Background()
	image, err := st.GetAssetByKey(ctx, model.KindContainerImage, "sha256:"+strings.Repeat("a", 64))
	if err != nil || image == nil || image.Scope != model.ScopeExternal {
		t.Fatalf("immutable external image: %+v %v", image, err)
	}
	if len(image.SourceFacts) != 2 {
		t.Fatalf("scanner source facts were lost: %+v", image.SourceFacts)
	}
	edges, err := st.Edges(ctx, image.ID)
	if err != nil || len(edges) != 2 {
		t.Fatalf("image/package edges=%d error=%v", len(edges), err)
	}
	fs, total, err := st.ListFindings(ctx, store.FindingFilter{Check: "ext.trivy"})
	if err != nil || total != 1 || len(fs) != 1 || fs[0].Status != model.StatusOpen {
		t.Fatalf("Trivy lifecycle changed: total=%d error=%v", total, err)
	}
}

func TestArtifactInputReaderStopsAtBound(t *testing.T) {
	previous := stdin
	defer func() { stdin = previous }()
	reader := strings.NewReader(strings.Repeat("x", 4096))
	stdin = reader
	if _, _, err := readIngestInput("", 1024); err == nil {
		t.Fatal("input over the native bound accepted")
	}
	if reader.Len() != 4096-1025 {
		t.Fatalf("reader consumed more than limit+1 bytes: remaining=%d", reader.Len())
	}
}
