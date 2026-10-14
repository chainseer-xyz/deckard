package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/imagecollector"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"k8s.io/client-go/kubernetes/fake"
)

const imagesScope = "k8s:uid:11111111-1111-4111-8111-111111111111:runtime-images"

func TestImagesCLIRequiresExplicitAuthorityBeforeKubernetes(t *testing.T) {
	for _, args := range [][]string{
		{"collect", "--cluster-scope", imagesScope, "--dry-run"},
		{"collect", "--all-namespaces", "--dry-run"},
		{"collect", "--namespaces", "apps", "--all-namespaces", "--cluster-scope", imagesScope, "--dry-run"},
		{"collect", "--all-namespaces", "--cluster-scope", imagesScope, "--timeout", "46m", "--dry-run"},
		{"collect", "--all-namespaces", "--cluster-scope", imagesScope, "--output", "/report/request.json", "--token-env", "TOKEN"},
	} {
		var out, errw bytes.Buffer
		called := false
		code := runImagesWith(args, &out, &errw, func() (imagecollector.Inventory, error) { called = true; return fake.NewClientset().CoreV1(), nil })
		if code == 0 || called {
			t.Fatalf("invalid flags contacted inventory: %v code%d called%v", args, code, called)
		}
	}
}

func TestImagesCollectWritesOneFreshValidatedEnvelopeWithoutToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "request.json")
	var out, errw bytes.Buffer
	load := func() (imagecollector.Inventory, error) { return fake.NewClientset().CoreV1(), nil }
	args := []string{"collect", "--all-namespaces", "--cluster-scope", imagesScope, "--output", file}
	if code := runImagesWith(args, &out, &errw, load); code != 0 {
		t.Fatalf("exit%d %s", code, errw.String())
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var request ingest.Request
	if err = json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	if request.Tool != "trivy" || request.Scope != imagesScope || !request.Complete || request.Findings == nil {
		t.Fatalf("invalid fresh request: %+v", request)
	}
	if code := runImagesWith(args, &out, &errw, load); code == 0 {
		t.Fatal("existing report overwritten")
	}
}

func TestImagesUploadPostsBoundedScopeCheckedEnvelope(t *testing.T) {
	t.Setenv("IMAGES_TEST_TOKEN", testIngestToken)
	now := time.Now().UTC()
	request := ingest.Request{Tool: "trivy", Scope: imagesScope, Complete: false, ObservedAt: &now, Findings: []ingest.Finding{}}
	file := filepath.Join(t.TempDir(), "request.json")
	write := func() {
		t.Helper()
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/api/v1/ingest" || r.Header.Get("Authorization") != "Bearer "+testIngestToken || !strings.Contains(string(body), `"complete":false`) {
			t.Error("wrong upload authority/body")
		}
		_, _ = io.WriteString(w, `{"accepted":0,"complete":false,"rejected":[]}`)
	}))
	defer server.Close()
	args := []string{"upload", "--file", file, "--cluster-scope", imagesScope, "--url", server.URL, "--token-env", "IMAGES_TEST_TOKEN"}
	var out, errw bytes.Buffer
	if code := runImages(args, &out, &errw); code != 0 || hits != 1 {
		t.Fatalf("exit%d hits%d %s", code, hits, errw.String())
	}
	if strings.Contains(out.String()+errw.String(), testIngestToken) {
		t.Fatal("upload token leaked")
	}
	request.Scope = "another-scope"
	write()
	if code := runImages(args, &out, &errw); code == 0 || hits != 1 {
		t.Fatal("wrong reconciliation scope posted")
	}
	request.Scope = imagesScope
	request.Tool = "prowler"
	write()
	if code := runImages(args, &out, &errw); code == 0 || hits != 1 {
		t.Fatal("wrong producer posted")
	}
	request.Tool = "trivy"
	old := now.Add(-2 * time.Hour)
	request.ObservedAt = &old
	write()
	if code := runImages(args, &out, &errw); code == 0 || hits != 1 {
		t.Fatal("stale output posted as fresh")
	}
}
