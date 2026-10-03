// Package ingesttest holds the test helpers every ingest parser uses: golden
// files and the check that parser output always makes a valid request.
package ingesttest

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

var update = flag.Bool("update", false, "rewrite the golden files of parser tests")

// Scope is the scope parser tests use.
const Scope = "test:scope"

// Request wraps findings in a request the way the CLI does.
func Request(tool string, fs []ingest.Finding) *ingest.Request {
	obs := time.Date(2026, 10, 3, 7, 0, 0, 0, time.UTC)
	if fs == nil {
		fs = []ingest.Finding{}
	}
	return &ingest.Request{Tool: tool, Scope: Scope, Complete: true, ObservedAt: &obs, Findings: fs}
}

// Valid fails t if fs does not make a valid request.
func Valid(t testing.TB, tool string, fs []ingest.Finding) {
	t.Helper()
	if p := ingest.Validate(Request(tool, fs), ingest.Options{MaxFindings: 1 << 30}); len(p) > 0 {
		t.Fatalf("parser output is not a valid request: %s", ingest.Summary(p))
	}
}

// Golden parses testdata/<name> with p and compares the request it makes
// with testdata/<name>.golden.json (rewritten with -update). It returns the
// findings.
func Golden(t *testing.T, tool string, p ingest.Parser, name string) []ingest.Finding {
	t.Helper()
	in, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	fs, err := p(in, ingest.ParseOptions{Scope: Scope})
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	Valid(t, tool, fs)
	got, err := json.MarshalIndent(Request(tool, fs), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", strings.TrimSuffix(name, filepath.Ext(name))+".golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: output differs from %s (run go test -update and review the diff)\n%s", name, path, got)
	}
	return fs
}

// Fuzz is the body of every parser fuzz test: parsing arbitrary input never
// panics and either fails or yields a valid request.
func Fuzz(t *testing.T, tool string, p ingest.Parser, data []byte) {
	t.Helper()
	fs, err := p(data, ingest.ParseOptions{Scope: Scope})
	if err != nil {
		return
	}
	Valid(t, tool, fs)
}

// Seeds adds every testdata fixture (not golden files) to the fuzz corpus.
func Seeds(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*"))
	for _, p := range files {
		if strings.HasSuffix(p, ".golden.json") {
			continue
		}
		b, err := os.ReadFile(p) // #nosec G304 -- test fixture
		if err == nil {
			f.Add(b)
		}
	}
}
