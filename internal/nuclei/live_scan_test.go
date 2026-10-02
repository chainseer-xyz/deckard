//go:build live

package nuclei

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/nuclei/templates"
)

const liveTemplate = `id: deckard-live-test
info:
  name: Deckard live test
  author: deckard
  severity: high
  tags: cve,test
  classification:
    cve-id: CVE-2099-0001
http:
  - method: GET
    path:
      - "{{BaseURL}}/vuln"
    matchers:
      - type: word
        words: ["vulnerable-marker"]
`

// TestLiveScanner runs the real nuclei binary through Scanner against local
// httptest servers with a one-template set, proving the argv (template list
// file, -pt, -bs, ...) is accepted and that matches are attributed to targets.
// NUCLEI_BIN selects the binary (default: nuclei on PATH).
func TestLiveScanner(t *testing.T) {
	bin := os.Getenv("NUCLEI_BIN")
	if bin == "" {
		p, err := exec.LookPath("nuclei")
		if err != nil {
			t.Skip("needs the nuclei binary (PATH or NUCLEI_BIN)")
		}
		bin = p
	}
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vuln" {
			_, _ = w.Write([]byte("vulnerable-marker"))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()
	clean := httptest.NewServer(http.NotFoundHandler())
	defer clean.Close()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o750); err != nil {
		t.Fatal(err)
	}
	tpl := filepath.Join(root, "http", "deckard-live-test.yaml")
	if err := os.WriteFile(tpl, []byte(liveTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	env := func() ([]string, func(), error) {
		return []string{"HOME=" + state, "XDG_CONFIG_HOME=" + state + "/config", "XDG_CACHE_HOME=" + state + "/cache",
			"NUCLEI_CONFIG_DIR=" + state + "/config/nuclei", "NUCLEI_TEMPLATES_DIR=" + root}, func() {}, nil
	}
	s := NewScanner(config.NucleiConfig{TemplatesDir: root, Binary: bin}, func(context.Context, string) bool { return true },
		ExecRunner{Env: env}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := s.Scan(ctx, ScanRequest{Targets: []ScanTarget{{1, vuln.URL}, {2, clean.URL}}, Templates: []string{tpl}})
	if err != nil {
		t.Fatal(err)
	}
	if fs := res.Findings[1]; len(fs) != 1 || fs[0].Key != "deckard-live-test" {
		t.Fatalf("vulnerable target findings = %+v", res.Findings)
	}
	if len(res.Findings[2]) != 0 {
		t.Errorf("clean target matched: %+v", res.Findings[2])
	}
	got, err := s.LookupCVEs([]string{"CVE-2099-0001"})
	if err != nil || len(got) != 1 || got[0] != "http/deckard-live-test.yaml" {
		t.Errorf("lookup = %v, %v", got, err)
	}
}

// TestLiveTechTagsExist checks every tag of the tech-to-tag table is used by at
// least one scannable template of a real release. Point NUCLEI_TEMPLATES_DIR at
// an installed nuclei-templates tree (for example the updater's current dir).
func TestLiveTechTagsExist(t *testing.T) {
	root := os.Getenv("NUCLEI_TEMPLATES_DIR")
	if root == "" {
		t.Skip("set NUCLEI_TEMPLATES_DIR to a real nuclei-templates tree")
	}
	tree, err := templates.Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]int{}
	for _, m := range tree.Templates {
		if !m.Scannable() {
			continue
		}
		for _, tag := range m.Tags {
			have[strings.ToLower(tag)]++
		}
	}
	for tech, tags := range techTags {
		for _, tag := range tags {
			if have[tag] == 0 {
				t.Errorf("tech %q maps to tag %q, which no template of this release uses", tech, tag)
			}
		}
	}
	for _, tag := range genericTags {
		if have[tag] == 0 {
			t.Errorf("generic tag %q unused by this release", tag)
		}
	}
}
