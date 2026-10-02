package templates_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/templates"
)

func TestParseHeader(t *testing.T) {
	doc := `id: CVE-2025-55182

info:
  name: React Server Components - Remote Code Execution
  severity: Critical
  classification:
    cvss-score: 10
    cve-id: cve-2025-55182
    cwe-id: CWE-502
  tags: cve,cve2025,react, rce ,nextjs

variables:
  id: "x: y"

http:
  - raw:
      - |
        POST / HTTP/1.1
`
	m, err := templates.ParseHeader([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "CVE-2025-55182" || m.Severity != "critical" || m.Name == "" {
		t.Errorf("meta = %+v", m)
	}
	if !slices.Equal(m.Tags, []string{"cve", "cve2025", "react", "rce", "nextjs"}) {
		t.Errorf("tags = %v", m.Tags)
	}
	if !slices.Equal(m.CVEs, []string{"CVE-2025-55182"}) {
		t.Errorf("cves = %v", m.CVEs)
	}
}

func TestParseHeaderListForms(t *testing.T) {
	m, err := templates.ParseHeader([]byte("id: x\ninfo:\n  tags:\n    - a\n    - b,c\n  classification:\n    cve-id:\n      - CVE-2024-1\n      - CVE-2024-2\nhttp:\n  - x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Tags, []string{"a", "b", "c"}) || !slices.Equal(m.CVEs, []string{"CVE-2024-1", "CVE-2024-2"}) {
		t.Errorf("%+v", m)
	}
	if _, err := templates.ParseHeader([]byte("id: [unterminated\n")); err == nil {
		t.Error("malformed header must error")
	}
}

func TestScanAndLookup(t *testing.T) {
	root := t.TempDir()
	fakenuclei.WriteTree(t, root,
		fakenuclei.Template{Path: "http/cves/2025/CVE-2025-55182.yaml", ID: "CVE-2025-55182", Severity: "critical", Tags: []string{"cve", "react", "nextjs"}, CVE: "CVE-2025-55182"},
		fakenuclei.Template{Path: "http/vulnerabilities/other/renamed.yaml", ID: "react-rsc-rce", Severity: "critical", Tags: []string{"react"}, CVE: "CVE-2025-55182,CVE-2025-66478"},
		fakenuclei.Template{Path: "network/cves/2024/CVE-2024-6387.yaml", ID: "CVE-2024-6387", Tags: []string{"cve", "ssh"}, CVE: "CVE-2024-6387"},
		fakenuclei.Template{Path: "ssl/expired-ssl.yaml", ID: "expired-ssl", Severity: "low"},
		fakenuclei.Template{Path: "dns/caa.yaml", ID: "caa-fingerprint", Severity: "info"},
		fakenuclei.Template{Path: "code/cves/2026/CVE-2026-8467.yaml", ID: "CVE-2026-8467", CVE: "CVE-2026-8467"},
		fakenuclei.Template{Path: "javascript/enum/x.yaml", ID: "js-enum"},
		fakenuclei.Template{Path: "workflows/wp.yaml", ID: "wp-workflow"},
	)
	// A broken file is skipped, never fatal; a non-yaml file is ignored.
	if err := os.WriteFile(filepath.Join(root, "http", "broken.yaml"), []byte("id: [oops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(root, "http", "link")); err != nil {
		t.Fatal(err)
	}
	tree, err := templates.Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", tree.Skipped)
	}
	by := map[string]templates.Meta{}
	for _, m := range tree.Templates {
		by[m.ID] = m
	}
	if _, ok := by["wp-workflow"]; ok {
		t.Error("workflows must not be listed as templates")
	}
	for id, proto := range map[string]string{"CVE-2025-55182": "http", "CVE-2024-6387": "tcp", "expired-ssl": "ssl", "caa-fingerprint": "dns", "CVE-2026-8467": "", "js-enum": ""} {
		m, ok := by[id]
		if !ok || m.Protocol != proto || m.Scannable() != (proto != "") {
			t.Errorf("%s = %+v ok=%v, want protocol %q", id, m, ok, proto)
		}
	}
	var hits []string
	for _, m := range tree.Templates {
		if m.Scannable() && m.MatchesCVE("cve-2025-55182") {
			hits = append(hits, m.Path)
		}
	}
	slices.Sort(hits)
	want := []string{"http/cves/2025/CVE-2025-55182.yaml", "http/vulnerabilities/other/renamed.yaml"}
	if !slices.Equal(hits, want) {
		t.Errorf("CVE lookup = %v, want %v (id match and classification match)", hits, want)
	}
	if !by["CVE-2025-55182"].HasTag("NextJS") {
		t.Error("HasTag must be case-insensitive")
	}
}

func TestIsTemplatePathAndProtocolOf(t *testing.T) {
	for p, want := range map[string]bool{
		"http/cves/a.yaml": true, "http/a.yml": true, "profiles/x.yml": false, "workflows/w.yaml": false,
		"helpers/payloads/p.yaml": false, "README.md": false, "cves.json": false, "a.yaml": true,
	} {
		if got := templates.IsTemplatePath(p); got != want {
			t.Errorf("IsTemplatePath(%q) = %v", p, got)
		}
	}
	for p, want := range map[string]string{"http/a.yaml": "http", "network/a.yaml": "tcp", "ssl/a.yaml": "ssl", "dns/a.yaml": "dns", "code/a.yaml": "", "a.yaml": ""} {
		if got := templates.ProtocolOf(p); got != want {
			t.Errorf("ProtocolOf(%q) = %q, want %q", p, got, want)
		}
	}
}
