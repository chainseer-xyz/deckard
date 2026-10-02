// Package fakenuclei is test support: a fake nuclei binary (built from
// ./cmd/fakenuclei) that records its argv, "updates" templates from a fixture
// tree and emits JSONL for templates whose probe matches a real HTTP response,
// plus helpers to write fake template trees. It never ships in the product.
package fakenuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Template describes one fake template file.
type Template struct {
	Path     string // relative, e.g. http/cves/2025/CVE-2025-55182.yaml
	ID       string
	Name     string
	Severity string // default high
	Tags     []string
	CVE      string // classification.cve-id when set
	Body     string // appended verbatim after the header (default: a tiny http block)
}

// YAML renders the template in nuclei's layout (id, info, then a request block).
func (t Template) YAML() string {
	sev := t.Severity
	if sev == "" {
		sev = "high"
	}
	name := t.Name
	if name == "" {
		name = t.ID
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id: %s\n\ninfo:\n  name: %s\n  author: test\n  severity: %s\n", t.ID, name, sev)
	b.WriteString("  description: |\n    fake template for tests\n")
	if t.CVE != "" {
		fmt.Fprintf(&b, "  classification:\n    cvss-score: 9.8\n    cve-id: %s\n    cwe-id: CWE-502\n", t.CVE)
	}
	if len(t.Tags) > 0 {
		fmt.Fprintf(&b, "  tags: %s\n", strings.Join(t.Tags, ","))
	}
	body := t.Body
	if body == "" {
		body = "variables:\n  n: \"{{rand_int(1, 9)}}\"\n\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: status\n        status: [200]\n"
	}
	b.WriteString("\n" + body)
	return b.String()
}

// WriteTree writes templates (and a couple of non-template files, like a real
// release) below root.
func WriteTree(tb testing.TB, root string, ts ...Template) {
	tb.Helper()
	for _, t := range ts {
		p := filepath.Join(root, filepath.FromSlash(t.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(t.YAML()), 0o600); err != nil {
			tb.Fatal(err)
		}
	}
	for name, body := range map[string]string{"README.md": "# fake nuclei-templates\n", "profiles/cves.yml": "id: cves\ntype: http\n"} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if _, err := os.Stat(p); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			tb.Fatal(err)
		}
	}
}

// BulkTemplates returns n filler http templates (ids filler-0..), so a tree can
// clear the updater's minimum-size checks.
func BulkTemplates(n int) []Template {
	out := make([]Template, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Template{
			Path: fmt.Sprintf("http/misconfiguration/filler-%d.yaml", i), ID: fmt.Sprintf("filler-%d", i),
			Severity: "info", Tags: []string{"misconfig", "filler"},
		})
	}
	return out
}
