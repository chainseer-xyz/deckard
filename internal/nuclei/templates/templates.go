// Package templates reads the metadata of a nuclei template tree without
// executing anything: id, severity, tags and CVE classification are parsed
// from each template's YAML header only. It backs the template updater (which
// diffs two releases) and CVE-targeted scans (which find templates by CVE id).
package templates

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// headerLimit bounds how much of a template is read: the id/info header is
// always in the first few KiB, the (possibly huge) request body is irrelevant.
const headerLimit = 16 << 10

// ScannableDirs are the top-level template directories deckard runs: the
// network protocols http, ssl, dns and tcp (nuclei keeps tcp templates under
// network/). code, headless, javascript, file, cloud, dast and workflows are
// never run.
var ScannableDirs = map[string]string{"http": "http", "ssl": "ssl", "dns": "dns", "network": "tcp"}

// Meta is the header metadata of one template.
type Meta struct {
	ID       string
	Path     string // relative to the tree root, slash separated
	Name     string
	Severity string
	Tags     []string
	CVEs     []string // upper case, from classification.cve-id
	Protocol string   // http|ssl|dns|tcp for scannable templates, "" otherwise
}

// Scannable reports whether deckard runs this template.
func (m Meta) Scannable() bool { return m.Protocol != "" }

// HasTag reports whether the template carries tag (case-insensitive).
func (m Meta) HasTag(tag string) bool {
	for _, t := range m.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// MatchesCVE reports whether the template's id or classification names cve
// (case-insensitive, e.g. "CVE-2025-55182").
func (m Meta) MatchesCVE(cve string) bool {
	if strings.EqualFold(m.ID, cve) {
		return true
	}
	for _, c := range m.CVEs {
		if strings.EqualFold(c, cve) {
			return true
		}
	}
	return false
}

// Tree is the parsed metadata of one template tree.
type Tree struct {
	Root      string
	Templates []Meta
	// Skipped counts YAML files whose header could not be parsed.
	Skipped int
}

// IDs returns the set of template ids.
func (t *Tree) IDs() map[string]bool {
	out := make(map[string]bool, len(t.Templates))
	for _, m := range t.Templates {
		out[m.ID] = true
	}
	return out
}

// Paths returns the set of relative paths.
func (t *Tree) Paths() map[string]bool {
	out := make(map[string]bool, len(t.Templates))
	for _, m := range t.Templates {
		out[m.Path] = true
	}
	return out
}

// excludedTop are top-level directories that hold no templates.
var excludedTop = map[string]bool{"profiles": true, "workflows": true, "helpers": true, ".git": true, ".github": true}

// IsTemplatePath reports whether a relative path could be a template: a YAML
// file outside the non-template top-level directories.
func IsTemplatePath(rel string) bool {
	rel = filepath.ToSlash(rel)
	ext := strings.ToLower(filepath.Ext(rel))
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	top, _, _ := strings.Cut(rel, "/")
	return !excludedTop[top]
}

// ProtocolOf maps a relative template path to its scannable protocol, or "".
func ProtocolOf(rel string) string {
	top, rest, ok := strings.Cut(filepath.ToSlash(rel), "/")
	if !ok || rest == "" {
		return ""
	}
	return ScannableDirs[top]
}

// Scan parses every template header below root. Unreadable or malformed files
// are counted in Skipped, never fatal. Symbolic links are not followed.
func Scan(root string) (*Tree, error) {
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			if rel != "." && excludedTop[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks and specials are never followed
		}
		if IsTemplatePath(rel) {
			paths = append(paths, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	type result struct {
		m  Meta
		ok bool
	}
	results := make([]result, len(paths))
	var wg sync.WaitGroup
	work := make(chan int)
	for w := 0; w < min(runtime.GOMAXPROCS(0), 8); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				m, err := ParseFile(root, paths[i])
				results[i] = result{m, err == nil && m.ID != ""}
			}
		}()
	}
	for i := range paths {
		work <- i
	}
	close(work)
	wg.Wait()

	t := &Tree{Root: root}
	for _, r := range results {
		if r.ok {
			t.Templates = append(t.Templates, r.m)
		} else {
			t.Skipped++
		}
	}
	return t, nil
}

// ParseFile reads the header of the template at root/rel.
func ParseFile(root, rel string) (Meta, error) {
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- path comes from walking the template tree
	if err != nil {
		return Meta{}, err
	}
	defer func() { _ = f.Close() }()
	buf, err := io.ReadAll(io.LimitReader(f, headerLimit))
	if err != nil {
		return Meta{}, err
	}
	m, err := ParseHeader(buf)
	m.Path = filepath.ToSlash(rel)
	m.Protocol = ProtocolOf(m.Path)
	return m, err
}

// headerKeys are the top-level keys that belong to the header.
var headerKeys = map[string]bool{"id": true, "info": true}

// cutHeader returns the leading lines up to the first top-level key that is
// not part of the header (variables:, http:, flow:, ...).
func cutHeader(b []byte) []byte {
	var out bytes.Buffer
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '#' && line[0] != '-' && line[0] != '\n' && line[0] != '\r' {
			key, _, _ := bytes.Cut(line, []byte(":"))
			if !headerKeys[strings.TrimSpace(string(key))] {
				break
			}
		}
		out.Write(line)
	}
	return out.Bytes()
}

type header struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string `yaml:"name"`
		Severity       string `yaml:"severity"`
		Tags           any    `yaml:"tags"`
		Classification struct {
			CVEID any `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

// ParseHeader parses the id/info header of a template document.
func ParseHeader(doc []byte) (Meta, error) {
	var h header
	if err := yaml.Unmarshal(cutHeader(doc), &h); err != nil {
		return Meta{}, err
	}
	m := Meta{
		ID: strings.TrimSpace(h.ID), Name: h.Info.Name,
		Severity: strings.ToLower(strings.TrimSpace(h.Info.Severity)),
		Tags:     splitList(h.Info.Tags),
	}
	for _, c := range splitList(h.Info.Classification.CVEID) {
		m.CVEs = append(m.CVEs, strings.ToUpper(c))
	}
	return m, nil
}

// splitList accepts "a, b" or a YAML list.
func splitList(v any) []string {
	var out []string
	add := func(s string) {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	switch x := v.(type) {
	case string:
		add(x)
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				add(s)
			}
		}
	}
	return out
}
