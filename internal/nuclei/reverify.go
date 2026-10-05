package nuclei

import (
	"log/slog"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/nuclei/templates"
)

// templateIndex maps template ids to their header metadata for one template
// release. Releases are immutable once installed, so the parsed tree is cached
// per resolved root.
type templateIndex struct {
	mu   sync.Mutex
	root string
	byID map[string]templates.Meta
}

func (x *templateIndex) lookup(root string) (map[string]templates.Meta, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.byID != nil && x.root == root {
		return x.byID, nil
	}
	t, err := templates.Scan(root)
	if err != nil {
		return nil, err
	}
	m := make(map[string]templates.Meta, len(t.Templates))
	for _, meta := range t.Templates {
		if _, dup := m[meta.ID]; !dup {
			m[meta.ID] = meta
		}
	}
	x.root, x.byID = root, m
	return m, nil
}

// reverifyPlan is what a full scan must additionally run so that every
// unresolved finding is re-verified by the template that produced it.
type reverifyPlan struct {
	// Files are absolute template paths to run explicitly (deduplicated, not
	// already selected by the tech tags).
	Files []string
	// Covered counts findings whose template the tech selection already runs.
	Covered int
	// Missing are template ids no longer in the active set: nothing can
	// reproduce those findings, so they accrue misses and resolve normally.
	Missing []string
	// Unverifiable is true when absence cannot be trusted: the findings could
	// not all be mapped to a template (no usable template directory, findings
	// without a template id, or more findings than the engine hands over).
	Unverifiable bool
}

// templateIDOf returns the template id a finding was reported for.
func templateIDOf(f check.OpenFinding) string {
	id, _ := f.Evidence["template_id"].(string)
	return strings.TrimSpace(id)
}

// planReverify decides which template files re-verify open. root is the
// resolved template directory ("" when none is known), tags the tech selection.
func (x *templateIndex) planReverify(root string, open []check.OpenFinding, tags []string) (reverifyPlan, error) {
	var p reverifyPlan
	if len(open) == 0 {
		return p, nil
	}
	if len(open) > check.MaxOpenFindings {
		p.Unverifiable = true // a direct caller supplied more than the bounded view
		open = open[:check.MaxOpenFindings]
	}
	if root == "" {
		p.Unverifiable = true
		return p, nil
	}
	idx, err := x.lookup(root)
	if err != nil {
		return p, err
	}
	seenID := map[string]bool{}
	seenFile := map[string]bool{}
	for _, f := range open {
		id := templateIDOf(f)
		if id == "" {
			p.Unverifiable = true
			continue
		}
		if seenID[id] {
			continue
		}
		seenID[id] = true
		m, ok := idx[id]
		if !ok || !m.Scannable() {
			p.Missing = append(p.Missing, id)
			continue
		}
		if tagCovered(m, tags) {
			p.Covered++
			continue
		}
		abs, ok := safeTemplate(root, filepath.Join(root, filepath.FromSlash(m.Path)))
		if !ok {
			p.Missing = append(p.Missing, id)
			continue
		}
		if !seenFile[abs] {
			seenFile[abs] = true
			p.Files = append(p.Files, abs)
		}
	}
	return p, nil
}

// tagCovered reports whether nuclei's -tags selection (any tag matches) already
// picks the template.
func tagCovered(m templates.Meta, tags []string) bool {
	for _, t := range tags {
		if m.HasTag(t) {
			return true
		}
	}
	return false
}

// missingLogged makes the "template removed" notice appear once per process
// and template id, not on every scan.
var missingLogged sync.Map

func logMissingOnce(ids []string, asset string) {
	for _, id := range ids {
		if _, seen := missingLogged.LoadOrStore(id, struct{}{}); !seen {
			slog.Info("nuclei: template of an open finding is no longer in the active set; the finding can only resolve",
				"template", id, "asset", asset)
		}
	}
}
