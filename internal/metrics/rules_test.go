package metrics

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every deckard_* series the example Prometheus rules and the docs mention must
// be defined by this package: a renamed metric must not leave a silent alert.
func TestDocumentedMetricsExist(t *testing.T) {
	var src strings.Builder
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- repo file
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	code := src.String()
	// Non-metric tokens that share the prefix (cookies, labels).
	skip := map[string]bool{"deckard_session": true, "deckard_csrf": true, "deckard_check": true}
	re := regexp.MustCompile(`deckard_[a-z_]+`)
	for _, doc := range []string{"../../deploy/examples/prometheus-rules.yml", "../../docs/operations.md", "../../docs/configuration.md", "../../README.md"} {
		b, err := os.ReadFile(doc) // #nosec G304 -- repo file
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range re.FindAllString(string(b), -1) {
			name = strings.TrimRight(name, "_")
			base := name
			for _, suf := range []string{"_bucket", "_sum", "_count"} {
				base = strings.TrimSuffix(base, suf)
			}
			if skip[name] || strings.Contains(code, `"`+name+`"`) || strings.Contains(code, `"`+base+`"`) {
				continue
			}
			t.Errorf("%s mentions %s, which no metric defines", filepath.Base(doc), name)
		}
	}
}
