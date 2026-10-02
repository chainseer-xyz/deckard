//go:build live

package updater_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/nuclei/templates"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
)

// TestLiveUpdate really runs `nuclei -update-templates` (one GitHub download of
// about 15 MB) into a temp dir with the production limits, then checks a
// second run is a no-op. Run with:
//
//	go test -tags live -run TestLiveUpdate -v ./internal/nuclei/updater
//
// Set NUCLEI_BIN to use a specific binary (default: nuclei on PATH).
func TestLiveUpdate(t *testing.T) {
	bin := os.Getenv("NUCLEI_BIN")
	if bin == "" {
		p, err := exec.LookPath("nuclei")
		if err != nil {
			t.Skip("needs the nuclei binary (PATH or NUCLEI_BIN)")
		}
		bin = p
	}
	dir := filepath.Join(t.TempDir(), "nuclei-templates")
	u, err := updater.New(updater.Config{Dir: dir, Binary: bin, Timeout: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := u.Update(ctx)
	if err != nil {
		t.Fatalf("live update: %v", err)
	}
	t.Logf("installed %s: %d templates", res.Version, res.TemplateCount)
	if !res.Changed || res.TemplateCount < 5000 || res.Version == "" {
		t.Fatalf("result = %+v", res)
	}
	cur, err := u.CurrentDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cur, "http", "cves")); err != nil {
		t.Fatalf("no http/cves in the release: %v", err)
	}
	tree, err := templates.Scan(cur)
	if err != nil {
		t.Fatal(err)
	}
	var cves int
	for _, m := range tree.Templates {
		if m.Scannable() && len(m.CVEs) > 0 {
			cves++
		}
	}
	t.Logf("%d scannable templates carry a CVE classification", cves)
	if cves < 1000 {
		t.Errorf("only %d CVE templates", cves)
	}
	// Second run: same upstream release, nothing to do.
	again, err := u.Update(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed || again.Version != res.Version {
		t.Errorf("second update = %+v, want unchanged %s", again, res.Version)
	}
	st, err := u.Status()
	if err != nil || st.LastError != "" || st.Version != res.Version {
		t.Errorf("status = %+v err %v", st, err)
	}
}
