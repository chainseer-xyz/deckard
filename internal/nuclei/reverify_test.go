package nuclei

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
)

func reverifyTree(t *testing.T, extra ...fakenuclei.Template) string {
	t.Helper()
	root := t.TempDir()
	ts := []fakenuclei.Template{
		{Path: "http/cves/2099/CVE-2099-0001.yaml", ID: "CVE-2099-0001", CVE: "CVE-2099-0001", Tags: []string{"rce", "kev"}},
		{Path: "http/cves/2099/CVE-2099-0002.yaml", ID: "CVE-2099-0002", CVE: "CVE-2099-0002", Tags: []string{"rce"}},
		{Path: "http/exposure/git.yaml", ID: "git-config", Tags: []string{"exposure"}}, // covered by the generic tags
		{Path: "code/cves/CVE-2099-0003.yaml", ID: "CVE-2099-0003", Tags: []string{"rce"}},
	}
	fakenuclei.WriteTree(t, root, append(ts, extra...)...)
	return root
}

func openOf(ids ...string) []check.OpenFinding {
	var out []check.OpenFinding
	for i, id := range ids {
		out = append(out, check.OpenFinding{
			Fingerprint: fmt.Sprint("fp", i), Severity: model.SeverityHigh, Status: model.StatusOpen,
			Evidence: map[string]any{"template_id": id},
		})
	}
	return out
}

func runReverify(t *testing.T, root string, cfg config.NucleiConfig, open []check.OpenFinding, runner *fakeRunner) (*check.Result, error) {
	t.Helper()
	cfg.TemplatesDir = root
	c := New(cfg, verifyOnly("app.example.com"), runner, false, nil)
	return c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com/"), OpenFindings: open})
}

func templatesOf(args []string) []string {
	var out []string
	for i, a := range args {
		if a == "-t" && i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	return out
}

func TestNucleiCheckWantsOpenFindings(t *testing.T) {
	c := New(config.NucleiConfig{}, nil, &fakeRunner{}, false, nil)
	w, ok := c.(check.WantsOpenFindings)
	if !ok || !w.WantsOpenFindings() {
		t.Fatal("the nuclei check must ask for Target.OpenFindings")
	}
}

// The template behind an open finding is re-run by the full scan even though
// the tech tags do not select it, in a second invocation with the same safety
// flags and nothing but that template.
func TestFullScanReverifiesOpenFindingTemplate(t *testing.T) {
	root := reverifyTree(t)
	fr := &fakeRunner{}
	res, err := runReverify(t, root, config.NucleiConfig{SeverityMin: "medium"}, openOf("CVE-2099-0001"), fr)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("invocations = %d, want the tech scan plus one re-verification", len(fr.calls))
	}
	real, _ := filepath.EvalSymlinks(root)
	if got := templatesOf(fr.calls[0]); !slices.Equal(got, []string{real}) {
		t.Errorf("tech scan templates = %v", got)
	}
	v := fr.calls[1]
	if got := templatesOf(v); len(got) != 1 || got[0] != filepath.Join(real, "http/cves/2099/CVE-2099-0001.yaml") {
		t.Errorf("re-verification templates = %v", got)
	}
	if slices.Contains(v, "-tags") {
		t.Errorf("the re-verification must not be tag restricted: %v", v)
	}
	if argAfter(v, "-u") != "https://app.example.com/" || argAfter(v, "-pt") != "http,ssl,dns,tcp" ||
		argAfter(v, "-etags") != "dos,intrusive" || argAfter(v, "-severity") != "medium,high,critical" ||
		argAfter(v, "-rate-limit") != "50" || !slices.Contains(v, "-no-interactsh") {
		t.Errorf("safety flags differ from the regular scan: %v", v)
	}
	for _, bad := range []string{"-code", "-headless", "-file", "-dast", "-l"} {
		if slices.Contains(v, bad) {
			t.Errorf("forbidden flag %s in %v", bad, v)
		}
	}
	if res.Partial {
		t.Error("every open finding's template ran: the scan must stay non-partial so absence resolves")
	}
}

// A match of the re-verification is reported like any other match (same key),
// and a template the tech scan also reports is not duplicated.
func TestReverifyMatchesMergeWithoutDuplicates(t *testing.T) {
	root := reverifyTree(t)
	out := []byte(`{"template-id":"CVE-2099-0001","type":"http","host":"https://app.example.com","matched-at":"https://app.example.com/x","info":{"name":"n","severity":"high"}}` + "\n")
	fr := &fakeRunner{output: out} // both invocations return the same match
	res, err := runReverify(t, root, config.NucleiConfig{}, openOf("CVE-2099-0001"), fr)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Key != "CVE-2099-0001" || res.Findings[0].Check != NameActive {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// A template the tech tags already select is run once: no second invocation.
func TestReverifyNoDuplicateWhenTechSelectionCoversTemplate(t *testing.T) {
	root := reverifyTree(t)
	fr := &fakeRunner{}
	res, err := runReverify(t, root, config.NucleiConfig{}, openOf("git-config", "git-config"), fr)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || res.Partial {
		t.Fatalf("calls = %d partial = %v, want a single non-partial invocation", len(fr.calls), res.Partial)
	}
}

// Two findings of one template (matchers) and two templates: each file once.
func TestReverifyEachTemplateFileOnce(t *testing.T) {
	root := reverifyTree(t)
	fr := &fakeRunner{}
	open := append(openOf("CVE-2099-0001", "CVE-2099-0002"), openOf("CVE-2099-0001")...)
	if _, err := runReverify(t, root, config.NucleiConfig{}, open, fr); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("calls = %d", len(fr.calls))
	}
	got := templatesOf(fr.calls[1])
	if len(got) != 2 || got[0] == got[1] {
		t.Errorf("templates = %v, want the two files exactly once", got)
	}
}

// scan_mode all already runs everything.
func TestReverifySkippedForScanModeAll(t *testing.T) {
	root := reverifyTree(t)
	fr := &fakeRunner{}
	res, err := runReverify(t, root, config.NucleiConfig{ScanMode: "all"}, openOf("CVE-2099-0001"), fr)
	if err != nil || len(fr.calls) != 1 || res.Partial {
		t.Fatalf("calls = %d partial = %v err = %v", len(fr.calls), res != nil && res.Partial, err)
	}
}

// A template removed upstream is not run, emits nothing so the finding accrues
// misses, and does not make the scan partial.
func TestReverifyMissingTemplateIsResolvable(t *testing.T) {
	root := reverifyTree(t)
	fr := &fakeRunner{}
	res, err := runReverify(t, root, config.NucleiConfig{}, openOf("CVE-2099-5555"), fr)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || res.Partial || len(res.Findings) != 0 {
		t.Fatalf("calls = %d partial = %v findings = %v", len(fr.calls), res.Partial, res.Findings)
	}
}

// Templates of other protocols (code/headless/...) are never run, even when a
// finding names one: treated as missing.
func TestReverifyNeverRunsNonNetworkTemplates(t *testing.T) {
	root := reverifyTree(t)
	fr := &fakeRunner{}
	if _, err := runReverify(t, root, config.NucleiConfig{}, openOf("CVE-2099-0003"), fr); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("a code template was handed to nuclei: %v", fr.calls)
	}
}

// More findings than the engine cap: the cap is respected and absence is not
// trusted (partial), so nothing resolves on the unverified remainder.
func TestReverifyCapRespected(t *testing.T) {
	var extra []fakenuclei.Template
	var ids []string
	for i := 0; i < check.MaxOpenFindings+10; i++ {
		id := fmt.Sprintf("CVE-2098-%04d", i)
		ids = append(ids, id)
		extra = append(extra, fakenuclei.Template{Path: fmt.Sprintf("http/cves/2098/%s.yaml", id), ID: id, Tags: []string{"rce"}})
	}
	root := reverifyTree(t, extra...)
	fr := &fakeRunner{}
	res, err := runReverify(t, root, config.NucleiConfig{}, openOf(ids...), fr)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(templatesOf(fr.calls[1])); n != check.MaxOpenFindings {
		t.Errorf("re-verified templates = %d, want the cap %d", n, check.MaxOpenFindings)
	}
	if !res.Partial {
		t.Error("with findings beyond the cap the scan must be partial")
	}
}

// Without a known template directory the templates cannot be located: the scan
// stays partial instead of letting findings resolve unverified.
func TestReverifyWithoutTemplateDirIsPartial(t *testing.T) {
	fr := &fakeRunner{}
	c := New(config.NucleiConfig{}, verifyOnly("app.example.com"), fr, false, nil)
	res, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com/"), OpenFindings: openOf("CVE-2099-0001")})
	if err != nil || !res.Partial {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

// A failed re-verification invocation is an error: nothing reaches the
// processor, so nothing can resolve.
func TestReverifyFailureIsAnError(t *testing.T) {
	root := reverifyTree(t)
	fr := &failSecond{}
	cfg := config.NucleiConfig{TemplatesDir: root}
	c := New(cfg, verifyOnly("app.example.com"), fr, false, nil)
	res, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com/"), OpenFindings: openOf("CVE-2099-0001")})
	if err == nil || res != nil {
		t.Fatalf("res = %+v err = %v, want an error", res, err)
	}
}

type failSecond struct{ n int }

func (f *failSecond) Run(context.Context, string, []string) ([]byte, error) {
	f.n++
	if f.n == 2 {
		return nil, errors.New("nuclei: timed out")
	}
	return nil, nil
}

// The re-verification honours scope: an unverifiable target never reaches nuclei.
func TestReverifyOutOfScopeNeverRuns(t *testing.T) {
	root := reverifyTree(t)
	fr := &fakeRunner{}
	c := New(config.NucleiConfig{TemplatesDir: root}, verifyOnly("other.example.com"), fr, false, nil)
	_, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com/"), OpenFindings: openOf("CVE-2099-0001")})
	if !errors.Is(err, ErrOutOfScope) || len(fr.calls) != 0 {
		t.Fatalf("err = %v calls = %d", err, len(fr.calls))
	}
}

func TestSecondRunTemplatesAreInsideTheSet(t *testing.T) {
	root := reverifyTree(t)
	fr := &fakeRunner{}
	if _, err := runReverify(t, root, config.NucleiConfig{}, openOf("CVE-2099-0001"), fr); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(root)
	for _, p := range templatesOf(fr.calls[1]) {
		if !strings.HasPrefix(p, real+string(filepath.Separator)) {
			t.Errorf("template %s lies outside the set", p)
		}
	}
}
