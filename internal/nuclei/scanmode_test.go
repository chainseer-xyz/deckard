package nuclei

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
)

func runArgs(t *testing.T, cfg config.NucleiConfig, opts ...Option) []string {
	t.Helper()
	fr := &fakeRunner{}
	c := New(cfg, verifyOnly("app.example.com"), fr, false, nil, opts...)
	if _, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com/", "nextjs")}); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("calls = %d", len(fr.calls))
	}
	return fr.calls[0]
}

func TestScanModeTechSelectsTags(t *testing.T) {
	for _, mode := range []string{"", "tech"} {
		a := runArgs(t, config.NucleiConfig{ScanMode: mode})
		if argAfter(a, "-tags") != "nextjs,react" {
			t.Errorf("mode %q: tags = %q", mode, argAfter(a, "-tags"))
		}
	}
}

func TestScanModeAllRunsEveryNonExcludedTemplate(t *testing.T) {
	a := runArgs(t, config.NucleiConfig{ScanMode: "all", TemplatesDir: "/tpl", ExtraTags: []string{"x"}, SeverityMin: "medium"})
	if slices.Contains(a, "-tags") {
		t.Errorf("scan_mode all must not restrict by tag: %v", a)
	}
	// Exclusions and severity still apply.
	if argAfter(a, "-etags") != "dos,intrusive" || argAfter(a, "-severity") != "medium,high,critical" || argAfter(a, "-t") != "/tpl" {
		t.Errorf("args = %v", a)
	}
}

// Nothing but the network protocols is ever requested: no code, headless,
// file, javascript or DAST templates, and no flag that enables them.
func TestRunsRestrictedToNetworkProtocols(t *testing.T) {
	for _, mode := range []string{"tech", "all"} {
		a := runArgs(t, config.NucleiConfig{ScanMode: mode})
		if got := argAfter(a, "-pt"); got != "http,ssl,dns,tcp" {
			t.Errorf("mode %s: -pt = %q", mode, got)
		}
		for _, bad := range []string{"-code", "-headless", "-file", "-dast", "-fuzz", "-esc", "-enable-self-contained", "-egm", "-lfa", "-allow-local-file-access", "-w", "-workflows", "-it", "-include-templates"} {
			if slices.Contains(a, bad) {
				t.Errorf("mode %s: forbidden flag %s in %v", mode, bad, a)
			}
		}
	}
}

func TestTemplatesDirSymlinkIsResolved(t *testing.T) {
	// nuclei does not descend into a symlinked -t root, and the updater's
	// "current" is a symlink: scans must be handed the real directory.
	root := t.TempDir()
	real := filepath.Join(root, "releases", "v1")
	if err := os.MkdirAll(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "current")
	if err := os.Symlink(filepath.Join("releases", "v1"), link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	a := runArgs(t, config.NucleiConfig{TemplatesDir: link})
	if got := argAfter(a, "-t"); got != resolved {
		t.Errorf("-t = %q, want %q", got, resolved)
	}
}

func TestTemplateDirOptionAndMissingTemplates(t *testing.T) {
	fr := &fakeRunner{}
	missing := func() (string, error) { return "", errors.New("no release installed yet") }
	c := New(config.NucleiConfig{}, verifyOnly("app.example.com"), fr, false, nil, WithTemplateDir(missing))
	_, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com/")})
	if !errors.Is(err, ErrNoTemplates) {
		t.Fatalf("err = %v, want ErrNoTemplates", err)
	}
	if len(fr.calls) != 0 {
		t.Error("the binary must not run (a clean empty scan would be a lie)")
	}

	dir := t.TempDir()
	a := runArgs(t, config.NucleiConfig{TemplatesDir: "/ignored"}, WithTemplateDir(func() (string, error) { return dir, nil }))
	want, _ := filepath.EvalSymlinks(dir)
	if argAfter(a, "-t") != want {
		t.Errorf("-t = %q, want the option's dir %q", argAfter(a, "-t"), want)
	}
}

func TestExecRunnerEnvHookOverridesAndCleansUp(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	cleaned := false
	r := ExecRunner{Env: func() ([]string, func(), error) {
		return []string{"HOME=/state/home", "NUCLEI_CONFIG_DIR=/state/cfg"}, func() { cleaned = true }, nil
	}}
	out, err := r.Run(context.Background(), sh, []string{"-c", `printf '%s|%s' "$HOME" "$NUCLEI_CONFIG_DIR"`})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "/state/home|/state/cfg" {
		t.Errorf("env = %q", out)
	}
	if !cleaned {
		t.Error("env cleanup not called")
	}
	bad := ExecRunner{Env: func() ([]string, func(), error) { return nil, func() {}, errors.New("disk full") }}
	if _, err := bad.Run(context.Background(), sh, []string{"-c", "true"}); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("env failure must fail the run, got %v", err)
	}
}
