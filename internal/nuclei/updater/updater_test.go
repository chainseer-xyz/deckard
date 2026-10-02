package updater_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { c.t = c.t.Add(time.Minute); return c.t }

// release writes a fixture release tree (30 filler templates plus extras) and
// returns its path.
func release(t *testing.T, extra ...fakenuclei.Template) string {
	t.Helper()
	root := t.TempDir()
	fakenuclei.WriteTree(t, root, append(fakenuclei.BulkTemplates(30), extra...)...)
	return root
}

type env struct {
	t   *testing.T
	bin *fakenuclei.Binary
	u   *updater.Updater
	dir string
}

func newEnv(t *testing.T, mut func(*updater.Config)) *env {
	t.Helper()
	bin := fakenuclei.Install(t, fakenuclei.Conf{})
	dir := filepath.Join(t.TempDir(), "nuclei-templates")
	cfg := updater.Config{Dir: dir, Binary: bin.Path, MinTemplates: 20, MinHTTPTemplates: 10, Now: (&clock{t0}).now}
	if mut != nil {
		mut(&cfg)
	}
	u, err := updater.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, bin: bin, u: u, dir: dir}
}

func (e *env) publish(version string, tree string, additions ...string) {
	e.bin.Set(func(c *fakenuclei.Conf) {
		c.Version, c.Tree, c.NewAdditions, c.UpdateFail, c.Escape = version, tree, additions, "", false
	})
}

func (e *env) current() string {
	e.t.Helper()
	d, err := e.u.CurrentDir()
	if err != nil {
		e.t.Fatalf("CurrentDir: %v", err)
	}
	return d
}

func (e *env) releases() []string {
	ents, _ := os.ReadDir(filepath.Join(e.dir, "releases"))
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	return out
}

func (e *env) noStaging() {
	e.t.Helper()
	ents, _ := os.ReadDir(e.dir)
	for _, x := range ents {
		if strings.HasPrefix(x.Name(), "staging-") {
			e.t.Errorf("staging dir %s left behind", x.Name())
		}
	}
}

func TestFirstInstall(t *testing.T) {
	e := newEnv(t, nil)
	e.publish("v10.0.0", release(t), "http/misconfiguration/filler-1.yaml")
	res, err := e.u.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Version != "v10.0.0" || res.TemplateCount != 30 {
		t.Fatalf("result = %+v", res)
	}
	// Nothing to compare with: the first install must not report 30 templates
	// as "new" (the regular full scan covers them).
	if len(res.NewTemplates) != 0 || len(res.NewIDs) != 0 {
		t.Errorf("first install NewTemplates = %v", res.NewTemplates)
	}
	if got := e.current(); got != resolve(t, res.Dir) || !strings.Contains(got, "v10.0.0") {
		t.Errorf("current = %s, result dir = %s", got, res.Dir)
	}
	if _, err := os.Stat(filepath.Join(e.current(), "http", "misconfiguration", "filler-3.yaml")); err != nil {
		t.Errorf("templates not installed at current: %v", err)
	}
	st, err := e.u.Status()
	if err != nil || st.Version != "v10.0.0" || st.TemplateCount != 30 || st.UpdatedAt.IsZero() || st.CheckedAt.IsZero() || st.LastError != "" {
		t.Errorf("status = %+v err %v", st, err)
	}
	e.noStaging()

	// How nuclei was invoked: real flags, no -duc (which makes -ut a silent
	// no-op), and a writable HOME/XDG/config dir that is not the process's.
	calls := e.bin.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %d", len(calls))
	}
	c := calls[0]
	if !fakenuclei.Has(c.Args, "-update-templates") || fakenuclei.Has(c.Args, "-duc") || fakenuclei.Has(c.Args, "-disable-update-check") {
		t.Errorf("args = %v", c.Args)
	}
	ud := fakenuclei.Arg(c.Args, "-update-template-dir")
	if len(ud) != 1 || !strings.HasPrefix(ud[0], e.dir+string(filepath.Separator)+"staging-") {
		t.Errorf("update dir = %v, want a staging dir under %s", ud, e.dir)
	}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "NUCLEI_CONFIG_DIR", "TMPDIR"} {
		if v := c.Env[k]; !strings.HasPrefix(v, e.dir+string(filepath.Separator)+"staging-") {
			t.Errorf("%s = %q, want a path under the staging dir", k, v)
		}
	}
	for _, a := range c.Args {
		if a == "-t" || a == "-u" || a == "-tags" {
			t.Errorf("update must never scan or load templates to run: %v", c.Args)
		}
	}
}

func resolve(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNewTemplatesFromDiffAndAdditions(t *testing.T) {
	e := newEnv(t, nil)
	e.publish("v10.0.0", release(t, fakenuclei.Template{Path: "http/cves/2024/CVE-2024-0001.yaml", ID: "CVE-2024-0001", CVE: "CVE-2024-0001"}))
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	// v10.0.1 adds a react CVE template and a template that moved (same id,
	// different path: not new), and drops nothing. v10.0.2 adds code/ and
	// javascript/ templates (never scanned) and one more http template. The
	// release's .new-additions only lists the latest release's additions.
	r2 := release(t,
		fakenuclei.Template{Path: "http/cves/2024/CVE-2024-0001.yaml", ID: "CVE-2024-0001", CVE: "CVE-2024-0001"},
		fakenuclei.Template{Path: "http/cves/2025/CVE-2025-55182.yaml", ID: "CVE-2025-55182", CVE: "CVE-2025-55182", Severity: "critical"})
	e.publish("v10.0.1", r2, "http/cves/2025/CVE-2025-55182.yaml")
	res, err := e.u.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.NewTemplates, []string{"http/cves/2025/CVE-2025-55182.yaml"}) || !slices.Equal(res.NewIDs, []string{"CVE-2025-55182"}) {
		t.Fatalf("v10.0.1 new = %v %v", res.NewTemplates, res.NewIDs)
	}

	r3 := release(t,
		fakenuclei.Template{Path: "http/cves/2024/CVE-2024-0001.yaml", ID: "CVE-2024-0001", CVE: "CVE-2024-0001"},
		fakenuclei.Template{Path: "http/cves/2025/CVE-2025-55182.yaml", ID: "CVE-2025-55182", CVE: "CVE-2025-55182"},
		fakenuclei.Template{Path: "http/exposed-panels/new-panel.yaml", ID: "new-panel"},
		fakenuclei.Template{Path: "network/cves/2025/CVE-2025-1111.yaml", ID: "CVE-2025-1111"},
		fakenuclei.Template{Path: "code/cves/2025/CVE-2025-2222.yaml", ID: "CVE-2025-2222"},
		fakenuclei.Template{Path: "javascript/enum/x.yaml", ID: "js-x"})
	// Additions that are not in the tree, are absolute, or escape are ignored.
	e.publish("v10.0.2", r3, "http/exposed-panels/new-panel.yaml", "/etc/passwd", "../../x.yaml", "http/missing.yaml", "# c", "")
	res, err = e.u.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http/exposed-panels/new-panel.yaml", "network/cves/2025/CVE-2025-1111.yaml"}
	if !slices.Equal(res.NewTemplates, want) {
		t.Fatalf("v10.0.2 new = %v, want %v (only scannable protocols)", res.NewTemplates, want)
	}
}

func TestSwapKeepsPreviousAndPrunesOlder(t *testing.T) {
	e := newEnv(t, func(c *updater.Config) { c.PruneGrace = time.Nanosecond })
	var firstDir string
	for i, v := range []string{"v1", "v2", "v3"} {
		e.publish(v, release(t))
		res, err := e.u.Update(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstDir = res.Dir
		}
		if i == 1 {
			prev, err := filepath.EvalSymlinks(filepath.Join(e.dir, "previous"))
			if err != nil || prev != resolve(t, firstDir) {
				t.Fatalf("previous = %s err %v, want %s", prev, err, firstDir)
			}
		}
	}
	if got := len(e.releases()); got != 2 {
		t.Errorf("releases kept = %v, want current + previous", e.releases())
	}
	if _, err := os.Stat(firstDir); !os.IsNotExist(err) {
		t.Errorf("oldest release should have been pruned: %v", err)
	}
	if !strings.Contains(e.current(), "v3") {
		t.Errorf("current = %s", e.current())
	}
	prev, _ := filepath.EvalSymlinks(filepath.Join(e.dir, "previous"))
	if !strings.Contains(prev, "v2") {
		t.Errorf("previous = %s, want v2", prev)
	}
}

func TestUnchangedReleaseKeepsCurrent(t *testing.T) {
	e := newEnv(t, nil)
	e.publish("v5", release(t))
	first, err := e.u.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st1, _ := e.u.Status()
	e.publish("v5", release(t, fakenuclei.Template{Path: "http/x/y.yaml", ID: "y"}), "http/x/y.yaml")
	res, err := e.u.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || len(res.NewTemplates) != 0 || res.Version != "v5" || res.TemplateCount != 30 || res.Dir != first.Dir {
		t.Fatalf("unchanged result = %+v", res)
	}
	st2, _ := e.u.Status()
	if !st2.CheckedAt.After(st1.CheckedAt) || !st2.UpdatedAt.Equal(st1.UpdatedAt) {
		t.Errorf("CheckedAt must advance, UpdatedAt must not: %+v -> %+v", st1, st2)
	}
	if len(e.releases()) != 1 {
		t.Errorf("releases = %v", e.releases())
	}
	e.noStaging()
}

func TestFailureKeepsLastGoodAndSurfacesError(t *testing.T) {
	e := newEnv(t, nil)
	e.publish("v1", release(t))
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := e.current()

	e.bin.Set(func(c *fakenuclei.Conf) { c.UpdateFail = "rate limit exceeded" })
	_, err := e.u.Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("err = %v, want it to carry nuclei's message", err)
	}
	if e.current() != before {
		t.Errorf("current changed on failure: %s -> %s", before, e.current())
	}
	st, _ := e.u.Status()
	if st.Version != "v1" || !strings.Contains(st.LastError, "rate limit") || st.LastErrorAt.IsZero() {
		t.Errorf("status = %+v", st)
	}
	e.noStaging()

	// Recovery clears the error.
	e.publish("v2", release(t))
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ = e.u.Status(); st.LastError != "" || st.Version != "v2" {
		t.Errorf("status after recovery = %+v", st)
	}
}

func TestFirstFailureLeavesNoCurrent(t *testing.T) {
	e := newEnv(t, nil)
	e.bin.Set(func(c *fakenuclei.Conf) { c.UpdateFail = "no network" })
	if _, err := e.u.Update(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if _, err := e.u.CurrentDir(); err == nil {
		t.Error("no release must be current after a failed first install")
	}
	if st, _ := e.u.Status(); !strings.Contains(st.LastError, "no network") {
		t.Errorf("status = %+v", st)
	}
}

func TestRejectsSymlinkEscape(t *testing.T) {
	e := newEnv(t, nil)
	e.publish("v1", release(t))
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := e.current()
	e.publish("v2", release(t))
	e.bin.Set(func(c *fakenuclei.Conf) { c.Escape = true })
	_, err := e.u.Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("err = %v, want symlink escape rejection", err)
	}
	if e.current() != before {
		t.Error("an escaping release must never become current")
	}
	e.noStaging()
	if len(e.releases()) != 1 {
		t.Errorf("releases = %v", e.releases())
	}
}

func TestRejectsDanglingAndInternalSymlinkOK(t *testing.T) {
	tree := release(t)
	// A link that stays inside the tree is fine.
	if err := os.Symlink("misconfiguration", filepath.Join(tree, "http", "alias")); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, nil)
	e.publish("v1", tree)
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatalf("internal symlink rejected: %v", err)
	}
	tree2 := release(t)
	if err := os.Symlink("nowhere", filepath.Join(tree2, "http", "dangling")); err != nil {
		t.Fatal(err)
	}
	e.publish("v2", tree2)
	if _, err := e.u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "dangling") {
		t.Fatalf("err = %v, want dangling symlink rejection", err)
	}
}

func TestRejectsImplausibleReleases(t *testing.T) {
	t.Run("too few templates", func(t *testing.T) {
		e := newEnv(t, func(c *updater.Config) { c.MinTemplates = 50 })
		e.publish("v1", release(t)) // 30 < 50
		if _, err := e.u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "only 30 templates") {
			t.Fatalf("err = %v", err)
		}
		if _, err := e.u.CurrentDir(); err == nil {
			t.Error("rejected release became current")
		}
	})
	t.Run("no http templates", func(t *testing.T) {
		e := newEnv(t, func(c *updater.Config) { c.MinTemplates = 5; c.MinHTTPTemplates = 5 })
		root := t.TempDir()
		var ts []fakenuclei.Template
		for i := 0; i < 20; i++ {
			ts = append(ts, fakenuclei.Template{Path: "dns/d" + string(rune('a'+i)) + ".yaml", ID: "dns-" + string(rune('a'+i))})
		}
		fakenuclei.WriteTree(t, root, ts...)
		e.publish("v1", root)
		if _, err := e.u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "http templates") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("size cap", func(t *testing.T) {
		e := newEnv(t, func(c *updater.Config) { c.MaxBytes = 2000 })
		e.publish("v1", release(t))
		if _, err := e.u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("file cap", func(t *testing.T) {
		e := newEnv(t, func(c *updater.Config) { c.MaxFiles = 10 })
		e.publish("v1", release(t))
		if _, err := e.u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "more than 10 files") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("mostly unparseable", func(t *testing.T) {
		e := newEnv(t, nil)
		root := release(t)
		for i := 0; i < 20; i++ {
			if err := os.WriteFile(filepath.Join(root, "http", "misconfiguration", "bad-"+string(rune('a'+i))+".yaml"), []byte("id: [oops\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		e.publish("v1", root)
		if _, err := e.u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "unparseable") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestNoVersionReportedIsAnError(t *testing.T) {
	// nuclei -ut -duc exits 0 having done nothing; an empty staging tree and
	// no version must be an error, never a "successful" empty update.
	e := newEnv(t, func(c *updater.Config) {
		real := c.Exec
		_ = real
		c.Exec = func(ctx context.Context, binary string, args, env []string) ([]byte, error) {
			return []byte("[INF] nothing"), nil
		}
	})
	_, err := e.u.Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not report a templates version") {
		t.Fatalf("err = %v", err)
	}
}

func TestTimeoutAndCancellation(t *testing.T) {
	e := newEnv(t, func(c *updater.Config) {
		c.Timeout = 50 * time.Millisecond
		c.Exec = func(ctx context.Context, binary string, args, env []string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	})
	start := time.Now()
	_, err := e.u.Update(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("timeout not enforced")
	}
	e.noStaging()
}

// A release installed moments ago survives pruning even when it is neither
// current nor previous: a scan that just started on it must not be cut off.
func TestPruneGraceKeepsFreshReleases(t *testing.T) {
	e := newEnv(t, nil) // default grace 1h; the injected clock moves one minute per read
	for _, v := range []string{"v1", "v2", "v3", "v4"} {
		e.publish(v, release(t))
		if _, err := e.u.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(e.releases()); got != 4 {
		t.Errorf("releases = %v, want all 4 within the grace period", e.releases())
	}
}

// Readers following the current symlink while releases are swapped must never
// see a missing or half-written tree.
func TestSwapIsAtomicForReaders(t *testing.T) {
	e := newEnv(t, nil)
	e.publish("v0", release(t))
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var bad atomic.Int64
	var reads atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				ents, err := os.ReadDir(filepath.Join(e.dir, "current", "http", "misconfiguration"))
				reads.Add(1)
				// macOS (APFS) can fail path resolution with EINVAL while a
				// symlink is being replaced by rename(2); Linux, where deckard
				// runs, cannot. That kernel quirk is not a partial tree.
				if runtime.GOOS == "darwin" && errors.Is(err, syscall.EINVAL) {
					continue
				}
				if err != nil || len(ents) < 30 {
					if bad.Add(1) == 1 {
						t.Logf("first bad read: err=%v entries=%d", err, len(ents))
					}
				}
			}
		}()
	}
	for i := 1; i <= 8; i++ {
		e.publish("v"+string(rune('0'+i)), release(t))
		if _, err := e.u.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d of %d reads saw a missing or partial tree during swaps", bad.Load(), reads.Load())
	}
}

func TestStaleStagingIsCleaned(t *testing.T) {
	e := newEnv(t, nil)
	old := filepath.Join(e.dir, "staging-1")
	fresh := filepath.Join(e.dir, "staging-2")
	for _, d := range []string{old, fresh} {
		if err := os.MkdirAll(filepath.Join(d, "templates"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// Age one past the staleness horizon.
	past := t0.Add(-3 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	e.publish("v1", release(t))
	// The injected clock is far from the real mtime of "fresh", so make it
	// recent relative to the injected clock instead.
	if err := os.Chtimes(fresh, t0, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("stale staging dir should be removed: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("recent staging dir must be kept (another updater may own it): %v", err)
	}
}

func TestStaleScanStateIsCleaned(t *testing.T) {
	e := newEnv(t, nil)
	oldRun := filepath.Join(e.dir, "run", "scan-old")
	freshRun := filepath.Join(e.dir, "run", "scan-fresh")
	for _, d := range []string{oldRun, freshRun} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(oldRun, t0.Add(-24*time.Hour), t0.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(freshRun, t0, t0); err != nil {
		t.Fatal(err)
	}
	e.publish("v1", release(t))
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldRun); !os.IsNotExist(err) {
		t.Errorf("a day-old scan state dir (crashed process) should be removed: %v", err)
	}
	if _, err := os.Stat(freshRun); err != nil {
		t.Errorf("a recent scan state dir may belong to a running scan: %v", err)
	}
}

func TestScanEnv(t *testing.T) {
	e := newEnv(t, nil)
	e.publish("v1", release(t))
	if _, err := e.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	env, cleanup, err := e.u.ScanEnv()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	run := filepath.Join(e.dir, "run") + string(filepath.Separator)
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "NUCLEI_CONFIG_DIR", "TMPDIR"} {
		if !strings.HasPrefix(m[k], run) {
			t.Errorf("%s = %q, want under %s", k, m[k], run)
		}
		if _, err := os.Stat(m[k]); err != nil && k != "HOME" {
			t.Errorf("%s dir missing: %v", k, err)
		}
	}
	if m["NUCLEI_TEMPLATES_DIR"] != e.current() {
		t.Errorf("NUCLEI_TEMPLATES_DIR = %q, want the resolved current release %q", m["NUCLEI_TEMPLATES_DIR"], e.current())
	}
	home := m["HOME"]
	cleanup()
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Errorf("cleanup left %s", home)
	}
}

func TestUpdateIfOlderThan(t *testing.T) {
	e := newEnv(t, nil)
	e.publish("v1", release(t))
	ctx := context.Background()
	// Nothing installed: runs.
	if _, ran, err := e.u.UpdateIfOlderThan(ctx, time.Hour); err != nil || !ran {
		t.Fatalf("first: ran=%v err=%v", ran, err)
	}
	// The injected clock advances a minute per read: still fresh, so no download.
	before := len(e.bin.Calls())
	if _, ran, err := e.u.UpdateIfOlderThan(ctx, time.Hour); err != nil || ran {
		t.Fatalf("fresh: ran=%v err=%v", ran, err)
	}
	if len(e.bin.Calls()) != before {
		t.Error("a fresh release must not trigger a download")
	}
	// Stale (older than a nanosecond): runs and reports unchanged.
	res, ran, err := e.u.UpdateIfOlderThan(ctx, time.Nanosecond)
	if err != nil || !ran || res.Changed {
		t.Fatalf("stale: %+v ran=%v err=%v", res, ran, err)
	}
	// A failure is reported and recorded, and still counts as an attempt.
	e.bin.Set(func(c *fakenuclei.Conf) { c.UpdateFail = "boom" })
	if _, ran, err := e.u.UpdateIfOlderThan(ctx, time.Nanosecond); err == nil || !ran {
		t.Fatalf("failing: ran=%v err=%v", ran, err)
	}
	if st, _ := e.u.Status(); st.LastError == "" {
		t.Error("error not recorded")
	}
}

func TestNewValidatesConfig(t *testing.T) {
	for _, dir := range []string{"", "relative/dir"} {
		if _, err := updater.New(updater.Config{Dir: dir}); err == nil {
			t.Errorf("Dir %q accepted", dir)
		}
	}
}

func TestParseNewAdditions(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".new-additions")
	body := "http/cves/2025/CVE-2025-1.yaml\n\n# comment\n/etc/passwd\n../../escape.yaml\nhttp//double/slash.yaml\n  ssl/spaced.yaml  \n.\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := updater.ParseNewAdditions(p)
	want := []string{"http/cves/2025/CVE-2025-1.yaml", "http/double/slash.yaml", "ssl/spaced.yaml"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if updater.ParseNewAdditions(filepath.Join(t.TempDir(), "missing")) != nil {
		t.Error("missing file must yield nil")
	}
}
