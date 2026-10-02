package app_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/app"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/engine"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const (
	cveTemplate = "http/cves/2025/CVE-2025-55182.yaml"
	cveID       = "CVE-2025-55182"
)

// release writes a template release: enough filler to pass the updater's size
// checks, an unrelated template, and any extras.
func release(t *testing.T, extra ...fakenuclei.Template) string {
	t.Helper()
	root := t.TempDir()
	ts := append(fakenuclei.BulkTemplates(1100), fakenuclei.Template{Path: "http/misc/unrelated.yaml", ID: "unrelated", Severity: "info", Tags: []string{"misc"}})
	fakenuclei.WriteTree(t, root, append(ts, extra...)...)
	return root
}

// The React2Shell story end to end. A template release without the CVE template
// is installed and the regular scan is clean. The next release ships the CVE
// template (tags that match nothing the asset advertises): the update installs
// it, only that template is run against every owned web asset (and never
// against anything out of scope), a finding opens on the vulnerable endpoint
// and reaches Alertmanager. A later release with an unrelated template runs as
// a partial run and cannot resolve the finding; only full scans do, once the
// endpoint is fixed.
func TestE2ENewTemplateFindsVulnerableEndpointAndAlerts(t *testing.T) {
	var vulnerable atomic.Bool
	vulnerable.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_rsc" && vulnerable.Load() {
			_, _ = w.Write([]byte("uid=0(root) rce-confirmed"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	labPort := srv.Listener.Addr().(*net.TCPAddr).Port
	am := newMockAlertmanager(t)

	bin := fakenuclei.Install(t, fakenuclei.Conf{Probes: []fakenuclei.Probe{{TemplateID: cveID, Path: "/_rsc", Contains: "rce-confirmed"}}})
	tplDir := filepath.Join(t.TempDir(), "nuclei-templates")
	dbURL := pgtest.NewURL(t)

	newCfg := func(activeInterval time.Duration) *config.Config {
		cfg, err := config.Load("", nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Refdata.Enabled = false   // hermetic: never reach the public dataset sources
		cfg.Vulnintel.Enabled = false // hermetic: never reach cisa.gov / api.first.org
		cfg.Database.URL = dbURL
		cfg.Scope.Include = []string{"127.0.0.1"}
		cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "static", URLs: []string{srv.URL, "http://not-ours.example.net:8080"}}} // the second is not owned
		// Hermetic: probe only the lab port, never whatever else listens on this
		// machine's loopback (CUPS on 631, ...).
		cfg.Checks = map[string]map[string]any{"net.ports": {"ports": strconv.Itoa(labPort)}}
		cfg.Nuclei.Enabled = true
		cfg.Nuclei.Binary = bin.Path
		cfg.Nuclei.Update.Dir = tplDir
		cfg.Nuclei.TemplatesDir = cfg.Nuclei.UpdateCurrentDir()
		cfg.Notify.Alertmanager.URLs = []string{am.srv.URL}
		cfg.Expansion.CTLogs = false
		cfg.Server.Roles = []string{"scheduler", "worker"}
		cfg.Findings.ResolveAfter = 2
		cfg.Auth.Mode = "none"
		cfg.Profiles.Active.Interval = activeInterval
		return cfg
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	a := newApp(t, ctx, newCfg(6*time.Hour), appOptions())
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st := openDB(t, ctx, dbURL)

	// ---- release 1: no CVE template. The first install is not "new" templates.
	bin.Set(func(c *fakenuclei.Conf) { c.Version, c.Tree = "v1.0.0", release(t) })
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce 1: %v", err)
	}
	if fs := nucleiFindings(t, ctx, st, model.StatusOpen); len(fs) != 0 {
		t.Fatalf("release 1 must be clean, got %+v", fs)
	}
	if n := len(deltaCalls(bin)); n != 0 {
		t.Fatalf("first install ran %d delta scans, want 0", n)
	}
	regular := regularScans(bin)
	if len(regular) == 0 {
		t.Fatal("the regular tech-tag scan never ran")
	}
	for _, c := range regular {
		if !slices.Contains(c.Args, "-tags") || !slices.Contains(c.Args, "-u") {
			t.Errorf("regular scan argv = %v", c.Args)
		}
	}

	// ---- release 2: the CVE template ships. Tags match nothing the asset
	// advertises, so only the new-template scan can find it.
	bin.Set(func(c *fakenuclei.Conf) {
		c.Version = "v1.0.1"
		c.Tree = release(t, fakenuclei.Template{Path: cveTemplate, ID: cveID, CVE: cveID, Severity: "critical", Tags: []string{"react", "nextjs", "rce"}})
		c.NewAdditions = []string{cveTemplate}
	})
	before := len(bin.Calls())
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce 2: %v", err)
	}
	deltas := deltaCalls(bin)
	if len(deltas) != 1 {
		t.Fatalf("delta scans = %d (calls since update: %d), want exactly 1", len(deltas), len(bin.Calls())-before)
	}
	d := deltas[0]
	if slices.Contains(d.Args, "-tags") {
		t.Errorf("a new-template scan must not be tag-restricted: %v", d.Args)
	}
	if pt := fakenuclei.Arg(d.Args, "-pt"); len(pt) != 1 || pt[0] != "http,ssl,dns,tcp" {
		t.Errorf("protocol restriction missing: %v", d.Args)
	}
	for _, bad := range []string{"-code", "-headless", "-file", "-dast"} {
		if slices.Contains(d.Args, bad) {
			t.Errorf("forbidden flag %s: %v", bad, d.Args)
		}
	}
	if !slices.Equal(d.Targets, []string{srv.URL}) {
		t.Errorf("delta targets = %v, want only the owned %s (the non-owned URL must never reach the binary)", d.Targets, srv.URL)
	}
	for _, c := range bin.Calls() {
		for _, tg := range c.Targets {
			if strings.Contains(tg, "not-ours") {
				t.Fatalf("out-of-scope target reached nuclei: %v", c)
			}
		}
	}

	open := nucleiFindings(t, ctx, st, model.StatusOpen)
	if len(open) != 1 || open[0].Evidence["template_id"] != cveID || open[0].Severity != model.SeverityCritical || open[0].AssetKey != srv.URL {
		t.Fatalf("open findings after the update = %+v", open)
	}
	// Same fingerprint a full scan would produce: check cve.nuclei, key = template id.
	if want := model.Fingerprint("cve.nuclei", srv.URL, cveID); open[0].Fingerprint != want {
		t.Errorf("fingerprint = %s, want the regular scan's %s", open[0].Fingerprint, want)
	}
	if err := a.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if firing, _ := am.alertsFor("cve.nuclei", srv.URL); firing != 1 {
		t.Fatalf("Alertmanager firing alerts for cve.nuclei = %d, want 1 (checks seen: %v)", firing, am.labels("deckard_check"))
	}

	// ---- release 3: an unrelated new template. The delta run reports nothing
	// about CVE-2025-55182; it must not count a miss, let alone resolve it. The
	// endpoint is even fixed meanwhile: only a FULL scan may notice.
	vulnerable.Store(false)
	bin.Set(func(c *fakenuclei.Conf) {
		c.Version = "v1.0.2"
		c.Tree = release(t,
			fakenuclei.Template{Path: cveTemplate, ID: cveID, CVE: cveID, Severity: "critical", Tags: []string{"react", "nextjs", "rce"}},
			fakenuclei.Template{Path: "http/misc/another-new.yaml", ID: "another-new", Severity: "low", Tags: []string{"misc"}})
		c.NewAdditions = []string{"http/misc/another-new.yaml"}
	})
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce 3: %v", err)
	}
	if len(deltaCalls(bin)) != 2 {
		t.Fatalf("delta scans = %d, want a second one for the unrelated template", len(deltaCalls(bin)))
	}
	f := nucleiFindings(t, ctx, st, model.StatusOpen)
	if len(f) != 1 || f[0].MissedRuns != 0 {
		t.Fatalf("an unrelated delta run touched the finding: %+v", f)
	}
	if err := a.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, resolved := am.alertsFor("cve.nuclei", srv.URL); resolved != 0 {
		t.Fatal("a resolved notice was sent by a partial run")
	}

	// ---- full scans resolve it normally (restart with a due interval).
	a2 := newApp(t, ctx, newCfg(time.Millisecond), appOptions())
	for i := 0; i < 2; i++ { // resolve_after = 2
		time.Sleep(20 * time.Millisecond)
		if err := a2.Engine().RunOnce(ctx); err != nil {
			t.Fatalf("full RunOnce %d: %v", i, err)
		}
	}
	if left := nucleiFindings(t, ctx, st, model.StatusOpen); len(left) != 0 {
		t.Fatalf("full scans must resolve the fixed finding, still open: %+v", left)
	}
	if got := nucleiFindings(t, ctx, st, model.StatusResolved); len(got) != 1 {
		t.Fatalf("resolved findings = %+v", got)
	}
	if err := a2.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, resolved := am.alertsFor("cve.nuclei", srv.URL); resolved < 1 {
		t.Errorf("no resolved notice after the full scans resolved it")
	}
}

// deckard scan --no-update: the one-shot run skips the updater entirely.
func TestE2ERunOnceNoUpdateSkipsTheUpdater(t *testing.T) {
	bin := fakenuclei.Install(t, fakenuclei.Conf{})
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false
	cfg.Vulnintel.Enabled = false
	cfg.Database.URL = pgtest.NewURL(t)
	cfg.Scope.Include = []string{"127.0.0.1"}
	cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "static", IPs: []string{"127.0.0.1"}}}
	cfg.Checks = map[string]map[string]any{"net.ports": {"ports": "1"}}
	cfg.Nuclei.Enabled = true
	cfg.Nuclei.Binary = bin.Path
	cfg.Nuclei.Update.Dir = filepath.Join(t.TempDir(), "nt")
	cfg.Nuclei.TemplatesDir = cfg.Nuclei.UpdateCurrentDir()
	cfg.Expansion.CTLogs = false
	cfg.Server.Roles = []string{"scheduler", "worker"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a := newApp(t, ctx, cfg, appOptions())
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Engine().RunOnceWith(ctx, engine.RunOnceOptions{SkipTemplateUpdate: true}); err != nil {
		t.Fatal(err)
	}
	for _, c := range bin.Calls() {
		if fakenuclei.Has(c.Args, "-update-templates") {
			t.Fatalf("updater ran despite --no-update: %v", c.Args)
		}
	}
	// And with the update enabled (no tree configured: the fake fails), the
	// failure is reported but does not abort the pass.
	err = a.Engine().RunOnce(ctx)
	if err == nil || !strings.Contains(err.Error(), "update nuclei templates") {
		t.Fatalf("RunOnce err = %v, want the update failure reported", err)
	}
}

func nucleiFindings(t *testing.T, ctx context.Context, st store.Store, statuses ...model.FindingStatus) []model.Finding {
	t.Helper()
	fs, _, err := st.ListFindings(ctx, store.FindingFilter{Check: "cve.nuclei", Statuses: statuses})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// deltaCalls are scans driven by a template list file (-t <file>, -l <file>).
func deltaCalls(b *fakenuclei.Binary) []fakenuclei.Call {
	var out []fakenuclei.Call
	for _, c := range b.ScanCalls() {
		if fakenuclei.Has(c.Args, "-l") {
			out = append(out, c)
		}
	}
	return out
}

// reverifyCalls are the per-asset scans that re-run exactly one open finding's
// template (-u <url> -t <that template file>, no -tags).
func reverifyCalls(b *fakenuclei.Binary, tpl string) []fakenuclei.Call {
	var out []fakenuclei.Call
	for _, c := range regularScans(b) {
		if len(c.Templates) == 1 && strings.HasSuffix(c.Templates[0], "/"+tpl) {
			out = append(out, c)
		}
	}
	return out
}

// regularScans are the per-asset tech-tag scans (-u <url> -tags ...).
func regularScans(b *fakenuclei.Binary) []fakenuclei.Call {
	var out []fakenuclei.Call
	for _, c := range b.ScanCalls() {
		if fakenuclei.Has(c.Args, "-u") {
			out = append(out, c)
		}
	}
	return out
}

var _ = app.Options{}
