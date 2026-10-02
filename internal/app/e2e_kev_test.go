package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chainseer-xyz/deckard/internal/app"
	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

const (
	kevCVE   = "CVE-2099-0001" // made up
	otherCVE = "CVE-2099-0002"
	kevTpl   = "http/cves/2099/CVE-2099-0001.yaml"
	otherTpl = "http/cves/2099/CVE-2099-0002.yaml"
)

// kevFeeds serves fake CISA KEV and FIRST EPSS feeds over TLS. The catalog
// starts without the made-up CVE; list() adds it.
type kevFeeds struct {
	srv     *httptest.Server
	mu      sync.Mutex
	listed  bool
	kevHits atomic.Int32
}

func newKEVFeeds(t *testing.T) *kevFeeds {
	t.Helper()
	f := &kevFeeds{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			f.kevHits.Add(1)
			f.mu.Lock()
			listed := f.listed
			f.mu.Unlock()
			type vuln struct {
				CVEID          string `json:"cveID"`
				DateAdded      string `json:"dateAdded"`
				RequiredAction string `json:"requiredAction"`
				Ransomware     string `json:"knownRansomwareCampaignUse"`
			}
			vs := []vuln{
				{CVEID: "CVE-2099-9001", DateAdded: "2099-01-01", RequiredAction: "Apply updates.", Ransomware: "Unknown"},
				{CVEID: "CVE-2099-9002", DateAdded: "2099-01-02", RequiredAction: "Apply updates.", Ransomware: "Unknown"},
			}
			if listed {
				vs = append(vs, vuln{CVEID: kevCVE, DateAdded: "2099-03-01", RequiredAction: "Apply updates or discontinue use.", Ransomware: "Unknown"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"title": "fake", "catalogVersion": "2099.03.01", "count": len(vs), "vulnerabilities": vs})
		case "/epss":
			var data []map[string]string
			for _, c := range strings.Split(r.URL.Query().Get("cve"), ",") {
				if c == kevCVE {
					data = append(data, map[string]string{"cve": c, "epss": "0.95000", "percentile": "0.99000"})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "OK", "status-code": 200, "data": data})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *kevFeeds) list() { f.mu.Lock(); f.listed = true; f.mu.Unlock() }

func (f *kevFeeds) options() func(*vulnintel.Options) {
	return func(o *vulnintel.Options) {
		o.KEVURL = f.srv.URL + "/kev.json"
		o.EPSSURL = f.srv.URL + "/epss"
		c := f.srv.Client()
		c.Timeout = 10 * time.Second
		o.HTTPClient = c
		o.EPSSOptions = []vulnintel.ClientOption{vulnintel.WithMinGap(time.Millisecond)}
	}
}

func riverJobs(t *testing.T, ctx context.Context, url, kind string) int {
	t.Helper()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE kind = $1", kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The React2Shell story, KEV-driven. The template set already ships a template
// for a (made-up) CVE, but its tags match nothing the asset advertises, so the
// regular scan never runs it. When CISA adds the CVE to KEV, the next
// refresh_vulnintel run triggers a scan of ONLY that template against the
// owned URL; the finding opens critical with the kev tag and reaches
// Alertmanager with kev="true". Full scans and unrelated partial runs cannot
// resolve it prematurely; once fixed, full scans do.
func TestE2EKEVAdditionTriggersTargetedScanAndAlerts(t *testing.T) {
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
	feeds := newKEVFeeds(t)

	bin := fakenuclei.Install(t, fakenuclei.Conf{Probes: []fakenuclei.Probe{
		{TemplateID: kevCVE, Path: "/_rsc", Contains: "rce-confirmed"},
		{TemplateID: otherCVE, Path: "/_other", Contains: "never"},
	}})
	tree := release(t,
		fakenuclei.Template{Path: kevTpl, ID: kevCVE, CVE: kevCVE, Severity: "high", Tags: []string{"react", "nextjs", "rce"}},
		fakenuclei.Template{Path: otherTpl, ID: otherCVE, CVE: otherCVE, Severity: "high", Tags: []string{"react", "rce"}})
	bin.Set(func(c *fakenuclei.Conf) { c.Version, c.Tree = "v1.0.0", tree })
	tplDir := filepath.Join(t.TempDir(), "nuclei-templates")
	vulnDir := filepath.Join(t.TempDir(), "vulnintel")
	dbURL := pgtest.NewURL(t)

	newCfg := func(activeInterval time.Duration) *config.Config {
		cfg, err := config.Load("", nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Refdata.Enabled = false // hermetic
		cfg.Database.URL = dbURL
		cfg.Scope.Include = []string{"127.0.0.1"}
		cfg.Sources = []config.SourceConfig{{Name: "lab", Type: "static", URLs: []string{srv.URL, "http://not-ours.example.net:8080"}}} // the second is not owned
		cfg.Checks = map[string]map[string]any{"net.ports": {"ports": strconv.Itoa(labPort)}}
		cfg.Nuclei.Enabled = true
		cfg.Nuclei.Binary = bin.Path
		cfg.Nuclei.Update.Dir = tplDir
		cfg.Nuclei.TemplatesDir = cfg.Nuclei.UpdateCurrentDir()
		cfg.Vulnintel.Enabled = true
		cfg.Vulnintel.Dir = vulnDir
		cfg.Vulnintel.Interval = time.Hour
		cfg.Notify.Alertmanager.URLs = []string{am.srv.URL}
		cfg.Expansion.CTLogs = false
		cfg.Server.Roles = []string{"scheduler", "worker"}
		cfg.Server.MetricsAddr = "127.0.0.1:0"
		cfg.Server.HTTPAddr = "127.0.0.1:0"
		cfg.Findings.ResolveAfter = 3
		cfg.Auth.Mode = "none"
		cfg.Profiles.Active.Interval = activeInterval
		return cfg
	}
	opts := app.Options{Version: "test", VulnintelOptions: feeds.options()}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	a := newApp(t, ctx, newCfg(6*time.Hour), opts)
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st := openDB(t, ctx, dbURL)

	// ---- (a)+(b first load): templates installed, regular scan, KEV loaded for
	// the first time without the CVE. Nothing fires.
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce 1: %v", err)
	}
	if feeds.kevHits.Load() == 0 {
		t.Fatal("the KEV feed was never fetched")
	}
	if fs := nucleiFindings(t, ctx, st, model.StatusOpen); len(fs) != 0 {
		t.Fatalf("regular scan must not find the CVE (tags match nothing), got %+v", fs)
	}
	regular := regularScans(bin)
	if len(regular) == 0 {
		t.Fatal("the regular tech-tag scan never ran")
	}
	for _, c := range regular {
		if slices.Contains(fakenuclei.Arg(c.Args, "-tags"), "react") || strings.Contains(strings.Join(c.Args, " "), kevTpl) {
			t.Errorf("the regular scan must not select the CVE template: %v", c.Args)
		}
	}
	if n := len(deltaCalls(bin)); n != 0 {
		t.Fatalf("first KEV load / first install ran %d targeted scans, want 0 (no storm)", n)
	}
	if n := riverJobs(t, ctx, dbURL, "scan_cves"); n != 0 {
		t.Fatalf("scan_cves jobs after the first load = %d, want 0", n)
	}

	// ---- (b) CISA adds the CVE. The next refresh_vulnintel (periodic RunOnStart
	// when the engine starts) sees it as NEW, (c) enqueues scan_cves, a worker
	// runs it.
	feeds.list()
	if err := a.Engine().Start(ctx); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		sctx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		if err := a.Engine().Stop(sctx); err != nil {
			t.Errorf("engine stop: %v", err)
		}
	}
	defer stop()
	waitFor(t, 90*time.Second, "the KEV-triggered finding", func() bool {
		return len(nucleiFindings(t, ctx, st, model.StatusOpen)) == 1
	})
	stop()

	// (c) argv.
	deltas := deltaCalls(bin)
	if len(deltas) != 1 {
		t.Fatalf("targeted scans = %d, want exactly 1: %+v", len(deltas), deltas)
	}
	d := deltas[0]
	if len(d.Templates) != 1 || !strings.HasSuffix(d.Templates[0], "/"+kevTpl) {
		t.Errorf("templates run = %v, want only %s", d.Templates, kevTpl)
	}
	if slices.Contains(d.Args, "-tags") {
		t.Errorf("a CVE scan must not be tag-restricted: %v", d.Args)
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
		t.Errorf("targets = %v, want only the owned %s", d.Targets, srv.URL)
	}
	for _, c := range bin.Calls() {
		for _, tg := range c.Targets {
			if strings.Contains(tg, "not-ours") {
				t.Fatalf("out-of-scope target reached nuclei: %v", c)
			}
		}
	}

	// (d) the finding.
	open := nucleiFindings(t, ctx, st, model.StatusOpen)
	f := open[0]
	if f.Severity != model.SeverityCritical || f.AssetKey != srv.URL || f.Evidence["template_id"] != kevCVE {
		t.Fatalf("finding = sev %s asset %s evidence %v", f.Severity, f.AssetKey, f.Evidence)
	}
	if !slices.Contains(f.Tags, "kev") {
		t.Errorf("tags = %v, want kev", f.Tags)
	}
	if f.Evidence["kev"] != true || f.Evidence["kev_date_added"] != "2099-03-01" {
		t.Errorf("kev evidence missing: %v", f.Evidence)
	}
	if want := model.Fingerprint("cve.nuclei", srv.URL, kevCVE); f.Fingerprint != want {
		t.Errorf("fingerprint = %s, want the regular scan's %s", f.Fingerprint, want)
	}
	if f.Evidence["epss"] != 0.95 || f.Evidence["epss_percentile"] != 0.99 {
		t.Errorf("epss evidence missing: %v", f.Evidence)
	}

	// (e) Alertmanager.
	if err := a.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if firing, _ := am.alertsFor("cve.nuclei", srv.URL); firing != 1 {
		t.Fatalf("firing cve.nuclei alerts = %d, want 1 (checks: %v)", firing, am.labels("deckard_check"))
	}
	if !contains(am.labels("kev"), "true") || !contains(am.labels("severity"), "critical") {
		t.Errorf("alert labels: kev=%v severity=%v", am.labels("kev"), am.labels("severity"))
	}

	// ---- (f) PartialRun semantics. A new process: full scans are due every pass.
	a2 := newApp(t, ctx, newCfg(time.Millisecond), opts)
	if err := a2.Engine().Start(ctx); err != nil {
		t.Fatal(err)
	}
	stopA2 := func() {
		sctx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_ = a2.Engine().Stop(sctx)
	}
	defer stopA2()
	// A targeted run for an UNRELATED CVE (the endpoint is still vulnerable, but
	// that template does not match): a partial run, it cannot count a miss.
	if n, err := a2.Engine().EnqueueCVEScan(ctx, []string{otherCVE}); err != nil || n != 1 {
		t.Fatalf("EnqueueCVEScan(unrelated) = %d, %v", n, err)
	}
	waitFor(t, 60*time.Second, "the unrelated CVE scan", func() bool { return len(deltaCalls(bin)) >= 2 })
	time.Sleep(500 * time.Millisecond) // let the run's reconcile commit
	if got := nucleiFindings(t, ctx, st, model.StatusOpen); len(got) != 1 || got[0].MissedRuns != 0 {
		t.Fatalf("an unrelated partial run touched the finding: %+v", got)
	}
	stopA2()

	// Regular full scans while the endpoint is STILL vulnerable. The tech tags
	// select nothing that matches the CVE, but every open finding is re-verified
	// by its own template, so each full scan re-runs it, re-matches, and the
	// finding stays open with no misses far beyond resolve_after (3).
	verifies := func() int { return len(reverifyCalls(bin, kevTpl)) }
	full := func(n int) {
		t.Helper()
		before := verifies()
		time.Sleep(20 * time.Millisecond)
		if err := a2.Engine().RunOnce(ctx); err != nil {
			t.Fatalf("full RunOnce %d: %v", n, err)
		}
		if got := verifies(); got != before+1 {
			t.Fatalf("full scan %d: the open finding's template ran %d times, want once more", n, got-before)
		}
	}
	for i := 1; i <= 5; i++ { // resolve_after + 2
		full(i)
		if got := nucleiFindings(t, ctx, st, model.StatusOpen); len(got) != 1 || got[0].MissedRuns != 0 {
			t.Fatalf("full scan %d of a still-vulnerable host must keep the finding open with 0 misses: %+v", i, got)
		}
	}
	for _, c := range reverifyCalls(bin, kevTpl) {
		if slices.Contains(c.Args, "-tags") || len(c.Templates) != 1 {
			t.Errorf("the re-verification must run exactly its template, untagged: %v", c.Args)
		}
		if pt := fakenuclei.Arg(c.Args, "-pt"); len(pt) != 1 || pt[0] != "http,ssl,dns,tcp" {
			t.Errorf("protocol restriction missing on the re-verification: %v", c.Args)
		}
		if len(c.Targets) != 1 || strings.TrimSuffix(c.Targets[0], "/") != srv.URL {
			t.Errorf("re-verification targets = %v, want only the owned %s", c.Targets, srv.URL)
		}
	}
	if err := a2.Dispatcher().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, resolved := am.alertsFor("cve.nuclei", srv.URL); resolved != 0 {
		t.Fatal("a resolved notice was sent while the host is still vulnerable")
	}

	// The endpoint is fixed: the re-verification still runs, no longer matches,
	// and the finding accrues misses and resolves after resolve_after clean runs.
	vulnerable.Store(false)
	full(6)
	full(7)
	if got := nucleiFindings(t, ctx, st, model.StatusOpen); len(got) != 1 || got[0].MissedRuns != 2 {
		t.Fatalf("two misses of three must not resolve: %+v", got)
	}
	full(8)
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
		t.Error("no resolved notice after the full scans resolved it")
	}
}

// cveCheck is a passive check that reports a finding keyed by a CVE id on every
// IP asset: it stands in for any check whose findings reference a CVE.
type cveCheck struct{}

func (cveCheck) Name() string               { return "test.cve" }
func (cveCheck) Tier() model.Tier           { return model.TierPassive }
func (cveCheck) Applies(a model.Asset) bool { return a.Kind == model.KindIP }
func (cveCheck) Run(context.Context, check.Target) (*check.Result, error) {
	return &check.Result{Findings: []model.FindingInput{{
		Check: "test.cve", Key: kevCVE, Severity: model.SeverityMedium, Title: "made-up CVE",
		Evidence: map[string]any{"cve": kevCVE},
	}}}, nil
}

// (g) nuclei disabled: a KEV addition is logged and dropped without error,
// retries or queued jobs, and finding enrichment still applies.
func TestE2EKEVAdditionWithNucleiDisabledIsDroppedButEnriches(t *testing.T) {
	feeds := newKEVFeeds(t)
	ln := newListener(t)
	cfg := testConfig(t, "", ln.Port)
	cfg.Vulnintel.Enabled = true
	cfg.Vulnintel.Dir = filepath.Join(t.TempDir(), "vulnintel")
	cfg.Nuclei.Enabled = false
	cfg.Profiles.Passive.Interval = time.Millisecond
	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a, err := app.New(ctx, cfg, log, app.Options{Version: "test", VulnintelOptions: feeds.options(), ExtraChecks: []check.Check{cveCheck{}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st := openDB(t, ctx, cfg.Database.URL)

	if err := a.Engine().RunOnce(ctx); err != nil { // first load: CVE not listed
		t.Fatal(err)
	}
	feeds.list()
	time.Sleep(20 * time.Millisecond)
	if err := a.Engine().RunOnce(ctx); err != nil { // refresh sees the addition
		t.Fatalf("a KEV addition without nuclei must not fail the run: %v", err)
	}
	const dropped = "template scanning is disabled"
	if !strings.Contains(logs.String(), dropped) {
		t.Errorf("the dropped trigger was not logged:\n%s", logs.String())
	}
	for _, kind := range []string{"scan_cves", "scan_new_templates"} {
		if n := riverJobs(t, ctx, cfg.Database.URL, kind); n != 0 {
			t.Errorf("%s jobs queued = %d, want 0", kind, n)
		}
	}
	// A third run: the dropped CVE is not retried.
	before := strings.Count(logs.String(), dropped)
	time.Sleep(20 * time.Millisecond)
	if err := a.Engine().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if after := strings.Count(logs.String(), dropped); after != before {
		t.Errorf("the dropped CVE was retried (%d -> %d log lines)", before, after)
	}

	fs, _, err := st.ListFindings(ctx, store.FindingFilter{Check: "test.cve", Statuses: []model.FindingStatus{model.StatusOpen}})
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, %v", fs, err)
	}
	if fs[0].Severity != model.SeverityCritical || !slices.Contains(fs[0].Tags, "kev") || fs[0].Evidence["kev"] != true {
		t.Fatalf("finding not enriched: sev=%s tags=%v evidence=%v", fs[0].Severity, fs[0].Tags, fs[0].Evidence)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
