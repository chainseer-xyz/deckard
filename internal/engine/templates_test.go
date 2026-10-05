package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river/rivertype"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
)

// ---- fakes ---------------------------------------------------------------------

type fakeTemplates struct {
	mu     sync.Mutex
	up     updater.Update
	err    error
	status updater.Status
	// calls records "update" and "ifolder:<age>".
	calls []string
	// skip makes UpdateIfOlderThan report "fresh" (no download).
	skip bool
}

func TestDeltaWorkerTimeoutTracksConfiguredNucleiRuntime(t *testing.T) {
	r := newRunner(Deps{Config: config.Config{Checks: map[string]map[string]any{
		nuclei.NameActive: {"run_timeout": "30m"},
	}}})
	want := nuclei.ProcessTimeout(r.Config.Checks[nuclei.NameActive], deltaAssetBatch) + deltaWorkerMargin
	if got := (&scanNewTemplatesWorker{r: r}).Timeout(nil); got != want {
		t.Errorf("new-template worker timeout = %s, want %s", got, want)
	}
	if got := (&scanCVEsWorker{r: r}).Timeout(nil); got != want {
		t.Errorf("CVE worker timeout = %s, want %s", got, want)
	}
}

func (f *fakeTemplates) Update(context.Context) (updater.Update, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "update")
	if f.err == nil && f.up.Version != "" {
		f.status.Version = f.up.Version
	}
	return f.up, f.err
}

func (f *fakeTemplates) UpdateIfOlderThan(_ context.Context, age time.Duration) (updater.Update, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ifolder:"+age.String())
	if f.skip {
		return updater.Update{}, false, nil
	}
	if f.err == nil && f.up.Version != "" {
		f.status.Version = f.up.Version
	}
	return f.up, true, f.err
}

func (f *fakeTemplates) Status() (updater.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, nil
}

func (f *fakeTemplates) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

type fakeDelta struct {
	mu       sync.Mutex
	reqs     []nuclei.ScanRequest
	res      nuclei.ScanResult
	scanErr  error
	cveTable map[string][]string // CVE -> relative template paths
	lookups  [][]string
	noTpls   bool // Resolve/Lookup fail with ErrNoTemplates
	missing  map[string]bool
}

func (f *fakeDelta) Scan(_ context.Context, req nuclei.ScanRequest) (nuclei.ScanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	res := f.res
	if res.Findings == nil {
		res.Findings = map[int64][]model.FindingInput{}
	}
	res.Scanned = len(req.Targets)
	return res, f.scanErr
}

func (f *fakeDelta) Resolve(rel []string) ([]string, error) {
	if f.noTpls {
		return nil, fmt.Errorf("%w: test", nuclei.ErrNoTemplates)
	}
	var out []string
	for _, r := range rel {
		if !f.missing[r] {
			out = append(out, "/tpl/"+r)
		}
	}
	return out, nil
}

func (f *fakeDelta) LookupCVEs(cves []string) ([]string, error) {
	f.mu.Lock()
	f.lookups = append(f.lookups, slices.Clone(cves))
	f.mu.Unlock()
	if f.noTpls {
		return nil, fmt.Errorf("%w: test", nuclei.ErrNoTemplates)
	}
	var out []string
	for _, c := range cves {
		out = append(out, f.cveTable[c]...)
	}
	return out, nil
}

func (f *fakeDelta) requests() []nuclei.ScanRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

// deltaQueue extends the recording queue with template-limited jobs.
type deltaRecQueue struct {
	*recQueue
	mu     sync.Mutex
	deltas []deltaJob
	seen   map[string]bool
}

func newDeltaRecQueue() *deltaRecQueue {
	return &deltaRecQueue{recQueue: newRecQueue(), seen: map[string]bool{}}
}

func (q *deltaRecQueue) enqueueDelta(_ context.Context, j deltaJob) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.seen[j.key()] {
		return false, nil
	}
	q.seen[j.key()] = true
	q.deltas = append(q.deltas, j)
	return true, nil
}

func (q *deltaRecQueue) jobs() []deltaJob {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Clone(q.deltas)
}

type tmplRec struct {
	*fakeRec
	mu       sync.Mutex
	updates  []string
	newTpls  int
	statuses []int
}

func (r *tmplRec) ObserveTemplateUpdate(res string) {
	r.mu.Lock()
	r.updates = append(r.updates, res)
	r.mu.Unlock()
}
func (r *tmplRec) AddNewTemplates(n int) { r.mu.Lock(); r.newTpls += n; r.mu.Unlock() }
func (r *tmplRec) SetTemplateStatus(n int, _ time.Time) {
	r.mu.Lock()
	r.statuses = append(r.statuses, n)
	r.mu.Unlock()
}

func urlAsset(id int64, key string) model.Asset {
	return model.Asset{ID: id, Kind: model.KindURL, Key: key, Scope: model.ScopeOwned, Source: "cf", Zone: "example.com"}
}

type tmplHarness struct {
	*harness
	tpl *fakeTemplates
	dl  *fakeDelta
	dq  *deltaRecQueue
	rec *tmplRec
}

func newTmplHarness(t *testing.T, mut func(*testCfg), assets []model.Asset) *tmplHarness {
	t.Helper()
	h := newHarness(func(c *testCfg) {
		c.Nuclei.Update.Enabled = true
		c.Nuclei.Update.Interval = 6 * time.Hour
		c.Nuclei.Update.RunNewTemplates = true
		if mut != nil {
			mut(c)
		}
	}, assets)
	th := &tmplHarness{harness: h, tpl: &fakeTemplates{}, dl: &fakeDelta{}, dq: newDeltaRecQueue(), rec: &tmplRec{fakeRec: h.rec}}
	h.r.Templates, h.r.Delta = th.tpl, th.dl
	h.r.rec = th.rec
	h.r.q = th.dq
	return th
}

func ids(js []deltaJob) [][]int64 {
	var out [][]int64
	for _, j := range js {
		out = append(out, j.AssetIDs)
	}
	return out
}

// ---- update -> new-template scans -----------------------------------------------

func TestUpdateQueuesNewTemplateScansForEligibleAssetsOnly(t *testing.T) {
	removed := urlAsset(4, "https://gone.example.com/")
	now := time.Now()
	removed.RemovedAt = &now
	web := model.Asset{ID: 6, Kind: model.KindService, Key: "203.0.113.7:443/tcp", Scope: model.ScopeOwned, Attrs: map[string]any{"ip": "203.0.113.7", "port": 443, "tls": true}}
	ssh := model.Asset{ID: 7, Kind: model.KindService, Key: "203.0.113.7:22/tcp", Scope: model.ScopeOwned, Attrs: map[string]any{"ip": "203.0.113.7", "port": 22}}
	shared := model.Asset{ID: 8, Kind: model.KindURL, Key: "https://cdn.example.net/", Scope: model.ScopeShared}
	dns := model.Asset{ID: 9, Kind: model.KindHostname, Key: "plain.example.com", Scope: model.ScopeOwned, Zone: "example.com"}
	ip := model.Asset{ID: 10, Kind: model.KindIP, Key: "203.0.113.7", Scope: model.ScopeOwned}
	th := newTmplHarness(t, nil, []model.Asset{
		urlAsset(1, "https://a.example.com/"), urlAsset(2, "https://b.example.com/"), urlAsset(3, "https://c.example.com/"),
		removed, web, ssh, shared, dns, ip,
	})
	// A guard that no longer classifies c.example.com as owned: the fresh
	// classification wins over the stored scope.
	th.g.classes = map[string]model.ScopeClass{"https://c.example.com/": model.ScopeExternal}
	th.tpl.up = updater.Update{
		Version: "v10.5.0", Changed: true, TemplateCount: 5000,
		NewTemplates: []string{"http/cves/2025/CVE-2025-55182.yaml"}, NewIDs: []string{"CVE-2025-55182"},
	}
	if err := th.r.updateAndScan(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	jobs := th.dq.jobs()
	if len(jobs) != 1 {
		t.Fatalf("jobs = %v", jobs)
	}
	j := jobs[0]
	if j.Kind != KindScanNewTemplates || j.Release != "v10.5.0" || !slices.Equal(j.Templates, th.tpl.up.NewTemplates) {
		t.Errorf("job = %+v", j)
	}
	if want := []int64{1, 2, 6}; !slices.Equal(j.AssetIDs, want) {
		t.Errorf("asset ids = %v, want %v (owned, non-removed, fresh class owned, web only)", j.AssetIDs, want)
	}
	if th.rec.updates[0] != "ok" || th.rec.newTpls != 1 {
		t.Errorf("metrics: %v new=%d", th.rec.updates, th.rec.newTpls)
	}
}

func TestUpdateOutcomesQueueNothingWhenNotWarranted(t *testing.T) {
	assets := []model.Asset{urlAsset(1, "https://a.example.com/")}
	newTpl := []string{"http/cves/x.yaml"}
	for name, tc := range map[string]struct {
		up      updater.Update
		err     error
		mut     func(*testCfg)
		wantErr bool
		metric  string
	}{
		"unchanged":               {up: updater.Update{Changed: false}, metric: "unchanged"},
		"changed but nothing new": {up: updater.Update{Changed: true}, metric: "ok"},
		"run_new_templates off": {up: updater.Update{Changed: true, NewTemplates: newTpl}, metric: "ok",
			mut: func(c *testCfg) { c.Nuclei.Update.RunNewTemplates = false }},
		"update error": {err: errors.New("rate limited"), wantErr: true, metric: "error"},
	} {
		th := newTmplHarness(t, tc.mut, assets)
		th.tpl.up, th.tpl.err = tc.up, tc.err
		err := th.r.updateAndScan(context.Background(), 0)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(th.dq.jobs()) != 0 {
			t.Errorf("%s: queued %v", name, th.dq.jobs())
		}
		if len(th.rec.updates) != 1 || th.rec.updates[0] != tc.metric {
			t.Errorf("%s: metrics = %v, want %s", name, th.rec.updates, tc.metric)
		}
	}
}

func TestNewTemplateJobsAreBatchedAndChunked(t *testing.T) {
	var assets []model.Asset
	for i := 1; i <= 120; i++ {
		assets = append(assets, urlAsset(int64(i), fmt.Sprintf("https://h%d.example.com/", i)))
	}
	th := newTmplHarness(t, nil, assets)
	var tpls []string
	for i := 0; i < 1100; i++ {
		tpls = append(tpls, fmt.Sprintf("http/cves/2025/CVE-2025-%04d.yaml", i))
	}
	th.tpl.up = updater.Update{Changed: true, Version: "v9", NewTemplates: tpls}
	if err := th.r.updateAndScan(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	jobs := th.dq.jobs()
	// 1100 templates -> 3 chunks of <=500; 120 assets -> 3 batches of <=50.
	if len(jobs) != 9 {
		t.Fatalf("jobs = %d, want 9", len(jobs))
	}
	var tplSeen, assetSeen = map[string]int{}, map[int64]int{}
	for _, j := range jobs {
		if len(j.Templates) > deltaTemplateChunk || len(j.AssetIDs) > deltaAssetBatch {
			t.Errorf("oversized job: %d templates, %d assets", len(j.Templates), len(j.AssetIDs))
		}
		for _, x := range j.Templates {
			tplSeen[x]++
		}
		for _, id := range j.AssetIDs {
			assetSeen[id]++
		}
	}
	if len(tplSeen) != 1100 || len(assetSeen) != 120 {
		t.Errorf("coverage: %d templates, %d assets", len(tplSeen), len(assetSeen))
	}
	// Re-running the same update queues nothing: the jobs are unique by args.
	if err := th.r.updateAndScan(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(th.dq.jobs()) != 9 {
		t.Errorf("duplicate jobs queued: %d", len(th.dq.jobs()))
	}
}

func TestHostnameWithLiveProbeIsScannedUnlessItsURLIsAlreadyCovered(t *testing.T) {
	host := func(id int64, key string) model.Asset {
		return model.Asset{ID: id, Kind: model.KindHostname, Key: key, Scope: model.ScopeOwned, Zone: "example.com", Source: "cf"}
	}
	th := newTmplHarness(t, nil, []model.Asset{
		urlAsset(1, "https://covered.example.com/"),
		host(2, "covered.example.com"), // its probe URL equals asset 1: skipped
		host(3, "live.example.com"),    // live probe, no URL asset: scanned
		host(4, "dead.example.com"),    // probe failed: skipped
		host(5, "noprobe.example.com"), // never probed: skipped
	})
	obs := map[int64][]model.Observation{
		2: {{AssetID: 2, Check: "http.probe", Data: map[string]any{"status": 200, "url": "https://covered.example.com/"}}},
		3: {{AssetID: 3, Check: "http.probe", Data: map[string]any{"status": 200, "url": "https://live.example.com/"}}},
		4: {{AssetID: 4, Check: "http.probe", Data: map[string]any{"results": []any{}}}},
	}
	th.r.Store = obsStore{th.st, obs}
	got, err := th.r.deltaAssetIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int64{1, 3}) {
		t.Errorf("ids = %v, want [1 3]", got)
	}
}

type obsStore struct {
	*fakeStore
	obs map[int64][]model.Observation
}

func (s obsStore) LatestObservations(_ context.Context, id int64) ([]model.Observation, error) {
	return s.obs[id], nil
}

// ---- running a batch --------------------------------------------------------------------

func sev(key string) model.FindingInput {
	return model.FindingInput{Check: "cve.nuclei", Key: key, Severity: model.SeverityCritical, Title: key}
}

func TestRunDeltaProcessesFindingsAsPartialRuns(t *testing.T) {
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/"), urlAsset(2, "https://b.example.com/")})
	th.dl.res = nuclei.ScanResult{Findings: map[int64][]model.FindingInput{1: {sev("CVE-2025-55182")}}}
	err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/cves/2025/CVE-2025-55182.yaml"}, AssetIDs: []int64{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	reqs := th.dl.requests()
	if len(reqs) != 1 || len(reqs[0].Targets) != 2 || !slices.Equal(reqs[0].Templates, []string{"/tpl/http/cves/2025/CVE-2025-55182.yaml"}) {
		t.Fatalf("scan requests = %+v", reqs)
	}
	if reqs[0].RatePerSec != 50 {
		t.Errorf("rate = %v, want the active profile's 50/s", reqs[0].RatePerSec)
	}
	calls := th.proc.calls
	if len(calls) != 1 || calls[0].asset.ID != 1 || calls[0].check != "cve.nuclei" || !calls[0].res.Partial || len(calls[0].res.Findings) != 1 {
		t.Fatalf("Process calls = %+v (want one partial cve.nuclei run for asset 1)", calls)
	}
	if len(calls[0].res.Observations) != 0 {
		t.Error("a delta run must not write observations or baselines")
	}
	// Scan history carries the delta name, never the regular check's: the
	// scheduler's due-computation for cve.nuclei must not be disturbed.
	runs := th.st.runs()
	if len(runs) != 2 {
		t.Fatalf("scan runs = %+v", runs)
	}
	for _, r := range runs {
		if r.Check != DeltaCheck || r.Tier != "active" {
			t.Errorf("run = %+v", r)
		}
	}
	for _, o := range th.rec.scans {
		if o.check == nuclei.NameActive {
			t.Errorf("metrics recorded the regular check name: %+v", o)
		}
	}
}

func TestRunDeltaNeverTouchesIneligibleAssets(t *testing.T) {
	removed := urlAsset(3, "https://gone.example.com/")
	now := time.Now()
	removed.RemovedAt = &now
	th := newTmplHarness(t, func(c *testCfg) { c.Profiles.Active.Enabled = false }, []model.Asset{urlAsset(1, "https://a.example.com/"), urlAsset(2, "https://b.example.com/"), removed})
	// Tier disabled by profile: nothing scanned at all.
	if err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	if len(th.dl.requests()) != 0 {
		t.Fatal("scan ran although the active tier is disabled")
	}

	th2 := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/"), urlAsset(2, "https://b.example.com/"), removed})
	th2.g.classes = map[string]model.ScopeClass{"https://b.example.com/": model.ScopeShared}
	if err := th2.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1, 2, 3, 99}}); err != nil {
		t.Fatal(err)
	}
	reqs := th2.dl.requests()
	if len(reqs) != 1 || len(reqs[0].Targets) != 1 || reqs[0].Targets[0].ID != 1 {
		t.Fatalf("targets = %+v, want only asset 1 (b re-classified shared, 3 removed, 99 gone)", reqs)
	}
}

func TestRunDeltaRecordsRefusedTargetsAsSkipped(t *testing.T) {
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/"), urlAsset(2, "https://b.example.com/")})
	th.dl.res = nuclei.ScanResult{Refused: []nuclei.ScanTarget{{ID: 2, URL: "https://b.example.com/"}}}
	if err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1, 2}}); err != nil {
		t.Fatal(err)
	}
	var skipped, ok int
	for _, r := range th.st.runs() {
		switch {
		case r.AssetID == 2 && strings.HasPrefix(r.Error, SkippedPrefix) && r.Check == DeltaCheck:
			skipped++
		case r.AssetID == 1 && r.Error == "":
			ok++
		}
	}
	if skipped != 1 || ok != 1 {
		t.Errorf("runs = %+v", th.st.runs())
	}
}

func TestRunDeltaSurfacesErrorsAfterProcessingFindings(t *testing.T) {
	boom := errors.New("nuclei: exit status 2")
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th.dl.res = nuclei.ScanResult{Findings: map[int64][]model.FindingInput{1: {sev("CVE-1")}}}
	th.dl.scanErr = boom
	err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1}})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v (River must retry)", err)
	}
	if len(th.proc.calls) != 1 {
		t.Error("findings that were matched before the failure must still be recorded")
	}
	runs := th.st.runs()
	if len(runs) != 1 || runs[0].Error == "" {
		t.Errorf("runs = %+v", runs)
	}

	th2 := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th2.dl.res = nuclei.ScanResult{Findings: map[int64][]model.FindingInput{1: {sev("CVE-1")}}}
	th2.proc.err = errors.New("db down")
	if err := th2.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1}}); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Errorf("process error lost: %v", err)
	}
}

func TestRunDeltaWaitsForTemplatesThatHaveNotArrived(t *testing.T) {
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th.dl.noTpls = true
	err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1}})
	if !errors.Is(err, errTemplatesNotReady) {
		t.Fatalf("err = %v", err)
	}
	if len(th.dl.requests()) != 0 {
		t.Error("scan ran without templates")
	}
	now := time.Now()
	var snooze *rivertype.JobSnoozeError
	if got := notReadyResult(err, now.Add(-time.Hour), now); !errors.As(got, &snooze) {
		t.Errorf("young job: %v, want a snooze", got)
	}
	var cancel *rivertype.JobCancelError
	if got := notReadyResult(err, now.Add(-13*time.Hour), now); !errors.As(got, &cancel) {
		t.Errorf("old job: %v, want a cancel", got)
	}
	other := errors.New("other")
	if !errors.Is(notReadyResult(other, now, now), other) || !errors.Is(notReadyResult(nil, now, now), nil) {
		t.Error("other results must pass through")
	}

	// Templates removed by a newer release: nothing to run, nothing to wait for.
	th2 := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th2.dl.missing = map[string]bool{"http/x.yaml": true}
	if err := th2.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1}}); err != nil || len(th2.dl.requests()) != 0 {
		t.Errorf("removed templates: err=%v scans=%d", err, len(th2.dl.requests()))
	}
}

func TestRunDeltaWithoutScannerIsANoop(t *testing.T) {
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th.r.Delta = nil
	if err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"x"}, AssetIDs: []int64{1}}); err != nil {
		t.Fatal(err)
	}
}

func TestRunDeltaHoldsAndReleasesHostSlots(t *testing.T) {
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/"), urlAsset(2, "https://a.example.com/other")})
	if err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1, 2}}); err != nil {
		t.Fatal(err)
	}
	if n := th.r.sems.size(); n != 0 {
		t.Errorf("host slots leaked: %d", n)
	}
	// A regular scan holding every slot of the host blocks the delta batch until
	// the context ends (shared per-host concurrency).
	rel1, _ := th.r.sems.acquire(context.Background(), "active|a.example.com", 2)
	rel2, _ := th.r.sems.acquire(context.Background(), "active|a.example.com", 2)
	defer rel1()
	defer rel2()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := th.r.runDelta(ctx, deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/x.yaml"}, AssetIDs: []int64{1}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want it to wait for the host slot", err)
	}
	if len(th.dl.requests()) != 1 {
		t.Errorf("the blocked batch must not have scanned: %d requests", len(th.dl.requests()))
	}
}

// ---- CVE-targeted scans -------------------------------------------------------------------

func TestCVEJobLooksUpTemplatesAtRunTime(t *testing.T) {
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th.dl.cveTable = map[string][]string{"CVE-2025-55182": {"http/cves/2025/CVE-2025-55182.yaml", "http/vulns/react.yaml"}}
	if err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanCVEs, CVEs: []string{"CVE-2025-55182"}, AssetIDs: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	reqs := th.dl.requests()
	if len(reqs) != 1 || len(reqs[0].Templates) != 2 {
		t.Fatalf("requests = %+v", reqs)
	}
	// No template for the CVE: a quiet no-op, no scan.
	th2 := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	if err := th2.r.runDelta(context.Background(), deltaJob{Kind: KindScanCVEs, CVEs: []string{"CVE-1999-0001"}, AssetIDs: []int64{1}}); err != nil || len(th2.dl.requests()) != 0 {
		t.Errorf("no-template CVE: err=%v scans=%d", err, len(th2.dl.requests()))
	}
	// No templates installed yet on this node: wait for them.
	th3 := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th3.dl.noTpls = true
	if err := th3.r.runDelta(context.Background(), deltaJob{Kind: KindScanCVEs, CVEs: []string{"CVE-2025-55182"}, AssetIDs: []int64{1}}); !errors.Is(err, errTemplatesNotReady) {
		t.Errorf("err = %v", err)
	}
}

func TestEnqueueCVEScan(t *testing.T) {
	var assets []model.Asset
	for i := 1; i <= 60; i++ {
		assets = append(assets, urlAsset(int64(i), fmt.Sprintf("https://h%d.example.com/", i)))
	}
	th := newTmplHarness(t, nil, assets)
	e := &Engine{d: th.r.Deps, r: th.r}

	n, err := e.EnqueueCVEScan(context.Background(), []string{" cve-2025-55182 ", "CVE-2025-55182", "CVE-2025-66478"})
	if err != nil {
		t.Fatal(err)
	}
	jobs := th.dq.jobs()
	if n != 2 || len(jobs) != 2 {
		t.Fatalf("queued %d jobs %v, want 2 (60 assets in batches of 50)", n, len(jobs))
	}
	for _, j := range jobs {
		if j.Kind != KindScanCVEs || !slices.Equal(j.CVEs, []string{"CVE-2025-55182", "CVE-2025-66478"}) {
			t.Errorf("job = %+v (ids must be normalised and deduplicated)", j)
		}
	}
	if len(ids(jobs)[0]) != 50 || len(ids(jobs)[1]) != 10 {
		t.Errorf("batches = %d/%d", len(ids(jobs)[0]), len(ids(jobs)[1]))
	}
	// Same request while the jobs are pending: unique, nothing new.
	if n, err := e.EnqueueCVEScan(context.Background(), []string{"CVE-2025-55182", "CVE-2025-66478"}); err != nil || n != 0 {
		t.Errorf("repeat queued %d (err %v)", n, err)
	}

	for _, bad := range [][]string{nil, {"nope"}, {"CVE-2025-1"}, {"CVE-2025-55182; id"}} {
		if _, err := e.EnqueueCVEScan(context.Background(), bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	e.r.Delta = nil
	if _, err := e.EnqueueCVEScan(context.Background(), []string{"CVE-2025-55182"}); !errors.Is(err, ErrNoTemplateScanning) {
		t.Errorf("err = %v", err)
	}
}

func TestEnqueueCVEScanWithNoEligibleAssets(t *testing.T) {
	th := newTmplHarness(t, nil, []model.Asset{{ID: 1, Kind: model.KindIP, Key: "203.0.113.7", Scope: model.ScopeOwned}})
	e := &Engine{d: th.r.Deps, r: th.r}
	if n, err := e.EnqueueCVEScan(context.Background(), []string{"CVE-2025-55182"}); err != nil || n != 0 {
		t.Errorf("n=%d err=%v", n, err)
	}
	// Without a queue (no database pool) the error is explicit.
	h2 := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	h2.r.q = noQueue{}
	e2 := &Engine{d: h2.r.Deps, r: h2.r}
	if _, err := e2.EnqueueCVEScan(context.Background(), []string{"CVE-2025-55182"}); !errors.Is(err, ErrNoQueue) {
		t.Errorf("err = %v", err)
	}
}

// ---- RunOnce ----------------------------------------------------------------------------

func newOnceEngine(t *testing.T, th *tmplHarness, checks ...check.Check) *Engine {
	t.Helper()
	d := th.r.Deps
	d.Checks = checks
	e, err := New(d, WithRunOnceConcurrency(2))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRunOnceUpdatesFirstThenRunsNewTemplates(t *testing.T) {
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th.tpl.up = updater.Update{Changed: true, Version: "v2", NewTemplates: []string{"http/cves/2025/CVE-2025-55182.yaml"}}
	th.dl.res = nuclei.ScanResult{Findings: map[int64][]model.FindingInput{1: {sev("CVE-2025-55182")}}}

	var order []string
	var mu sync.Mutex
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	chk := &fakeCheck{name: "p.rec", tier: model.TierPassive, run: func(context.Context, check.Target) (*check.Result, error) {
		note("regular scan")
		return &check.Result{}, nil
	}}
	e := newOnceEngine(t, th, chk)
	e.r.Templates = &orderTemplates{fakeTemplates: th.tpl, note: note}
	e.r.Delta = &orderDelta{fakeDelta: th.dl, note: note}
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"update", "regular scan", "delta scan"}; !slices.Equal(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	var partial int
	for _, c := range th.proc.calls {
		if c.check == "cve.nuclei" && c.res.Partial {
			partial++
		}
	}
	if partial != 1 {
		t.Errorf("want exactly one partial cve.nuclei run among %d Process calls", len(th.proc.calls))
	}
}

type orderTemplates struct {
	*fakeTemplates
	note func(string)
}

func (o *orderTemplates) Update(ctx context.Context) (updater.Update, error) {
	o.note("update")
	return o.fakeTemplates.Update(ctx)
}

type orderDelta struct {
	*fakeDelta
	note func(string)
}

func (o *orderDelta) Scan(ctx context.Context, r nuclei.ScanRequest) (nuclei.ScanResult, error) {
	o.note("delta scan")
	return o.fakeDelta.Scan(ctx, r)
}

func TestRunOnceSkipAndFailure(t *testing.T) {
	// --no-update: the updater is never touched.
	th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	e := newOnceEngine(t, th)
	if err := e.RunOnceWith(context.Background(), RunOnceOptions{SkipTemplateUpdate: true}); err != nil {
		t.Fatal(err)
	}
	if len(th.tpl.called()) != 0 {
		t.Errorf("updater called despite skip: %v", th.tpl.called())
	}
	// Updater disabled by config: also untouched.
	th2 := newTmplHarness(t, func(c *testCfg) { c.Nuclei.Update.Enabled = false }, nil)
	if err := newOnceEngine(t, th2).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(th2.tpl.called()) != 0 {
		t.Errorf("updater called while disabled: %v", th2.tpl.called())
	}
	// A failed update is reported but the pass still completes.
	th3 := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th3.tpl.err = errors.New("offline")
	ran := false
	chk := &fakeCheck{name: "p.rec", tier: model.TierPassive, run: func(context.Context, check.Target) (*check.Result, error) { ran = true; return &check.Result{}, nil }}
	err := newOnceEngine(t, th3, chk).RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "offline") {
		t.Errorf("err = %v", err)
	}
	if !ran {
		t.Error("the scan pass must continue after an update failure")
	}
}

// ---- catch-up loop ----------------------------------------------------------------------

func TestTemplateGuardUpdatesStaleNodesOnly(t *testing.T) {
	th := newTmplHarness(t, nil, nil)
	e := &Engine{d: th.r.Deps, o: options{guardInitial: time.Millisecond, guardEvery: 5 * time.Millisecond}, r: th.r}
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	th.tpl.skip = true // fresh: UpdateIfOlderThan reports nothing to do
	go e.templateGuard(ctx, done)
	deadline := time.Now().Add(5 * time.Second)
	for len(th.tpl.called()) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	calls := th.tpl.called()
	if len(calls) < 3 {
		t.Fatalf("guard did not tick: %v", calls)
	}
	// Max age is the interval plus a quarter, beyond the job's own jitter.
	for _, c := range calls {
		if c != "ifolder:7h30m0s" {
			t.Errorf("call = %q, want a conditional update with maxAge 7h30m", c)
		}
	}
	if len(th.dq.jobs()) != 0 || len(th.rec.updates) != 0 {
		t.Errorf("a fresh node must not queue or count anything: %v %v", th.dq.jobs(), th.rec.updates)
	}

	// A stale node updates and queues the new-template scans.
	th2 := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
	th2.tpl.up = updater.Update{Changed: true, Version: "v3", NewTemplates: []string{"http/cves/x.yaml"}}
	e2 := &Engine{d: th2.r.Deps, o: options{guardInitial: time.Millisecond, guardEvery: time.Hour}, r: th2.r}
	done2 := make(chan struct{})
	ctx2, cancel2 := context.WithCancel(context.Background())
	go e2.templateGuard(ctx2, done2)
	deadline = time.Now().Add(5 * time.Second)
	for len(th2.dq.jobs()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel2()
	<-done2
	if len(th2.dq.jobs()) != 1 {
		t.Errorf("stale node queued %v", th2.dq.jobs())
	}

	// Disabled via the option.
	if _, _, ok := (&Engine{d: th.r.Deps, o: options{guardInitial: -1}, r: th.r}).guardTiming(); ok {
		t.Error("negative initial delay must disable the guard")
	}
}

func TestStaleTemplatesAreLoggedAgainstMaxAgeWarn(t *testing.T) {
	var buf strings.Builder
	th := newTmplHarness(t, func(c *testCfg) { c.Nuclei.Update.MaxAgeWarn = 72 * time.Hour }, nil)
	th.r.log = slog.New(slog.NewTextHandler(&buf, nil))
	th.tpl.err = errors.New("github.com unreachable")
	th.tpl.status = updater.Status{Version: "v1", TemplateCount: 10, CheckedAt: th.now.Add(-100 * time.Hour), LastError: "github.com unreachable"}
	if err := th.r.updateAndScan(context.Background(), 0); err == nil {
		t.Fatal("expected the update error")
	}
	if out := buf.String(); !strings.Contains(out, "older than nuclei.update.max_age_warn") || !strings.Contains(out, "github.com unreachable") {
		t.Errorf("no staleness warning: %s", out)
	}
	buf.Reset()
	th.tpl.err = nil
	th.tpl.status.CheckedAt = th.now.Add(-time.Hour)
	if err := th.r.updateAndScan(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "older than") {
		t.Errorf("fresh templates must not warn: %s", buf.String())
	}
}

func TestStatusIsReportedToTheRecorder(t *testing.T) {
	th := newTmplHarness(t, nil, nil)
	th.tpl.status = updater.Status{Version: "v1", TemplateCount: 321, CheckedAt: time.Now()}
	th.tpl.up = updater.Update{Changed: false}
	if err := th.r.updateAndScan(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(th.rec.statuses) != 1 || th.rec.statuses[0] != 321 {
		t.Errorf("statuses = %v", th.rec.statuses)
	}
	// A recorder without the optional interface is fine.
	th.r.rec = th.rec.fakeRec
	if err := th.r.updateAndScan(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
}

// The scope verifier is the last gate: even an asset the engine's guard
// classifies as owned never reaches the nuclei binary unless the verifier (the
// real one resolves DNS and checks every address) agrees.
func TestOutOfScopeTargetsNeverReachTheBinary(t *testing.T) {
	root := t.TempDir()
	fakenuclei.WriteTree(t, root, fakenuclei.Template{Path: "http/cves/2025/CVE-2025-55182.yaml", ID: "CVE-2025-55182", CVE: "CVE-2025-55182"})
	bin := fakenuclei.Install(t, fakenuclei.Conf{})
	var verified []string
	verify := func(_ context.Context, host string) bool {
		verified = append(verified, host)
		return host == "a.example.com"
	}
	scanner := nuclei.NewScanner(config.NucleiConfig{TemplatesDir: root, Binary: bin.Path}, verify,
		nuclei.ExecRunner{Policy: func(context.Context, []string) ([]string, error) { return []string{"192.0.2.0/24"}, nil }}, nil)

	th := newTmplHarness(t, nil, []model.Asset{
		urlAsset(1, "https://a.example.com/"),
		urlAsset(2, "https://evil.example.net/"),      // owned per the guard, refused by the verifier
		urlAsset(3, "https://a.example.com.evil.io/"), // lookalike
	})
	th.r.Delta = scanner
	if err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/cves/2025/CVE-2025-55182.yaml"}, AssetIDs: []int64{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	calls := bin.ScanCalls()
	if len(calls) != 1 || !slices.Equal(calls[0].Targets, []string{"https://a.example.com/"}) {
		t.Fatalf("binary calls = %+v, want exactly the verified target", calls)
	}
	if len(verified) != 3 {
		t.Errorf("verifier consulted for %v, want all three", verified)
	}
	var skipped []int64
	for _, r := range th.st.runs() {
		if strings.HasPrefix(r.Error, SkippedPrefix) && r.Check == DeltaCheck {
			skipped = append(skipped, r.AssetID)
		}
	}
	slices.Sort(skipped)
	if !slices.Equal(skipped, []int64{2, 3}) {
		t.Errorf("skipped runs = %v, want [2 3]", skipped)
	}

	// Nothing verifiable: the binary is not even started.
	bin2 := fakenuclei.Install(t, fakenuclei.Conf{})
	none := nuclei.NewScanner(config.NucleiConfig{TemplatesDir: root, Binary: bin2.Path}, func(context.Context, string) bool { return false }, nuclei.ExecRunner{}, nil)
	th.r.Delta = none
	if err := th.r.runDelta(context.Background(), deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/cves/2025/CVE-2025-55182.yaml"}, AssetIDs: []int64{1, 2}}); err != nil {
		t.Fatal(err)
	}
	if len(bin2.Calls()) != 0 {
		t.Errorf("binary started with no verified target: %+v", bin2.Calls())
	}
}
