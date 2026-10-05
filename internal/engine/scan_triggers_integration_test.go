package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

type failSecondDeltaQueue struct {
	queue
	calls int
}

func (q *failSecondDeltaQueue) enqueueDelta(ctx context.Context, job deltaJob) (bool, error) {
	q.calls++
	if q.calls == 2 {
		return false, errors.New("enqueue interrupted after the first batch")
	}
	return q.queue.(templateQueue).enqueueDelta(ctx, job)
}

func outboxEngine(t *testing.T) (*Engine, *pgxpool.Pool, store.ScanTriggerStore) {
	t.Helper()
	e, pool, _, _, _, st := templateEngine(t, []string{RoleAPI})
	assets := make([]store.AssetUpsert, 100)
	for i := range assets {
		assets[i] = store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindURL,
			Key: fmt.Sprintf("https://asset-%03d.example.com/", i), Source: "test", Zone: "example.com"}, Scope: model.ScopeOwned}
	}
	if _, err := st.AddDiscovered(context.Background(), assets, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	return e, pool, st.(store.ScanTriggerStore)
}

func outboxUpdater(t *testing.T, dir, binary string, triggers store.ScanTriggerStore) *updater.Updater {
	t.Helper()
	u, err := updater.New(updater.Config{Dir: dir, Binary: binary, MinTemplates: 20, MinHTTPTemplates: 10,
		BeforePublish: func(ctx context.Context, up updater.Update) error {
			if len(up.NewTemplates) == 0 {
				return nil
			}
			return triggers.PutScanTrigger(ctx, store.NewScanTrigger(store.ScanTriggerTemplates, up.Version, up.NewTemplates, nil))
		}})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func pendingTriggerCount(t *testing.T, triggers store.ScanTriggerStore, kind string, want int) {
	t.Helper()
	pending, err := triggers.ListPendingScanTriggers(context.Background(), kind)
	if err != nil || len(pending) != want {
		t.Fatalf("pending %s triggers=%v err=%v, want %d", kind, pending, err, want)
	}
}

func TestIntegrationTemplateOutboxSurvivesPartialEnqueueAndRestart(t *testing.T) {
	for _, moved := range []bool{false, true} {
		t.Run(fmt.Sprintf("new_volume=%v", moved), func(t *testing.T) { replayTemplateOutbox(t, moved) })
	}
}

func replayTemplateOutbox(t *testing.T, moved bool) {
	ctx := context.Background()
	e, pool, triggers := outboxEngine(t)
	base, next := t.TempDir(), t.TempDir()
	fakenuclei.WriteTree(t, base, fakenuclei.BulkTemplates(30)...)
	fakenuclei.WriteTree(t, next, append(fakenuclei.BulkTemplates(30), fakenuclei.Template{Path: "http/new.yaml", ID: "new"})...)
	bin := fakenuclei.Install(t, fakenuclei.Conf{Version: "v1", Tree: base})
	dir := filepath.Join(t.TempDir(), "templates")
	u := outboxUpdater(t, dir, bin.Path, triggers)
	if _, err := u.Update(ctx); err != nil {
		t.Fatal(err)
	}
	pendingTriggerCount(t, triggers, store.ScanTriggerTemplates, 0)
	bin.Set(func(c *fakenuclei.Conf) { c.Version, c.Tree = "v2", next })
	interrupted := e.r.withQueue(&failSecondDeltaQueue{queue: e.r.q})
	interrupted.Templates = u
	if err := interrupted.updateAndScan(ctx, 0); err == nil {
		t.Fatal("expected partial enqueue failure")
	}
	st, err := u.Status()
	if err != nil || st.Version != "v2" {
		t.Fatalf("release was not committed before interruption: %+v err=%v", st, err)
	}
	pendingTriggerCount(t, triggers, store.ScanTriggerTemplates, 1)
	if _, n := riverJobs(t, pool, KindScanNewTemplates); n != 1 {
		t.Fatalf("partial enqueue created %d jobs, want 1", n)
	}
	if moved {
		dir = filepath.Join(t.TempDir(), "moved-templates")
	}
	restarted := e.r.withQueue(e.r.q)
	restarted.Templates = outboxUpdater(t, dir, bin.Path, triggers)
	if err := restarted.updateAndScan(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	pendingTriggerCount(t, triggers, store.ScanTriggerTemplates, 0)
	if _, n := riverJobs(t, pool, KindScanNewTemplates); n != 3 {
		t.Fatalf("replay created %d jobs, want 3 deduplicated batches", n)
	}
	if err := restarted.updateAndScan(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if _, n := riverJobs(t, pool, KindScanNewTemplates); n != 3 {
		t.Fatalf("acknowledged delta was replayed: %d jobs", n)
	}
}

type outboxCVEScanTrigger struct{ engine *Engine }

func (t outboxCVEScanTrigger) EnqueueCVEScan(ctx context.Context, cves []string) (int, error) {
	return t.engine.EnqueueCVEScan(ctx, cves)
}

func TestIntegrationKEVOutboxSurvivesPartialEnqueueAndFeedRestart(t *testing.T) {
	ctx := context.Background()
	e, pool, triggers := outboxEngine(t)
	var updated atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/epss" {
			_, _ = w.Write([]byte(`{"status":"OK","data":[]}`))
			return
		}
		etag, body := `"v1"`, `{"count":1,"vulnerabilities":[{"cveID":"CVE-2024-00001"}]}`
		if updated.Load() {
			etag, body = `"v2"`, `{"count":2,"vulnerabilities":[{"cveID":"CVE-2024-00001"},{"cveID":"CVE-2025-00002"}]}`
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	opts := vulnintel.Options{Dir: t.TempDir(), KEVURL: srv.URL + "/kev", EPSSURL: srv.URL + "/epss", HTTPClient: srv.Client(),
		BeforePublish: func(ctx context.Context, delta vulnintel.Delta) error {
			return triggers.PutScanTrigger(ctx, store.NewScanTrigger(store.ScanTriggerKEV, delta.Revision, nil, delta.NewKEV))
		}}
	feed, err := vulnintel.NewService(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := feed.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	pendingTriggerCount(t, triggers, store.ScanTriggerKEV, 0)
	updated.Store(true)
	baseQueue := e.r.q
	e.r.q = &failSecondDeltaQueue{queue: baseQueue}
	job := &vulnintelJob{feed: feed, trigger: outboxCVEScanTrigger{e}, triggers: triggers, log: quietLog}
	if err := job.run(ctx); err == nil {
		t.Fatal("expected partial KEV enqueue failure")
	}
	pendingTriggerCount(t, triggers, store.ScanTriggerKEV, 1)
	e.r.q = baseQueue
	replayKEVOutbox(t, opts, e, pool, triggers)
}

func TestIntegrationKEVFallbackSeparatesCatalogRevisions(t *testing.T) {
	ctx := context.Background()
	_, _, triggers := outboxEngine(t)
	feed := &fakeFeed{}
	scan := &fakeTrigger{}
	job := &vulnintelJob{feed: feed, trigger: scan, triggers: triggers, log: quietLog}
	for _, step := range []struct {
		revision string
		fail     bool
		calls    int
		pending  int
	}{
		{"catalog-v2", false, 1, 0},
		{"catalog-v2", false, 1, 0}, // the same publication remains acknowledged
		{"catalog-v4", true, 2, 1},  // the same CVEs in a later publication create new work
		{"catalog-v4", false, 3, 0}, // retry acknowledges only the new revision
		{"catalog-v4", false, 3, 0},
	} {
		feed.delta = vulnintel.Delta{Revision: step.revision, NewKEV: []string{"CVE-2025-00002"}}
		scan.err = nil
		if step.fail {
			scan.err = errors.New("queue unavailable")
		}
		if err := job.run(ctx); (err != nil) != step.fail {
			t.Fatalf("revision %q: err=%v, want failure=%v", step.revision, err, step.fail)
		}
		if len(scan.calls) != step.calls {
			t.Fatalf("revision %q: scan calls=%v, want %d", step.revision, scan.calls, step.calls)
		}
		pendingTriggerCount(t, triggers, store.ScanTriggerKEV, step.pending)
		if step.pending > 0 {
			pending, err := triggers.ListPendingScanTriggers(ctx, store.ScanTriggerKEV)
			if err != nil || pending[0].Release != step.revision {
				t.Fatalf("fallback discarded the catalog revision: %+v err=%v", pending, err)
			}
		}
	}
}

func replayKEVOutbox(t *testing.T, opts vulnintel.Options, e *Engine, pool *pgxpool.Pool, triggers store.ScanTriggerStore) {
	t.Helper()
	ctx := context.Background()
	restored, err := vulnintel.NewService(opts)
	if err != nil {
		t.Fatal(err)
	}
	if delta, err := restored.Refresh(ctx); err != nil || !delta.NotModified {
		t.Fatalf("persisted KEV catalog was not restored: %+v err=%v", delta, err)
	}
	job := &vulnintelJob{feed: restored, trigger: outboxCVEScanTrigger{e}, triggers: triggers, log: quietLog}
	if err := job.run(ctx); err != nil {
		t.Fatal(err)
	}
	pendingTriggerCount(t, triggers, store.ScanTriggerKEV, 0)
	if _, n := riverJobs(t, pool, KindScanCVEs); n != 3 {
		t.Fatalf("KEV replay created %d jobs, want 3 deduplicated batches", n)
	}
	if err := job.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, n := riverJobs(t, pool, KindScanCVEs); n != 3 {
		t.Fatalf("304 requeued an acknowledged KEV delta: %d jobs", n)
	}
}
