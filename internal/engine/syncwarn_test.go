package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func shrinkHarness(t *testing.T) (*harness, *bytes.Buffer, error) {
	t.Helper()
	added := hostAsset(1, "add.example.com")
	changed := hostAsset(2, "chg.example.com")
	src := &fakeSource{name: "cf"}
	h := newHarness(func(c *testCfg) { c.sources = append(c.sources, src) },
		[]model.Asset{added, changed}, passiveCheck("dns.x"))
	var buf bytes.Buffer
	h.r.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.inv.syncDiff = store.InventoryDiff{Added: []model.Asset{added}, Changed: []model.Asset{changed}}
	err := fmt.Errorf("%w: cf: 40 of 50 assets vanished", inventory.ErrSuspiciousShrink)
	h.inv.syncErr = err
	return h, &buf, err
}

// A suspicious shrink returns the applied diff together with the error. The
// engine must still act on the diff, record the sync as not ok, and say why.
func TestRunSyncSuspiciousShrinkStillActsOnDiff(t *testing.T) {
	h, buf, _ := shrinkHarness(t)
	err := h.r.runSync(context.Background(), "cf")
	if !errors.Is(err, inventory.ErrSuspiciousShrink) {
		t.Fatalf("err = %v, want ErrSuspiciousShrink", err)
	}
	if got, want := strings.Join(h.q.keys(), ","), "1|passive|dns.x,2|passive|dns.x"; got != want {
		t.Fatalf("queued %s, want %s (scans for added/changed must still be queued)", got, want)
	}
	if oks := h.rec.syncs["cf"]; len(oks) != 1 || oks[0] {
		t.Fatalf("ObserveSync ok values = %v, want [false]", oks)
	}
	if h.rec.changes["added"] != 1 || h.rec.changes["changed"] != 1 {
		t.Fatalf("diff must be reported: %v", h.rec.changes)
	}
	log := buf.String()
	if !strings.Contains(log, "level=WARN") || !strings.Contains(log, "cf") || !strings.Contains(log, "suspicious shrink") {
		t.Fatalf("expected a WARN naming the source and the reason, got:\n%s", log)
	}
}

// River must not hammer retries for a suspicious shrink: the next periodic
// sync re-evaluates. Plain errors keep River's normal retry/backoff.
func TestSyncWorkerCancelsSuspiciousShrinkOnly(t *testing.T) {
	h, _, _ := shrinkHarness(t)
	w := &syncWorker{r: h.r}
	job := &river.Job[SyncSourceArgs]{Args: SyncSourceArgs{Source: "cf"}}
	err := w.Work(context.Background(), job)
	var jc *river.JobCancelError
	if !errors.As(err, &jc) {
		t.Fatalf("suspicious shrink must be a permanent job error (JobCancel), got %T %v", err, err)
	}
	if !errors.Is(err, inventory.ErrSuspiciousShrink) {
		t.Fatalf("cancel must keep the cause: %v", err)
	}

	h2, _, _ := shrinkHarness(t)
	h2.inv.syncDiff = store.InventoryDiff{}
	h2.inv.syncErr = errors.New("cf 503")
	err = (&syncWorker{r: h2.r}).Work(context.Background(), job)
	if err == nil || errors.As(err, &jc) {
		t.Fatalf("plain errors must be retried normally, got %T %v", err, err)
	}
}

// A plain failure with an empty diff still queues nothing and changes nothing.
func TestRunSyncPlainFailureActsOnNothing(t *testing.T) {
	h, _, _ := shrinkHarness(t)
	h.inv.syncDiff = store.InventoryDiff{}
	h.inv.syncErr = errors.New("cf 503")
	if err := h.r.runSync(context.Background(), "cf"); err == nil {
		t.Fatal("expected error")
	}
	if len(h.q.keys()) != 0 || len(h.rec.changes) != 0 {
		t.Fatalf("queued=%v changes=%v", h.q.keys(), h.rec.changes)
	}
}
