package finding_test

import (
	"context"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestFlushSkipsFindingsMatchingConfigSuppression(t *testing.T) {
	st := &dstore{open: []model.Finding{
		{ID: 1, Check: "http.headers", AssetKey: "blog.example.com", Status: model.StatusOpen, Severity: model.SeverityLow},
		{ID: 2, Check: "tls.cert", AssetKey: "blog.example.com", Status: model.StatusOpen, Severity: model.SeverityLow},
	}}
	n := &fnotifier{name: "am"}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet,
		finding.WithSuppressions([]config.Suppression{{Match: "check=http.headers asset=blog.example.com", Reason: "accepted"}}))
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.calls() != 1 || !eq(n.open[0], []int64{2}) {
		t.Fatalf("suppressed finding must not be notified: %v", n.open)
	}
}

func TestFlushOnlySuppressedOpenSendsNothing(t *testing.T) {
	st := &dstore{open: []model.Finding{{ID: 1, Check: "c", AssetKey: "a.example.com", Status: model.StatusOpen}}}
	n := &fnotifier{name: "am"}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet,
		finding.WithSuppressions([]config.Suppression{{Match: "check=c", Reason: "r"}}))
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.calls() != 0 {
		t.Fatalf("nothing to send: %v", n.open)
	}
}

func openN(n int) []model.Finding {
	out := make([]model.Finding, n)
	for i := range out {
		out[i] = model.Finding{ID: int64(i + 1), Status: model.StatusOpen}
	}
	return out
}

func TestFlushBatchesOpenAndSendsResolvedOnlyInFirstChunk(t *testing.T) {
	clk := &clock{epoch}
	st := &dstore{open: openN(250), resolved: []model.Finding{resolvedF(900, epoch.Add(time.Minute))}}
	n := &fnotifier{name: "am"}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now))
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.calls() != 3 {
		t.Fatalf("want 3 chunks, got %d", n.calls())
	}
	sizes := []int{len(n.open[0]), len(n.open[1]), len(n.open[2])}
	if sizes[0] != 100 || sizes[1] != 100 || sizes[2] != 50 {
		t.Fatalf("chunk sizes %v", sizes)
	}
	if !eq(n.res[0], []int64{900}) || len(n.res[1]) != 0 || len(n.res[2]) != 0 {
		t.Fatalf("resolved only in first chunk: %v", n.res)
	}
	// Resolved was acknowledged: next cycle does not resend it.
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(n.res[3]) != 0 {
		t.Fatalf("resolved resent after success: %v", n.res[3])
	}
}

func TestChunkFailureIsolatedAndResolvedRetried(t *testing.T) {
	clk := &clock{epoch}
	st := &dstore{open: openN(150), resolved: []model.Finding{resolvedF(900, epoch.Add(time.Minute))}}
	bad := &fnotifier{name: "bad", fail: true}
	good := &fnotifier{name: "good"}
	d := finding.NewDispatcher(st, notifyN{bad, good}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now))
	if err := d.Flush(context.Background()); err == nil {
		t.Fatal("want joined error")
	}
	if bad.calls() != 1 {
		t.Fatalf("a failing notifier stops after the failed chunk: %d", bad.calls())
	}
	if good.calls() != 2 {
		t.Fatalf("healthy notifier still gets every chunk: %d", good.calls())
	}
	bad.setFail(false)
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !eq(bad.res[1], []int64{900}) {
		t.Fatalf("resolved must be retried for the notifier that failed: %v", bad.res)
	}
}

func resolvedN(n int, at time.Time) []model.Finding {
	out := make([]model.Finding, n)
	for i := range out {
		out[i] = resolvedF(int64(900+i), at)
	}
	return out
}

// A notifier that was down through a mass resolution must not be handed every
// pending resolved notice in one request: resolved notices are chunked like
// open findings, and notices delivered by a successful chunk are not re-sent
// after a later chunk fails.
func TestFlushChunksResolvedNotices(t *testing.T) {
	clk := &clock{epoch}
	st := &dstore{resolved: resolvedN(250, epoch.Add(time.Minute))}
	n := &fnotifier{name: "am"}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now))
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.calls() != 3 {
		t.Fatalf("250 resolved notices must arrive in 3 chunks, got %d call(s)", n.calls())
	}
	sizes := []int{len(n.res[0]), len(n.res[1]), len(n.res[2])}
	if sizes[0] != 100 || sizes[1] != 100 || sizes[2] != 50 {
		t.Fatalf("resolved chunk sizes %v, want [100 100 50]", sizes)
	}
	// Everything was acknowledged: the next cycle re-sends nothing.
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.calls() != 3 {
		t.Fatalf("acknowledged resolved notices were re-sent: %d calls", n.calls())
	}
}

func TestResolvedDeliveredBeforeChunkFailureNotResent(t *testing.T) {
	clk := &clock{epoch}
	st := &dstore{resolved: resolvedN(150, epoch.Add(time.Minute))}
	n := &fnotifier{name: "am", failAfter: 1} // first chunk succeeds, second fails
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now))
	if err := d.Flush(context.Background()); err == nil {
		t.Fatal("want error from failing second chunk")
	}
	if n.calls() != 2 {
		t.Fatalf("want 2 calls (second fails), got %d", n.calls())
	}
	n.setFail(false)
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Only the 50 notices of the failed chunk are retried.
	last := n.res[len(n.res)-1]
	if len(last) != 50 {
		t.Fatalf("retry re-sent %d notices, want only the 50 undelivered", len(last))
	}
}

func TestBatchSizeOption(t *testing.T) {
	st := &dstore{open: openN(5)}
	n := &fnotifier{name: "am"}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet, finding.WithBatchSize(2))
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.calls() != 3 {
		t.Fatalf("calls %d", n.calls())
	}
}
