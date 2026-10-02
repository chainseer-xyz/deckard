package finding_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/notify"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// dstore is a minimal in-memory Store for dispatcher tests; unimplemented
// methods panic via the nil embedded interface.
type dstore struct {
	store.Store
	mu         sync.Mutex
	open       []model.Finding
	resolved   []model.Finding
	expired    int
	sinceSeen  []time.Time
	listErr    error
	resolveErr error
}

func (s *dstore) ExpireSuppressions(context.Context, time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expired++
	return 0, nil
}
func (s *dstore) ListFindings(context.Context, store.FindingFilter) ([]model.Finding, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.Finding(nil), s.open...), len(s.open), s.listErr
}
func (s *dstore) ResolvedSince(_ context.Context, t time.Time) ([]model.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sinceSeen = append(s.sinceSeen, t)
	var out []model.Finding
	for _, f := range s.resolved {
		if !f.ResolvedAt.Before(t) {
			out = append(out, f)
		}
	}
	return out, s.resolveErr
}

type fnotifier struct {
	name string
	mu   sync.Mutex
	fail bool
	pan  bool
	hang bool
	open [][]int64
	res  [][]int64
}

func (n *fnotifier) Name() string { return n.name }
func (n *fnotifier) Notify(ctx context.Context, open, resolved []model.Finding) error {
	n.mu.Lock()
	n.open = append(n.open, ids(open))
	n.res = append(n.res, ids(resolved))
	fail, pan, hang := n.fail, n.pan, n.hang
	n.mu.Unlock()
	if pan {
		panic("boom")
	}
	if hang {
		<-ctx.Done()
		return ctx.Err()
	}
	if fail {
		return errors.New("alertmanager unreachable")
	}
	return nil
}
func (n *fnotifier) setFail(v bool) { n.mu.Lock(); n.fail = v; n.mu.Unlock() }
func (n *fnotifier) calls() int     { n.mu.Lock(); defer n.mu.Unlock(); return len(n.open) }
func (n *fnotifier) lastRes() []int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.res[len(n.res)-1]
}

func ids(fs []model.Finding) []int64 {
	out := []int64{}
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func resolvedF(id int64, at time.Time) model.Finding {
	return model.Finding{ID: id, Status: model.StatusResolved, ResolvedAt: &at}
}

func eq(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFlushResendsOpenEveryCycle(t *testing.T) {
	clk := &clock{epoch}
	st := &dstore{open: []model.Finding{{ID: 1}, {ID: 2}}}
	n := &fnotifier{name: "am"}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now))
	for i := 0; i < 3; i++ {
		if err := d.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		clk.advance(2 * time.Minute)
	}
	if n.calls() != 3 || !eq(n.open[2], []int64{1, 2}) {
		t.Fatalf("open must be re-sent every cycle: %v", n.open)
	}
	if st.expired != 3 {
		t.Fatalf("suppressions must expire each cycle: %d", st.expired)
	}
}

// notifyN is a tiny helper to build []notify.Notifier from fakes.
type notifyN []*fnotifier

func (l notifyN) list() []notify.Notifier {
	out := make([]notify.Notifier, len(l))
	for i, n := range l {
		out[i] = n
	}
	return out
}

func TestResolvedResentUntilEachNotifierSucceeds(t *testing.T) {
	clk := &clock{epoch}
	good := &fnotifier{name: "good"}
	bad := &fnotifier{name: "bad", fail: true}
	st := &dstore{resolved: []model.Finding{resolvedF(7, epoch.Add(time.Second))}}
	d := finding.NewDispatcher(st, notifyN{good, bad}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now))
	clk.advance(time.Minute)

	err := d.Flush(context.Background())
	if err == nil {
		t.Fatal("failing notifier must surface an error")
	}
	if !eq(good.lastRes(), []int64{7}) || !eq(bad.lastRes(), []int64{7}) {
		t.Fatalf("both get the notice: %v %v", good.res, bad.res)
	}

	// Next cycle: good already acknowledged (no call: nothing open/pending),
	// bad is retried with the same resolved finding.
	clk.advance(2 * time.Minute)
	_ = d.Flush(context.Background())
	if good.calls() != 1 {
		t.Fatalf("good must not be re-sent a delivered resolution: %d calls", good.calls())
	}
	if bad.calls() != 2 || !eq(bad.lastRes(), []int64{7}) {
		t.Fatalf("bad must be retried: %v", bad.res)
	}

	// bad recovers: gets it once more, then never again.
	bad.setFail(false)
	clk.advance(2 * time.Minute)
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	callsAfter := bad.calls()
	clk.advance(2 * time.Minute)
	_ = d.Flush(context.Background())
	if bad.calls() != callsAfter {
		t.Fatal("resolution re-sent after success")
	}
}

func TestFailingNotifierDoesNotBlockOthers(t *testing.T) {
	st := &dstore{open: []model.Finding{{ID: 1}}}
	pan := &fnotifier{name: "pan", pan: true}
	hang := &fnotifier{name: "hang", hang: true}
	ok := &fnotifier{name: "ok"}
	d := finding.NewDispatcher(st, notifyN{pan, hang, ok}.list(), time.Minute, quiet, finding.WithNotifyTimeout(50*time.Millisecond))
	err := d.Flush(context.Background())
	if err == nil || ok.calls() != 1 {
		t.Fatalf("err=%v ok.calls=%d", err, ok.calls())
	}
}

func TestResolvedLookbackShrinksAfterAllSucceed(t *testing.T) {
	clk := &clock{epoch}
	st := &dstore{open: []model.Finding{{ID: 1}}}
	n := &fnotifier{name: "n"}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now))
	_ = d.Flush(context.Background())
	clk.advance(30 * time.Minute)
	_ = d.Flush(context.Background())
	clk.advance(30 * time.Minute)
	_ = d.Flush(context.Background())
	last := st.sinceSeen[len(st.sinceSeen)-1]
	if !last.After(epoch) || last.After(clk.t) {
		t.Fatalf("lookback should advance but stay <= now: %v", last)
	}
	// With a failing notifier and pending work the watermark must not move.
	n.setFail(true)
	st.resolved = []model.Finding{resolvedF(9, clk.t)}
	clk.advance(10 * time.Minute)
	_ = d.Flush(context.Background())
	first := st.sinceSeen[len(st.sinceSeen)-1]
	clk.advance(10 * time.Minute)
	_ = d.Flush(context.Background())
	clk.advance(10 * time.Minute)
	_ = d.Flush(context.Background())
	if got := st.sinceSeen[len(st.sinceSeen)-1]; !got.Equal(first) {
		t.Fatalf("watermark advanced despite failure: %v -> %v", first, got)
	}
}

func TestReresolvedFindingIsNotifiedAgain(t *testing.T) {
	clk := &clock{epoch}
	n := &fnotifier{name: "n"}
	st := &dstore{resolved: []model.Finding{resolvedF(3, epoch.Add(time.Second))}}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now))
	clk.advance(time.Minute)
	_ = d.Flush(context.Background())
	// Same id resolves again later (reopened in between): new resolved_at.
	st.resolved = []model.Finding{resolvedF(3, clk.t.Add(time.Second))}
	clk.advance(time.Minute)
	_ = d.Flush(context.Background())
	if n.calls() != 2 || !eq(n.lastRes(), []int64{3}) {
		t.Fatalf("second resolution must be notified: %v", n.res)
	}
}

func TestTrackerBounded(t *testing.T) {
	clk := &clock{epoch}
	n := &fnotifier{name: "n"}
	var rs []model.Finding
	for i := 1; i <= 5; i++ {
		rs = append(rs, resolvedF(int64(i), epoch.Add(time.Duration(i)*time.Second)))
	}
	st := &dstore{resolved: rs}
	d := finding.NewDispatcher(st, notifyN{n}.list(), 4*time.Minute, quiet, finding.WithClock(clk.now), finding.WithMaxTracked(2))
	clk.advance(time.Minute)
	_ = d.Flush(context.Background())
	// Only the 2 newest remain tracked; the 3 oldest are forgotten and re-sent
	// while they are still inside the lookback window.
	_ = d.Flush(context.Background())
	if !eq(n.lastRes(), []int64{1, 2, 3}) {
		t.Fatalf("bounded tracker should forget oldest: %v", n.res)
	}
}

func TestFlushStoreErrorsAndNoNotifiers(t *testing.T) {
	st := &dstore{listErr: errors.New("db down")}
	d := finding.NewDispatcher(st, nil, time.Minute, nil)
	if err := d.Flush(context.Background()); err == nil {
		t.Fatal("list error must surface")
	}
	st.listErr, st.resolveErr = nil, errors.New("db down")
	if err := d.Flush(context.Background()); err == nil {
		t.Fatal("resolved error must surface")
	}
	st.resolveErr = nil
	if err := d.Flush(context.Background()); err != nil {
		t.Fatalf("no notifiers is not an error: %v", err)
	}
}

type fticker struct {
	c       chan time.Time
	stopped bool
}

func (f *fticker) C() <-chan time.Time { return f.c }
func (f *fticker) Stop()               { f.stopped = true }

func TestRunTicksUntilCancelled(t *testing.T) {
	st := &dstore{open: []model.Finding{{ID: 1}}}
	n := &fnotifier{name: "n"}
	ft := &fticker{c: make(chan time.Time)}
	var gotInterval time.Duration
	d := finding.NewDispatcher(st, notifyN{n}.list(), 10*time.Second, quiet,
		finding.WithTicker(func(iv time.Duration) finding.Ticker { gotInterval = iv; return ft }))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()

	waitCalls := func(want int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for n.calls() < want {
			if time.Now().After(deadline) {
				t.Fatalf("want %d calls, have %d", want, n.calls())
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitCalls(1) // immediate flush
	ft.c <- epoch
	waitCalls(2)
	cancel()
	<-done
	if !ft.stopped || gotInterval != 5*time.Second {
		t.Fatalf("stopped=%v interval=%v", ft.stopped, gotInterval)
	}
}

func TestRunIntervalMinimumAndRealTicker(t *testing.T) {
	st := &dstore{}
	var iv time.Duration
	d := finding.NewDispatcher(st, nil, 500*time.Millisecond, quiet,
		finding.WithTicker(func(x time.Duration) finding.Ticker { iv = x; return &fticker{c: make(chan time.Time)} }))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.Run(ctx)
	if iv != time.Second {
		t.Fatalf("minimum interval is 1s, got %v", iv)
	}
	// default real ticker path
	d = finding.NewDispatcher(st, nil, 2*time.Second, quiet)
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	d.Run(ctx)
}
