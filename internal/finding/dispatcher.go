package finding

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/notify"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// resolvedKey identifies one resolution of a finding (a finding can resolve,
// reopen and resolve again; each resolution needs its own notice).
type resolvedKey struct {
	id int64
	at int64 // resolved_at, UnixNano
}

// tracker remembers which resolutions one notifier has acknowledged. It is
// bounded: past max entries the oldest are forgotten. Forgetting is safe
// because the dispatcher's lookback window (see Flush) is far shorter than
// what the bound allows in practice, and Alertmanager expires an alert by
// itself at endsAt/resolve_timeout if a notice is ever missed. The memory is
// not persisted: after a restart resolutions are not re-sent beyond the
// lookback window, and Alertmanager's expiry covers the gap.
type tracker struct {
	max   int
	done  map[resolvedKey]struct{}
	order []resolvedKey
}

func (t *tracker) has(k resolvedKey) bool { _, ok := t.done[k]; return ok }

func (t *tracker) add(k resolvedKey) {
	if t.has(k) {
		return
	}
	t.done[k] = struct{}{}
	t.order = append(t.order, k)
	for t.max > 0 && len(t.order) > t.max {
		delete(t.done, t.order[0])
		t.order = t.order[1:]
	}
}

// defaultBatchSize bounds the open findings per Notify call so a large open
// set never becomes one giant request.
const defaultBatchSize = 100

// Dispatcher periodically pushes the current open findings and recent
// resolutions to every notifier.
type Dispatcher struct {
	st        store.Store
	notifiers []notify.Notifier
	resend    time.Duration
	log       *slog.Logger
	opts      options
	sup       *Suppressor

	mu     sync.Mutex // serialises Flush
	since  time.Time  // resolved-lookback watermark
	tracks []*tracker // parallel to notifiers
}

// NewDispatcher builds a Dispatcher. resend is notify.resend; the loop ticks
// at resend/2 (minimum 1s).
func NewDispatcher(st store.Store, notifiers []notify.Notifier, resend time.Duration, log *slog.Logger, opts ...Option) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	o := buildOptions(opts)
	if !o.enricherSet && st != nil {
		o.enricher = NewEnricher(st)
	}
	if o.batchSize < 1 {
		o.batchSize = defaultBatchSize
	}
	sup, err := NewSuppressor(o.suppressions)
	if err != nil {
		log.Error("finding: invalid suppressions ignored entirely by dispatcher", "err", err)
		sup = &Suppressor{}
	}
	d := &Dispatcher{st: st, notifiers: notifiers, resend: resend, log: log, opts: o, sup: sup, since: o.now()}
	for range notifiers {
		d.tracks = append(d.tracks, &tracker{max: o.maxTracked, done: map[resolvedKey]struct{}{}})
	}
	return d
}

func (d *Dispatcher) interval() time.Duration {
	iv := d.resend / 2
	if iv < time.Second {
		iv = time.Second
	}
	return iv
}

// Run flushes immediately and then on every tick until ctx is done.
func (d *Dispatcher) Run(ctx context.Context) {
	tk := d.opts.newTicker(d.interval())
	defer tk.Stop()
	for {
		if err := d.Flush(ctx); err != nil && ctx.Err() == nil {
			d.log.Warn("finding: notification cycle had failures", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tk.C():
		}
	}
}

// Flush performs one cycle: expire suppressions, load OPEN findings and
// recent resolutions, and call every notifier concurrently. A failing
// notifier does not affect the others; its resolved notices are retried next
// cycle until it succeeds once. The returned error joins notifier failures.
func (d *Dispatcher) Flush(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cycleStart := d.opts.now()

	if n, err := d.st.ExpireSuppressions(ctx, cycleStart); err != nil {
		d.log.Warn("finding: expire suppressions", "err", err)
	} else if n > 0 {
		d.log.Info("finding: suppressions expired", "count", n)
	}
	open, _, err := d.st.ListFindings(ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusOpen}})
	if err != nil {
		return fmt.Errorf("list open findings: %w", err)
	}
	resolved, err := d.st.ResolvedSince(ctx, d.since)
	if err != nil {
		return fmt.Errorf("list resolved findings: %w", err)
	}
	if len(d.notifiers) == 0 {
		return nil
	}
	open = d.dropSuppressed(open, cycleStart)
	open = d.opts.enricher.Enrich(ctx, open)

	errs := make([]error, len(d.notifiers))
	allOK := true
	var wg sync.WaitGroup
	for i, n := range d.notifiers {
		var pending []model.Finding
		for _, f := range resolved {
			if f.ResolvedAt != nil && !d.tracks[i].has(keyOf(f)) {
				pending = append(pending, f)
			}
		}
		if len(open) == 0 && len(pending) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			nctx, cancel := context.WithTimeout(ctx, d.opts.notifyTimeout)
			defer cancel()
			// Chunk the open set AND the resolved notices: a notifier that was
			// down through a mass resolution must not be handed every pending
			// notice in one request. Stop at the first failure: undelivered
			// chunks are re-sent next cycle, while notices a successful chunk
			// already delivered are tracked and never re-sent.
			for c, off, rOff := 0, 0, 0; c == 0 || off < len(open) || rOff < len(pending); c++ {
				end := min(off+d.opts.batchSize, len(open))
				rEnd := min(rOff+d.opts.batchSize, len(pending))
				res := pending[rOff:rEnd]
				if err := safeNotify(nctx, n, open[off:end], res); err != nil {
					errs[i] = fmt.Errorf("notifier %s: %w", n.Name(), err)
					return
				}
				// Only this goroutine touches tracks[i].
				for _, f := range res {
					d.tracks[i].add(keyOf(f))
				}
				off, rOff = end, rEnd
			}
		}()
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			allOK = false
		}
	}
	// Once every notifier has seen everything resolved so far, shrink the
	// lookback. Keep one resend of overlap: resolved_at is stamped by the
	// processor's clock before its transaction commits, so a row can become
	// visible slightly after we looked; the per-notifier tracker dedupes the
	// overlap.
	if allOK {
		if w := cycleStart.Add(-d.resend); w.After(d.since) {
			d.since = w
		}
	}
	return errors.Join(errs...)
}

// dropSuppressed removes findings that match a configured suppression: the
// Processor suppresses them right after reconciling, but a flush in between
// must not alert on them.
func (d *Dispatcher) dropSuppressed(open []model.Finding, now time.Time) []model.Finding {
	if len(d.sup.rules) == 0 {
		return open
	}
	out := open[:0:0]
	for _, f := range open {
		if _, _, ok := d.sup.Match(f, now); ok {
			continue
		}
		out = append(out, f)
	}
	return out
}

func keyOf(f model.Finding) resolvedKey {
	return resolvedKey{id: f.ID, at: f.ResolvedAt.UnixNano()}
}

func safeNotify(ctx context.Context, n notify.Notifier, open, resolved []model.Finding) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return n.Notify(ctx, open, resolved)
}
