package refdata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Outcomes of a refresh, also the values of the refresh_total result label.
const (
	OutcomeOK        = "ok"        // new data validated, applied and persisted
	OutcomeUnchanged = "unchanged" // sources unchanged since the applied data
	OutcomeRejected  = "rejected"  // downloaded data failed validation; old data kept
	OutcomeError     = "error"     // could not download or apply; old data kept
)

// Where the live data came from.
const (
	SourceEmbedded  = "embedded"
	SourcePersisted = "persisted"
	SourceRefreshed = "refreshed"
)

// DefaultMaxShrink is the largest tolerated relative shrink of a dataset.
const DefaultMaxShrink = 0.5

// Dataset describes one refreshable dataset of parsed type T.
type Dataset[T any] struct {
	// Name is a short [a-z0-9_-] identifier; it names the persisted file and
	// the metric label.
	Name string
	// URLs are the HTTPS sources. Parse receives the body of each (keyed by
	// URL); a source that could not be fetched and has no stored copy is
	// absent from the map.
	URLs []string
	// Parse converts and validates the raw sources and merges them with the
	// embedded data. It must not panic (a panic is recovered and rejected).
	Parse func(bodies map[string][]byte) (T, error)
	// Count is the dataset size used by MinEntries and the shrink guard.
	Count func(T) int
	// Apply installs a validated value into its consumers.
	Apply func(T) error
	// Embedded loads the always-available fallback.
	Embedded func() (T, error)
	// MinEntries rejects data smaller than this.
	MinEntries int
	// MaxShrink rejects data smaller than (1-MaxShrink) of the applied
	// dataset (default DefaultMaxShrink; 0 uses the default).
	MaxShrink float64
}

// Result reports one refresh.
type Result struct {
	Dataset string
	Outcome string
	Entries int
	Err     error
}

// Recorder receives refdata metrics. Implementations must be concurrency safe.
type Recorder interface {
	ObserveRefdata(dataset, result string)
	SetRefdataState(dataset string, entries int, updated time.Time)
}

// Options configure a Runner.
type Options struct {
	// Dir is where the last good copy is persisted ("" disables persistence).
	Dir     string
	Fetcher *Fetcher
	Log     *slog.Logger
	Rec     Recorder
	Now     func() time.Time
}

type sourceState struct {
	Validators
	Body []byte `json:"body"`
}

type snapshot struct {
	Updated time.Time              `json:"updated"`
	Sources map[string]sourceState `json:"sources"`
}

type live[T any] struct {
	val    T
	count  int
	source string
}

// Updater is the type-erased face of a Runner.
type Updater interface {
	Name() string
	Init() error
	Refresh(ctx context.Context) Result
}

// Runner owns the live value of one dataset.
type Runner[T any] struct {
	ds   Dataset[T]
	opts Options

	cur atomic.Pointer[live[T]]

	mu   sync.Mutex // serialises Init/Refresh
	snap snapshot
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// NewRunner validates ds and builds its runner. Call Init before use.
func NewRunner[T any](ds Dataset[T], opts Options) (*Runner[T], error) {
	switch {
	case !nameRE.MatchString(ds.Name):
		return nil, fmt.Errorf("refdata: invalid dataset name %q", ds.Name)
	case ds.Parse == nil || ds.Count == nil || ds.Apply == nil || ds.Embedded == nil:
		return nil, fmt.Errorf("refdata: %s: Parse, Count, Apply and Embedded are required", ds.Name)
	case ds.MaxShrink < 0 || ds.MaxShrink >= 1:
		return nil, fmt.Errorf("refdata: %s: MaxShrink must be in [0,1)", ds.Name)
	}
	if ds.MaxShrink == 0 {
		ds.MaxShrink = DefaultMaxShrink
	}
	if opts.Fetcher == nil {
		opts.Fetcher = &Fetcher{}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Runner[T]{ds: ds, opts: opts}, nil
}

// Name implements Updater.
func (r *Runner[T]) Name() string { return r.ds.Name }

// Value returns the live dataset (false before Init).
func (r *Runner[T]) Value() (T, bool) {
	l := r.cur.Load()
	if l == nil {
		var zero T
		return zero, false
	}
	return l.val, true
}

// Source reports where the live data came from ("" before Init).
func (r *Runner[T]) Source() string {
	if l := r.cur.Load(); l != nil {
		return l.source
	}
	return ""
}

func (r *Runner[T]) path() string {
	if r.opts.Dir == "" {
		return ""
	}
	return filepath.Join(r.opts.Dir, r.ds.Name+".json")
}

func (r *Runner[T]) safeParse(bodies map[string][]byte) (v T, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("parser panic: %v", p)
		}
	}()
	return r.ds.Parse(bodies)
}

func (r *Runner[T]) report(entries int, updated time.Time) {
	if r.opts.Rec != nil {
		r.opts.Rec.SetRefdataState(r.ds.Name, entries, updated)
	}
}

// Init installs the best offline data: the persisted last-good copy when it
// exists and still validates, else the embedded fallback. It never touches
// the network and is what runs before the first refresh.
func (r *Runner[T]) Init() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.path(); p != "" {
		if snap, ok := r.loadPersisted(p); ok {
			bodies := bodiesOf(snap)
			v, err := r.safeParse(bodies)
			if err == nil && r.ds.Count(v) >= r.ds.MinEntries {
				if err = r.ds.Apply(v); err == nil {
					n := r.ds.Count(v)
					r.cur.Store(&live[T]{val: v, count: n, source: SourcePersisted})
					r.snap = snap
					r.report(n, snap.Updated)
					r.opts.Log.Info("refdata: loaded persisted copy", "dataset", r.ds.Name, "entries", n, "updated", snap.Updated)
					return nil
				}
			}
			r.opts.Log.Warn("refdata: persisted copy unusable, using embedded", "dataset", r.ds.Name, "err", err)
		}
	}
	v, err := r.ds.Embedded()
	if err != nil {
		return fmt.Errorf("refdata: %s: embedded fallback: %w", r.ds.Name, err)
	}
	if err := r.ds.Apply(v); err != nil {
		return fmt.Errorf("refdata: %s: apply embedded: %w", r.ds.Name, err)
	}
	n := r.ds.Count(v)
	r.cur.Store(&live[T]{val: v, count: n, source: SourceEmbedded})
	r.snap = snapshot{}
	// Age is measured from process start for embedded data, so an instance
	// that never manages to refresh trips the staleness alert.
	r.report(n, r.opts.Now())
	return nil
}

func bodiesOf(s snapshot) map[string][]byte {
	m := make(map[string][]byte, len(s.Sources))
	for u, st := range s.Sources {
		m[u] = st.Body
	}
	return m
}

func (r *Runner[T]) loadPersisted(p string) (snapshot, bool) {
	b, err := os.ReadFile(p) // #nosec G304 -- operator-configured refdata dir plus a validated dataset name
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			r.opts.Log.Warn("refdata: read persisted copy", "dataset", r.ds.Name, "err", err)
		}
		return snapshot{}, false
	}
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil || len(s.Sources) == 0 {
		r.opts.Log.Warn("refdata: persisted copy corrupt", "dataset", r.ds.Name, "err", err)
		return snapshot{}, false
	}
	return s, true
}

func (r *Runner[T]) persist(s snapshot) error {
	p := r.path()
	if p == "" {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "."+r.ds.Name+"-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	// #nosec G302 -- group-readable reference data, no secrets
	if err := os.Chmod(name, 0o640); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, p); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// Refresh downloads the sources and, if they pass validation, applies and
// persists them. It never replaces live data with anything that fails.
func (r *Runner[T]) Refresh(ctx context.Context) Result {
	res := r.refresh(ctx)
	if r.opts.Rec != nil {
		r.opts.Rec.ObserveRefdata(r.ds.Name, res.Outcome)
	}
	lv := []any{"dataset", r.ds.Name, "outcome", res.Outcome, "entries", res.Entries}
	switch res.Outcome {
	case OutcomeOK, OutcomeUnchanged:
		r.opts.Log.Info("refdata refreshed", lv...)
	default:
		r.opts.Log.Warn("refdata refresh failed", append(lv, "err", res.Err)...)
	}
	return res
}

func (r *Runner[T]) refresh(ctx context.Context) Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.cur.Load()
	if cur == nil {
		return Result{Dataset: r.ds.Name, Outcome: OutcomeError, Err: errors.New("refdata: not initialised")}
	}
	fail := func(outcome string, err error) Result {
		return Result{Dataset: r.ds.Name, Outcome: outcome, Entries: cur.count, Err: err}
	}

	next := snapshot{Sources: map[string]sourceState{}}
	var changed bool
	var errs []error
	for _, u := range r.ds.URLs {
		old, have := r.snap.Sources[u]
		v := Validators{}
		if have && len(old.Body) > 0 {
			v = old.Validators
		}
		got, err := r.opts.Fetcher.Get(ctx, u, v)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", redact(u), err))
			if have {
				next.Sources[u] = old // keep the last good copy of this source
			}
		case got.NotModified:
			next.Sources[u] = old
		default:
			if have && bytes.Equal(old.Body, got.Body) {
				next.Sources[u] = sourceState{Validators: got.Validators, Body: old.Body}
				continue
			}
			next.Sources[u] = sourceState{Validators: got.Validators, Body: got.Body}
			changed = true
		}
	}
	if len(next.Sources) == 0 {
		return fail(OutcomeError, errors.Join(errs...))
	}
	if !changed {
		if len(errs) > 0 {
			return fail(OutcomeError, errors.Join(errs...))
		}
		r.report(cur.count, r.opts.Now())
		return Result{Dataset: r.ds.Name, Outcome: OutcomeUnchanged, Entries: cur.count}
	}

	v, err := r.safeParse(bodiesOf(next))
	if err != nil {
		return fail(OutcomeRejected, fmt.Errorf("parse: %w", err))
	}
	n := r.ds.Count(v)
	if n < r.ds.MinEntries {
		return fail(OutcomeRejected, fmt.Errorf("only %d entries, need at least %d", n, r.ds.MinEntries))
	}
	if cur.count > 0 && float64(n) < float64(cur.count)*(1-r.ds.MaxShrink) {
		return fail(OutcomeRejected, fmt.Errorf("shrink guard: %d entries vs %d applied (more than %.0f%% smaller)", n, cur.count, r.ds.MaxShrink*100))
	}
	if err := r.ds.Apply(v); err != nil {
		return fail(OutcomeError, fmt.Errorf("apply: %w", err))
	}
	now := r.opts.Now()
	next.Updated = now
	r.cur.Store(&live[T]{val: v, count: n, source: SourceRefreshed})
	r.snap = next
	r.report(n, now)
	if err := r.persist(next); err != nil {
		r.opts.Log.Warn("refdata: persist failed (data is applied in memory)", "dataset", r.ds.Name, "err", err)
	}
	if len(errs) > 0 {
		r.opts.Log.Warn("refdata: some sources failed; used their last good copy where available", "dataset", r.ds.Name, "err", errors.Join(errs...))
	}
	return Result{Dataset: r.ds.Name, Outcome: OutcomeOK, Entries: n}
}

// Manager drives a set of datasets together.
type Manager struct {
	us []Updater
}

// NewManager groups updaters.
func NewManager(us ...Updater) *Manager { return &Manager{us: us} }

// Names lists the managed datasets.
func (m *Manager) Names() []string {
	out := make([]string, 0, len(m.us))
	for _, u := range m.us {
		out = append(out, u.Name())
	}
	sort.Strings(out)
	return out
}

// Init installs offline data for every dataset (persisted, else embedded).
func (m *Manager) Init() error {
	var errs []error
	for _, u := range m.us {
		if err := u.Init(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RefreshAll refreshes every dataset. The returned error joins only the
// transient failures (outcome "error"): a rejected download is a verdict on
// the data, not something a retry fixes.
func (m *Manager) RefreshAll(ctx context.Context) ([]Result, error) {
	var out []Result
	var errs []error
	for _, u := range m.us {
		r := u.Refresh(ctx)
		out = append(out, r)
		if r.Outcome == OutcomeError {
			errs = append(errs, fmt.Errorf("%s: %w", r.Dataset, r.Err))
		}
	}
	return out, errors.Join(errs...)
}
