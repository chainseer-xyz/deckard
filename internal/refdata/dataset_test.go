package refdata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lines is the toy dataset: one entry per non-empty line, merged with a
// two-entry embedded fallback.
var embeddedLines = []string{"emb1", "emb2"}

func parseLines(bodies map[string][]byte) ([]string, error) {
	out := append([]string(nil), embeddedLines...)
	for _, b := range bodies {
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			if strings.ContainsAny(l, "{}<") {
				return nil, fmt.Errorf("garbage line %q", l)
			}
			out = append(out, l)
		}
	}
	return out, nil
}

type fakeRec struct {
	mu      sync.Mutex
	results []string
	entries map[string]int
	updated map[string]time.Time
}

func (f *fakeRec) ObserveRefdata(d, r string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, d+":"+r)
}
func (f *fakeRec) SetRefdataState(d string, n int, t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.entries == nil {
		f.entries, f.updated = map[string]int{}, map[string]time.Time{}
	}
	f.entries[d], f.updated[d] = n, t
}

type harness struct {
	srv     *httptest.Server
	body    atomic.Value // string
	etag    atomic.Value // string
	hits    atomic.Int32
	dir     string
	rec     *fakeRec
	applied atomic.Value
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{dir: t.TempDir(), rec: &fakeRec{}}
	h.body.Store("a\nb\nc\nd\n")
	h.etag.Store(`"e1"`)
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		et := h.etag.Load().(string)
		if et != "" && r.Header.Get("If-None-Match") == et {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if et != "" {
			w.Header().Set("ETag", et)
		}
		_, _ = io.WriteString(w, h.body.Load().(string))
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) runner(t *testing.T, mod func(*Dataset[[]string])) *Runner[[]string] {
	t.Helper()
	ds := Dataset[[]string]{
		Name: "toy", URLs: []string{h.srv.URL}, Parse: parseLines,
		Count:      func(v []string) int { return len(v) },
		Apply:      func(v []string) error { h.applied.Store(v); return nil },
		Embedded:   func() ([]string, error) { return embeddedLines, nil },
		MinEntries: 3,
	}
	if mod != nil {
		mod(&ds)
	}
	r, err := NewRunner(ds, Options{
		Dir: h.dir, Rec: h.rec, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Fetcher: &Fetcher{Client: h.srv.Client(), Backoff: time.Millisecond, Attempts: 2, MaxBytes: 1 << 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Init(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestInitUsesEmbeddedWhenNothingPersisted(t *testing.T) {
	h := newHarness(t)
	r := h.runner(t, nil)
	v, ok := r.Value()
	if !ok || len(v) != 2 || r.Source() != SourceEmbedded {
		t.Fatalf("v=%v src=%s", v, r.Source())
	}
	if h.rec.entries["toy"] != 2 {
		t.Errorf("entries metric = %d", h.rec.entries["toy"])
	}
}

func TestRefreshAppliesPersistsAndReloadsOnRestart(t *testing.T) {
	h := newHarness(t)
	r := h.runner(t, nil)
	res := r.Refresh(context.Background())
	if res.Outcome != OutcomeOK || res.Entries != 6 {
		t.Fatalf("res=%+v", res)
	}
	if v, _ := r.Value(); len(v) != 6 || r.Source() != SourceRefreshed {
		t.Fatalf("live=%v", v)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "toy.json")); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(h.dir, "*.tmp")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}

	// "Restart" with the network gone: persisted data is live BEFORE any refresh.
	h.srv.Close()
	r2 := h.runner(t, nil)
	if v, _ := r2.Value(); len(v) != 6 || r2.Source() != SourcePersisted {
		t.Fatalf("after restart v=%v src=%s", v, r2.Source())
	}
	if a := h.applied.Load().([]string); len(a) != 6 {
		t.Errorf("persisted copy not applied to consumers: %v", a)
	}
	// Offline refresh fails and keeps the persisted data.
	res = r2.Refresh(context.Background())
	if res.Outcome != OutcomeError {
		t.Fatalf("offline refresh outcome=%s", res.Outcome)
	}
	if v, _ := r2.Value(); len(v) != 6 {
		t.Errorf("data lost after failed refresh")
	}
}

func TestRefreshETagUnchangedAfterRestart(t *testing.T) {
	h := newHarness(t)
	r := h.runner(t, nil)
	r.Refresh(context.Background())
	r2 := h.runner(t, nil) // restart: validators come from disk
	res := r2.Refresh(context.Background())
	if res.Outcome != OutcomeUnchanged {
		t.Fatalf("res=%+v", res)
	}
	if h.rec.results[len(h.rec.results)-1] != "toy:unchanged" {
		t.Errorf("results=%v", h.rec.results)
	}
}

func TestRefreshNewContentAfterETagChange(t *testing.T) {
	h := newHarness(t)
	r := h.runner(t, nil)
	r.Refresh(context.Background())
	h.body.Store("a\nb\nc\nd\ne\n")
	h.etag.Store(`"e2"`)
	res := r.Refresh(context.Background())
	if res.Outcome != OutcomeOK || res.Entries != 7 {
		t.Fatalf("res=%+v", res)
	}
}

func TestRefreshSameBodyWithoutETagIsUnchanged(t *testing.T) {
	h := newHarness(t)
	h.etag.Store("")
	r := h.runner(t, nil)
	r.Refresh(context.Background())
	if res := r.Refresh(context.Background()); res.Outcome != OutcomeUnchanged {
		t.Fatalf("res=%+v", res)
	}
}

func TestRefreshRejections(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"invalid":     {"{\"not\": \"lines\"}\n", "garbage"},
		"empty":       {"", "need at least"},
		"binary junk": {"\x00\x01<html>", "garbage"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			r := h.runner(t, nil)
			r.Refresh(context.Background()) // 6 good entries
			h.body.Store(tc.body)
			h.etag.Store(`"bad"`)
			res := r.Refresh(context.Background())
			if res.Outcome != OutcomeRejected || res.Err == nil || !strings.Contains(res.Err.Error(), tc.want) {
				t.Fatalf("res=%+v", res)
			}
			if v, _ := r.Value(); len(v) != 6 {
				t.Errorf("live data replaced by rejected download: %v", v)
			}
			// Persisted copy must still be the good one.
			if v, _ := h.runner(t, nil).Value(); len(v) != 6 {
				t.Errorf("persisted copy poisoned: %v", v)
			}
		})
	}
}

func TestShrinkGuard(t *testing.T) {
	h := newHarness(t)
	h.body.Store(strings.Repeat("x\n", 1) + "a\nb\nc\nd\ne\nf\ng\nh\n") // 9 + 2 embedded = 11
	r := h.runner(t, nil)
	if res := r.Refresh(context.Background()); res.Outcome != OutcomeOK || res.Entries != 11 {
		t.Fatalf("res=%+v", res)
	}
	h.etag.Store(`"trunc"`)
	h.body.Store("a\nb\nc\n") // 5 < 11*0.5
	res := r.Refresh(context.Background())
	if res.Outcome != OutcomeRejected || !strings.Contains(res.Err.Error(), "shrink") {
		t.Fatalf("res=%+v", res)
	}
	// Exactly 50% is allowed ("more than 50%" is rejected).
	h.etag.Store(`"half"`)
	h.body.Store("a\nb\nc\nd\n") // 6 entries; 6 >= 5.5
	if res := r.Refresh(context.Background()); res.Outcome != OutcomeOK {
		t.Fatalf("res=%+v", res)
	}
}

func TestOversizedBodyIsAnErrorNotApplied(t *testing.T) {
	h := newHarness(t)
	r := h.runner(t, nil)
	h.etag.Store(`"big"`)
	h.body.Store(strings.Repeat("a\n", 2000)) // > 1 KiB cap in the harness
	res := r.Refresh(context.Background())
	if res.Outcome != OutcomeError || !errors.Is(res.Err, ErrTooLarge) {
		t.Fatalf("res=%+v", res)
	}
	if v, _ := r.Value(); len(v) != 2 {
		t.Errorf("live=%v", v)
	}
}

func TestRedirectToHTTPNeverApplied(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "a\nb\nc\nd\n") }))
	defer plain.Close()
	h := newHarness(t)
	h.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, plain.URL, 302) })
	r := h.runner(t, nil)
	res := r.Refresh(context.Background())
	if res.Outcome != OutcomeError || !errors.Is(res.Err, ErrNotHTTPS) {
		t.Fatalf("res=%+v", res)
	}
}

func TestCorruptPersistedFileFallsBackToEmbedded(t *testing.T) {
	h := newHarness(t)
	for _, content := range []string{"not json", `{"updated":"2020-01-01T00:00:00Z","sources":{}}`, `{"sources":{"u":{"body":"e3t9"}}}`} {
		if err := os.WriteFile(filepath.Join(h.dir, "toy.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		r := h.runner(t, nil)
		if v, _ := r.Value(); len(v) != 2 || r.Source() != SourceEmbedded {
			t.Errorf("content %q: v=%v src=%s", content, v, r.Source())
		}
	}
}

func TestPartialSourceFailureKeepsLastGoodCopy(t *testing.T) {
	var failB atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "a1\na2\n") })
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		if failB.Load() {
			http.Error(w, "x", 500)
			return
		}
		_, _ = io.WriteString(w, "b1\nb2\n")
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	h := &harness{dir: t.TempDir(), rec: &fakeRec{}, srv: srv}
	r := h.runner(t, func(d *Dataset[[]string]) { d.URLs = []string{srv.URL + "/a", srv.URL + "/b"} })
	if res := r.Refresh(context.Background()); res.Outcome != OutcomeOK || res.Entries != 6 {
		t.Fatalf("res=%+v", res)
	}
	failB.Store(true)
	if res := r.Refresh(context.Background()); res.Outcome == OutcomeOK {
		t.Fatalf("nothing changed, must not report ok: %+v", res)
	}
	if v, _ := r.Value(); len(v) != 6 {
		t.Errorf("live=%v", v)
	}
}

func TestParserPanicIsRejected(t *testing.T) {
	h := newHarness(t)
	r := h.runner(t, func(d *Dataset[[]string]) {
		d.Parse = func(map[string][]byte) ([]string, error) { panic("boom") }
	})
	res := r.Refresh(context.Background())
	if res.Outcome != OutcomeRejected || !strings.Contains(res.Err.Error(), "panic") {
		t.Fatalf("res=%+v", res)
	}
}

func TestApplyErrorKeepsOldAndDoesNotPersist(t *testing.T) {
	h := newHarness(t)
	var n atomic.Int32
	r := h.runner(t, func(d *Dataset[[]string]) {
		d.Apply = func([]string) error {
			if n.Add(1) > 1 { // first call is Init's embedded apply
				return errors.New("apply failed")
			}
			return nil
		}
	})
	res := r.Refresh(context.Background())
	if res.Outcome != OutcomeError {
		t.Fatalf("res=%+v", res)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "toy.json")); !os.IsNotExist(err) {
		t.Errorf("must not persist unapplied data: %v", err)
	}
}

func TestNoPersistenceWithoutDir(t *testing.T) {
	h := newHarness(t)
	h.dir = ""
	r := h.runner(t, nil)
	if res := r.Refresh(context.Background()); res.Outcome != OutcomeOK {
		t.Fatalf("res=%+v", res)
	}
}

func TestConcurrentRefreshAndRead(t *testing.T) {
	h := newHarness(t)
	r := h.runner(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); r.Refresh(context.Background()) }()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if v, ok := r.Value(); !ok || len(v) < 2 {
					t.Error("bad read")
				}
			}
		}()
	}
	wg.Wait()
}

func TestNewRunnerValidation(t *testing.T) {
	ok := Dataset[int]{Name: "x", Parse: func(map[string][]byte) (int, error) { return 0, nil },
		Count: func(int) int { return 0 }, Apply: func(int) error { return nil }, Embedded: func() (int, error) { return 0, nil }}
	for name, mut := range map[string]func(*Dataset[int]){
		"bad name":   func(d *Dataset[int]) { d.Name = "../etc" },
		"empty":      func(d *Dataset[int]) { d.Name = "" },
		"no parse":   func(d *Dataset[int]) { d.Parse = nil },
		"no embed":   func(d *Dataset[int]) { d.Embedded = nil },
		"bad shrink": func(d *Dataset[int]) { d.MaxShrink = 1 },
	} {
		d := ok
		mut(&d)
		if _, err := NewRunner(d, Options{}); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := NewRunner(ok, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshBeforeInitErrors(t *testing.T) {
	r, _ := NewRunner(Dataset[int]{Name: "x", Parse: func(map[string][]byte) (int, error) { return 0, nil },
		Count: func(int) int { return 0 }, Apply: func(int) error { return nil }, Embedded: func() (int, error) { return 0, nil }}, Options{})
	if res := r.Refresh(context.Background()); res.Outcome != OutcomeError {
		t.Fatalf("%+v", res)
	}
}

func TestManager(t *testing.T) {
	h := newHarness(t)
	good := h.runner(t, nil)
	bad := h.runner(t, func(d *Dataset[[]string]) { d.Name = "bad"; d.URLs = []string{"http://insecure.invalid/x"} })
	m := NewManager(good, bad)
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	res, err := m.RefreshAll(context.Background())
	if len(res) != 2 || err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got := strings.Join(m.Names(), ","); got != "bad,toy" {
		t.Errorf("names=%s", got)
	}
}

// Fuzz-ish: arbitrary bytes must never panic the pipeline or replace good data.
func TestGarbageBodiesNeverPanic(t *testing.T) {
	garbage := []string{"", "\x00", "{", "[", "null", "[[[[", "\xff\xfe\xfd", strings.Repeat("{", 500), "<?xml?>", "a\x00b\nc", "\n\n\n"}
	for _, g := range garbage {
		h := newHarness(t)
		h.body.Store(g)
		r := h.runner(t, nil)
		res := r.Refresh(context.Background())
		if res.Outcome == OutcomeError && !errors.Is(res.Err, ErrTooLarge) && res.Err == nil {
			t.Errorf("garbage %q: %+v", g, res)
		}
		if v, ok := r.Value(); !ok || len(v) < 2 {
			t.Errorf("garbage %q lost data", g)
		}
	}
}
