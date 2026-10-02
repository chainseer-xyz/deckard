package vulnintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultEPSSTTL   = 24 * time.Hour
	maxPendingEPSS   = 5000
	epssPruneFactor  = 7 // drop cache entries older than 7*TTL when persisting
	kevFileName      = "kev.json"
	kevMetaFileName  = "kev.meta.json"
	epssFileName     = "epss.json"
	persistFileMode  = 0o600
	persistDirMode   = 0o750
	maxPersistedEPSS = 20 << 20
)

// Options configures a Service. The zero value is usable: feeds default to
// cisa.gov and api.first.org, nothing is persisted (empty Dir).
type Options struct {
	Dir        string // persistence directory; "" disables persistence
	KEVURL     string
	EPSSURL    string
	HTTPClient *http.Client
	UserAgent  string
	EPSSTTL    time.Duration // default 24h; also the negative-cache TTL
	Now        func() time.Time
	Logger     *slog.Logger
	// KEVOptions / EPSSOptions further tune the clients (retry, size cap,
	// batch gap); mostly for tests.
	KEVOptions  []ClientOption
	EPSSOptions []ClientOption
}

// Delta describes what a Refresh changed.
type Delta struct {
	// NewKEV lists CVE ids newly added to KEV since the last good copy,
	// sorted. It is empty on the very first load (no previous copy), so a
	// fresh deployment does not fire a storm.
	NewKEV      []string
	Entries     int  // catalog size after the refresh
	NotModified bool // server answered 304; the copy is unchanged
	FirstLoad   bool // there was no previous copy
}

// Status is a point-in-time summary for metrics.
type Status struct {
	KEVEntries    int
	KEVFetchedAt  time.Time // last successful check of the KEV feed (zero = never)
	EPSSEntries   int
	EPSSFetchedAt time.Time // last successful EPSS fetch (zero = never)
}

type kevSnapshot struct {
	byCVE     map[string]KEVEntry
	etag      string
	lastMod   string
	fetchedAt time.Time
}

type kevMeta struct {
	ETag         string    `json:"etag"`
	LastModified string    `json:"last_modified"`
	FetchedAt    time.Time `json:"fetched_at"`
}

type epssEntry struct {
	Score      float64   `json:"s"`
	Percentile float64   `json:"p"`
	Unknown    bool      `json:"u,omitempty"`
	At         time.Time `json:"at"`
}

type epssFile struct {
	FetchedAt time.Time            `json:"fetched_at"`
	Entries   map[string]epssEntry `json:"entries"`
}

// Service holds the KEV and EPSS snapshots. Lookups are lock-light, never
// block on the network and are safe for concurrent use.
type Service struct {
	opts Options
	log  *slog.Logger
	now  func() time.Time
	ttl  time.Duration
	kc   *KEVClient
	ec   *EPSSClient

	kev atomic.Pointer[kevSnapshot]

	refreshMu sync.Mutex // serialises Refresh/RefreshEPSS

	mu            sync.RWMutex
	epss          map[string]epssEntry
	epssFetchedAt time.Time
	pending       map[string]struct{}
}

var _ Intel = (*Service)(nil)

// NewService builds a Service and reloads any persisted last-good copies.
// Unreadable or invalid persisted files are ignored (and logged): the service
// then simply starts empty.
func NewService(o Options) (*Service, error) {
	s := &Service{opts: o, log: o.Logger, now: o.Now, ttl: o.EPSSTTL,
		epss: map[string]epssEntry{}, pending: map[string]struct{}{}}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.ttl <= 0 {
		s.ttl = defaultEPSSTTL
	}
	common := []ClientOption{}
	if o.HTTPClient != nil {
		common = append(common, WithHTTPClient(o.HTTPClient))
	}
	if o.UserAgent != "" {
		common = append(common, WithUserAgent(o.UserAgent))
	}
	var err error
	if s.kc, err = NewKEVClient(o.KEVURL, append(common, o.KEVOptions...)...); err != nil {
		return nil, err
	}
	if s.ec, err = NewEPSSClient(o.EPSSURL, append(common, o.EPSSOptions...)...); err != nil {
		return nil, err
	}
	s.load()
	return s, nil
}

// KEV reports whether cve is in the loaded catalog. Never blocks.
func (s *Service) KEV(cve string) (KEVEntry, bool) {
	snap := s.kev.Load()
	if snap == nil {
		return KEVEntry{}, false
	}
	e, ok := snap.byCVE[strings.ToUpper(strings.TrimSpace(cve))]
	return e, ok
}

// EPSS returns the cached score for cve. It never blocks on the network: a CVE
// that has never been looked up is remembered and fetched by the next
// RefreshEPSS. Stale (past TTL) entries are still served until refreshed;
// CVEs EPSS does not know return ok=false.
func (s *Service) EPSS(cve string) (score, percentile float64, ok bool) {
	id, valid := NormalizeCVE(cve)
	if !valid {
		return 0, 0, false
	}
	s.mu.RLock()
	e, found := s.epss[id]
	s.mu.RUnlock()
	if found {
		if e.Unknown {
			return 0, 0, false
		}
		return e.Score, e.Percentile, true
	}
	s.mu.Lock()
	if len(s.pending) < maxPendingEPSS {
		s.pending[id] = struct{}{}
	}
	s.mu.Unlock()
	return 0, 0, false
}

// Status summarises the snapshots for metrics.
func (s *Service) Status() Status {
	var st Status
	if k := s.kev.Load(); k != nil {
		st.KEVEntries, st.KEVFetchedAt = len(k.byCVE), k.fetchedAt
	}
	s.mu.RLock()
	st.EPSSEntries, st.EPSSFetchedAt = len(s.epss), s.epssFetchedAt
	s.mu.RUnlock()
	return st
}

// Refresh downloads the KEV catalog (conditional GET), validates it against
// the last good copy, atomically swaps and persists it, and reports the CVEs
// newly added to KEV. On any failure the previous copy keeps being served and
// the error is returned.
func (s *Service) Refresh(ctx context.Context) (Delta, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	prev := s.kev.Load()
	var etag, lastMod string
	if prev != nil {
		etag, lastMod = prev.etag, prev.lastMod
	}
	res, err := s.kc.Fetch(ctx, etag, lastMod)
	if err != nil {
		return Delta{}, err
	}
	now := s.now()
	if res.NotModified && prev != nil {
		next := *prev
		next.fetchedAt = now
		s.kev.Store(&next)
		s.persistKEVMeta(&next)
		return Delta{Entries: len(prev.byCVE), NotModified: true}, nil
	}
	if res.NotModified { // 304 with nothing loaded cannot happen on a sane server
		return Delta{}, errors.New("kev: unexpected 304 with no local copy")
	}
	prevCount := 0
	if prev != nil {
		prevCount = len(prev.byCVE)
	}
	if err := ValidateShrink(prevCount, len(res.Entries)); err != nil {
		return Delta{}, err
	}
	next := &kevSnapshot{byCVE: make(map[string]KEVEntry, len(res.Entries)), etag: res.ETag, lastMod: res.LastModified, fetchedAt: now}
	var added []string
	for _, e := range res.Entries {
		next.byCVE[e.CVE] = e
		if prev != nil {
			if _, had := prev.byCVE[e.CVE]; !had {
				added = append(added, e.CVE)
			}
		}
	}
	sort.Strings(added)
	s.kev.Store(next)
	if err := s.persistKEV(res.Body, next); err != nil {
		s.log.Warn("vulnintel: persisting KEV copy failed (in-memory copy is active)", "err", err)
	}
	return Delta{NewKEV: added, Entries: len(next.byCVE), FirstLoad: prev == nil}, nil
}

// RefreshEPSS fetches scores for cves (plus any CVEs previously looked up and
// missed) that are not cached or whose cache entry is past its TTL, in batches
// of at most 100. CVEs the API does not know are negatively cached for the
// same TTL. It returns how many CVEs were answered. Failed batches leave their
// CVEs uncached so they are retried next time.
func (s *Service) RefreshEPSS(ctx context.Context, cves []string) (int, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	now := s.now()
	want := map[string]struct{}{}
	s.mu.Lock()
	for id := range s.pending {
		want[id] = struct{}{}
	}
	for _, c := range cves {
		if id, ok := NormalizeCVE(c); ok {
			want[id] = struct{}{}
		}
	}
	var due []string
	for id := range want {
		if e, ok := s.epss[id]; ok && now.Sub(e.At) < s.ttl {
			delete(s.pending, id)
			continue
		}
		due = append(due, id)
	}
	s.mu.Unlock()
	if len(due) == 0 {
		return 0, nil
	}
	sort.Strings(due)

	scores, answered, err := s.ec.Lookup(ctx, due)
	if len(answered) > 0 {
		s.mu.Lock()
		for _, id := range answered {
			if sc, ok := scores[id]; ok {
				s.epss[id] = epssEntry{Score: sc.Score, Percentile: sc.Percentile, At: now}
			} else {
				s.epss[id] = epssEntry{Unknown: true, At: now}
			}
			delete(s.pending, id)
		}
		s.epssFetchedAt = now
		s.mu.Unlock()
		if perr := s.persistEPSS(now); perr != nil {
			s.log.Warn("vulnintel: persisting EPSS cache failed", "err", perr)
		}
	}
	return len(answered), err
}

// ---- persistence ----------------------------------------------------------

func (s *Service) persistKEV(body []byte, snap *kevSnapshot) error {
	if s.opts.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(s.opts.Dir, persistDirMode); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(s.opts.Dir, kevFileName), body); err != nil {
		return err
	}
	return s.writeKEVMeta(snap)
}

func (s *Service) persistKEVMeta(snap *kevSnapshot) {
	if s.opts.Dir == "" {
		return
	}
	if err := s.writeKEVMeta(snap); err != nil {
		s.log.Warn("vulnintel: persisting KEV metadata failed", "err", err)
	}
}

func (s *Service) writeKEVMeta(snap *kevSnapshot) error {
	b, err := json.Marshal(kevMeta{ETag: snap.etag, LastModified: snap.lastMod, FetchedAt: snap.fetchedAt})
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.opts.Dir, kevMetaFileName), b)
}

func (s *Service) persistEPSS(now time.Time) error {
	if s.opts.Dir == "" {
		return nil
	}
	s.mu.Lock()
	for id, e := range s.epss { // bound the cache
		if now.Sub(e.At) > epssPruneFactor*s.ttl {
			delete(s.epss, id)
		}
	}
	f := epssFile{FetchedAt: s.epssFetchedAt, Entries: make(map[string]epssEntry, len(s.epss))}
	for k, v := range s.epss {
		f.Entries[k] = v
	}
	s.mu.Unlock()
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.opts.Dir, persistDirMode); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.opts.Dir, epssFileName), b)
}

// load restores persisted copies; any problem leaves that feed empty.
func (s *Service) load() {
	dir := s.opts.Dir
	if dir == "" {
		return
	}
	if body, err := readCapped(filepath.Join(dir, kevFileName), defaultKEVMaxBytes); err == nil {
		entries, perr := ParseKEV(body)
		if perr != nil {
			s.log.Warn("vulnintel: ignoring invalid persisted KEV copy", "err", perr)
		} else {
			snap := &kevSnapshot{byCVE: make(map[string]KEVEntry, len(entries))}
			for _, e := range entries {
				snap.byCVE[e.CVE] = e
			}
			if mb, merr := readCapped(filepath.Join(dir, kevMetaFileName), 1<<16); merr == nil {
				var m kevMeta
				if json.Unmarshal(mb, &m) == nil {
					snap.etag, snap.lastMod, snap.fetchedAt = m.ETag, m.LastModified, m.FetchedAt
				}
			}
			s.kev.Store(snap)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("vulnintel: cannot read persisted KEV copy", "err", err)
	}
	if b, err := readCapped(filepath.Join(dir, epssFileName), maxPersistedEPSS); err == nil {
		var f epssFile
		if jerr := json.Unmarshal(b, &f); jerr != nil {
			s.log.Warn("vulnintel: ignoring invalid persisted EPSS cache", "err", jerr)
		} else if f.Entries != nil {
			for k, v := range f.Entries {
				if _, ok := NormalizeCVE(k); ok && v.Score >= 0 && v.Score <= 1 && v.Percentile >= 0 && v.Percentile <= 1 {
					s.epss[k] = v
				}
			}
			s.epssFetchedAt = f.FetchedAt
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("vulnintel: cannot read persisted EPSS cache", "err", err)
	}
}

func readCapped(path string, max int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, max)
	}
	return os.ReadFile(path) // #nosec G304 -- path is built from the operator-configured vulnintel.dir
}

// atomicWrite writes data to path via a synced temp file and rename, so a
// crash never leaves a torn file.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(name, persistFileMode); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
