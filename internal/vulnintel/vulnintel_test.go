package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// kevBody builds a catalog with the given ids (count matches).
func kevBody(ids ...string) []byte {
	type v struct {
		CVEID string `json:"cveID"`
		Added string `json:"dateAdded"`
	}
	vs := make([]v, 0, len(ids))
	for _, id := range ids {
		vs = append(vs, v{id, "2025-02-02"})
	}
	b, _ := json.Marshal(map[string]any{"count": len(vs), "vulnerabilities": vs})
	return b
}

func manyIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("CVE-2024-%05d", i+1)
	}
	return out
}

var noSleep = func(context.Context, time.Duration) error { return nil }

func fastOpts() []ClientOption {
	return []ClientOption{WithRetry(3, time.Millisecond, noSleep), WithMinGap(0)}
}

func TestParseKEV(t *testing.T) {
	es, err := ParseKEV(fixture(t, "kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 4 || es[0].CVE != "CVE-2017-5638" {
		t.Fatalf("entries = %+v", es)
	}
	var log4j KEVEntry
	for _, e := range es {
		if e.CVE == "CVE-2021-44228" {
			log4j = e
		}
	}
	if log4j.DateAdded != "2021-12-10" || !log4j.Ransomware || log4j.Product != "Log4j2" || log4j.DueDate != "2021-12-24" || log4j.RequiredAction == "" || log4j.VendorProject != "Apache" {
		t.Fatalf("log4j = %+v", log4j)
	}
	if es[0].Ransomware {
		t.Error("Unknown ransomware use parsed as true")
	}
}

func TestParseKEVRejects(t *testing.T) {
	cases := map[string]string{
		"invalid json":   `{"vulnerabilities": [`,
		"empty":          `{"vulnerabilities": []}`,
		"count mismatch": `{"count": 5, "vulnerabilities": [{"cveID":"CVE-2020-0001"}]}`,
		"all malformed":  `{"vulnerabilities": [{"cveID":"nope"},{"cveID":""}]}`,
	}
	for name, body := range cases {
		if _, err := ParseKEV([]byte(body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestExtractAndNormalizeCVE(t *testing.T) {
	got := ExtractCVEs("see cve-2021-44228, CVE-2023-34362 and cve-2021-44228; not CVE-21-1")
	if strings.Join(got, ",") != "CVE-2021-44228,CVE-2023-34362" {
		t.Fatalf("got %v", got)
	}
	if id, ok := NormalizeCVE(" cve-2020-0001 "); !ok || id != "CVE-2020-0001" {
		t.Fatal("normalize")
	}
	if _, ok := NormalizeCVE("CVE-2020-1"); ok {
		t.Fatal("short sequence accepted")
	}
}

func TestKEVClientRefusesPlainHTTP(t *testing.T) {
	if _, err := NewKEVClient("http://example.com/kev.json"); err == nil {
		t.Fatal("http accepted")
	}
	if _, err := NewEPSSClient("http://example.com/epss"); err == nil {
		t.Fatal("http accepted")
	}
}

func TestKEVClientFetchConditionalAndHeaders(t *testing.T) {
	body := fixture(t, "kev.json")
	var ua atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.Header.Get("User-Agent"))
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Wed, 01 Jan 2025 12:00:00 GMT")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c, err := NewKEVClient(srv.URL, append(fastOpts(), WithHTTPClient(srv.Client()))...)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := c.Fetch(context.Background(), "", "")
	if err != nil || r1.NotModified || len(r1.Entries) != 4 || r1.ETag != `"v1"` || r1.LastModified == "" {
		t.Fatalf("first fetch %+v %v", r1, err)
	}
	if !strings.Contains(ua.Load().(string), "deckard") {
		t.Errorf("user agent = %q", ua.Load())
	}
	r2, err := c.Fetch(context.Background(), r1.ETag, r1.LastModified)
	if err != nil || !r2.NotModified {
		t.Fatalf("second fetch %+v %v", r2, err)
	}
}

func TestKEVClientOversizedAndRetry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
			return
		}
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(kevBody("CVE-2024-00001"))
	}))
	defer srv.Close()
	opts := append(fastOpts(), WithHTTPClient(srv.Client()), WithMaxBytes(1024))
	big, _ := NewKEVClient(srv.URL+"/big", opts...)
	if _, err := big.Fetch(context.Background(), "", ""); err == nil || !strings.Contains(err.Error(), "size cap") {
		t.Fatalf("oversized err = %v", err)
	}
	c, _ := NewKEVClient(srv.URL+"/ok", opts...)
	r, err := c.Fetch(context.Background(), "", "")
	if err != nil || len(r.Entries) != 1 || hits.Load() != 3 {
		t.Fatalf("retry: %+v %v hits=%d", r, err, hits.Load())
	}
}

func TestKEVClientDoesNotRetry404(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c, _ := NewKEVClient(srv.URL, append(fastOpts(), WithHTTPClient(srv.Client()))...)
	if _, err := c.Fetch(context.Background(), "", ""); err == nil || hits.Load() != 1 {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
}

func TestKEVRefusesRedirectToHTTP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/x", http.StatusFound)
	}))
	defer srv.Close()
	c, _ := NewKEVClient(srv.URL, append(fastOpts(), WithHTTPClient(srv.Client()))...)
	if _, err := c.Fetch(context.Background(), "", ""); err == nil {
		t.Fatal("redirect to http followed")
	}
}

// feed is a mutable fake KEV+EPSS endpoint pair.
type feed struct {
	kev      atomic.Value // []byte
	etag     atomic.Value // string
	fail     atomic.Bool
	kevHits  atomic.Int32
	epssReqs atomic.Int32
	epssSeen atomic.Value // [][]string
	epss     map[string]string
	kevSrv   *httptest.Server
	epssSrv  *httptest.Server
}

func newFeed(t *testing.T, kev []byte) *feed {
	f := &feed{epss: map[string]string{}}
	f.kev.Store(kev)
	f.etag.Store(`"e1"`)
	f.epssSeen.Store([][]string{})
	f.kevSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.kevHits.Add(1)
		if f.fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		et := f.etag.Load().(string)
		if r.Header.Get("If-None-Match") == et {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", et)
		_, _ = w.Write(f.kev.Load().([]byte))
	}))
	f.epssSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.epssReqs.Add(1)
		ids := strings.Split(r.URL.Query().Get("cve"), ",")
		seen := f.epssSeen.Load().([][]string)
		f.epssSeen.Store(append(seen, ids))
		type row struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		}
		var data []row
		for _, id := range ids {
			if s, ok := f.epss[id]; ok {
				data = append(data, row{id, s, "0.5"})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "OK", "status-code": 200, "data": data})
	}))
	t.Cleanup(func() { f.kevSrv.Close(); f.epssSrv.Close() })
	return f
}

func (f *feed) service(t *testing.T, dir string, now func() time.Time) *Service {
	t.Helper()
	s, err := NewService(Options{
		Dir: dir, KEVURL: f.kevSrv.URL, EPSSURL: f.epssSrv.URL, HTTPClient: f.kevSrv.Client(), Now: now,
		KEVOptions: fastOpts(), EPSSOptions: fastOpts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServiceFirstLoadNoDeltaThenDelta(t *testing.T) {
	f := newFeed(t, kevBody("CVE-2024-00001", "CVE-2024-00002"))
	s := f.service(t, t.TempDir(), nil)
	ctx := context.Background()
	if _, ok := s.KEV("CVE-2024-00001"); ok {
		t.Fatal("hit before any load")
	}
	d, err := s.Refresh(ctx)
	if err != nil || len(d.NewKEV) != 0 || !d.FirstLoad || d.Entries != 2 {
		t.Fatalf("first load: %+v %v", d, err)
	}
	if e, ok := s.KEV("cve-2024-00002"); !ok || e.CVE != "CVE-2024-00002" {
		t.Fatalf("lookup (case-insensitive) = %+v %v", e, ok)
	}
	// Unchanged: 304.
	if d, err = s.Refresh(ctx); err != nil || !d.NotModified || len(d.NewKEV) != 0 {
		t.Fatalf("304: %+v %v", d, err)
	}
	// Catalog grows.
	f.kev.Store(kevBody("CVE-2024-00001", "CVE-2024-00002", "CVE-2025-00009", "CVE-2025-00003"))
	f.etag.Store(`"e2"`)
	d, err = s.Refresh(ctx)
	if err != nil || strings.Join(d.NewKEV, ",") != "CVE-2025-00003,CVE-2025-00009" || d.FirstLoad {
		t.Fatalf("delta: %+v %v", d, err)
	}
	// Same content again: no repeat delta.
	f.etag.Store(`"e3"`)
	if d, err = s.Refresh(ctx); err != nil || len(d.NewKEV) != 0 {
		t.Fatalf("repeat: %+v %v", d, err)
	}
}

func TestServiceRejectsShrinkTruncatedInvalidAndKeepsLastGood(t *testing.T) {
	f := newFeed(t, kevBody(manyIDs(10)...))
	s := f.service(t, t.TempDir(), nil)
	ctx := context.Background()
	if _, err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"shrunk":    kevBody(manyIDs(4)...),
		"truncated": kevBody(manyIDs(10)...)[:60],
		"invalid":   []byte("<html>oops</html>"),
		"empty":     kevBody(),
	}
	i := 0
	for name, body := range cases {
		i++
		f.kev.Store(body)
		f.etag.Store(fmt.Sprintf(`"bad%d"`, i))
		if _, err := s.Refresh(ctx); err == nil {
			t.Errorf("%s: want error", name)
		}
		if _, ok := s.KEV("CVE-2024-00001"); !ok || s.Status().KEVEntries != 10 {
			t.Fatalf("%s: last good copy lost", name)
		}
	}
	// Exactly half is allowed.
	f.kev.Store(kevBody(manyIDs(5)...))
	f.etag.Store(`"half"`)
	if _, err := s.Refresh(ctx); err != nil {
		t.Fatalf("50%% shrink should pass: %v", err)
	}
}

func TestServicePersistenceAndReload(t *testing.T) {
	dir := t.TempDir()
	f := newFeed(t, kevBody("CVE-2024-00001"))
	f.epss["CVE-2024-00001"] = "0.9"
	now := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	s := f.service(t, dir, func() time.Time { return now })
	ctx := context.Background()
	if _, err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RefreshEPSS(ctx, []string{"CVE-2024-00001", "CVE-2024-77777"}); err != nil || n != 2 {
		t.Fatalf("epss refresh n=%d err=%v", n, err)
	}
	for _, name := range []string{kevFileName, kevMetaFileName, epssFileName} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}

	// Restart with the feed completely offline: persisted copies serve.
	f.fail.Store(true)
	s2 := f.service(t, dir, func() time.Time { return now })
	if _, ok := s2.KEV("CVE-2024-00001"); !ok {
		t.Fatal("KEV not reloaded")
	}
	if sc, _, ok := s2.EPSS("CVE-2024-00001"); !ok || sc != 0.9 {
		t.Fatalf("EPSS not reloaded: %v %v", sc, ok)
	}
	if st := s2.Status(); st.KEVEntries != 1 || !st.KEVFetchedAt.Equal(now) || !st.EPSSFetchedAt.Equal(now) {
		t.Fatalf("status = %+v", st)
	}
	if _, err := s2.Refresh(ctx); err == nil {
		t.Fatal("offline refresh should error")
	}
	if _, ok := s2.KEV("CVE-2024-00001"); !ok {
		t.Fatal("offline refresh dropped data")
	}
	// After restart the first refresh diffs against the persisted copy.
	f.fail.Store(false)
	f.kev.Store(kevBody("CVE-2024-00001", "CVE-2024-00002"))
	f.etag.Store(`"new"`)
	d, err := s2.Refresh(ctx)
	if err != nil || len(d.NewKEV) != 1 || d.NewKEV[0] != "CVE-2024-00002" {
		t.Fatalf("post-restart delta: %+v %v", d, err)
	}
}

func TestServiceIgnoresCorruptPersistedFiles(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{kevFileName, kevMetaFileName, epssFileName} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("garbage{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := newFeed(t, kevBody("CVE-2024-00001"))
	s := f.service(t, dir, nil)
	if st := s.Status(); st.KEVEntries != 0 || st.EPSSEntries != 0 {
		t.Fatalf("status = %+v", st)
	}
}

func TestOfflineServiceIsNoOp(t *testing.T) {
	s, err := NewService(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.KEV("CVE-2021-44228"); ok {
		t.Error("KEV hit with no data")
	}
	if _, _, ok := s.EPSS("CVE-2021-44228"); ok {
		t.Error("EPSS hit with no data")
	}
	if st := s.Status(); st != (Status{}) {
		t.Errorf("status = %+v", st)
	}
}

func TestEPSSBatchingAndNegativeCaching(t *testing.T) {
	f := newFeed(t, kevBody("CVE-2024-00001"))
	ids := manyIDs(250)
	for _, id := range ids[:200] {
		f.epss[id] = "0.25"
	}
	now := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	cur := now
	s := f.service(t, "", func() time.Time { return cur })
	ctx := context.Background()

	n, err := s.RefreshEPSS(ctx, ids)
	if err != nil || n != 250 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := f.epssReqs.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3 batches", got)
	}
	for _, b := range f.epssSeen.Load().([][]string) {
		if len(b) > 100 {
			t.Fatalf("batch of %d > 100", len(b))
		}
	}
	if sc, pct, ok := s.EPSS(ids[0]); !ok || sc != 0.25 || pct != 0.5 {
		t.Fatalf("score %v %v %v", sc, pct, ok)
	}
	if _, _, ok := s.EPSS(ids[240]); ok {
		t.Fatal("unknown CVE reported as known")
	}
	// Within TTL: nothing refetched, including the negatively cached CVEs.
	if n, err := s.RefreshEPSS(ctx, ids); err != nil || n != 0 || f.epssReqs.Load() != 3 {
		t.Fatalf("within TTL: n=%d err=%v reqs=%d", n, err, f.epssReqs.Load())
	}
	// Past TTL: refetched; stale values were served until then.
	cur = now.Add(25 * time.Hour)
	if _, _, ok := s.EPSS(ids[0]); !ok {
		t.Fatal("stale entry should still be served")
	}
	if n, err := s.RefreshEPSS(ctx, ids[:10]); err != nil || n != 10 || f.epssReqs.Load() != 4 {
		t.Fatalf("after TTL: n=%d err=%v reqs=%d", n, err, f.epssReqs.Load())
	}
}

func TestEPSSLookupIsNonBlockingAndQueuesMisses(t *testing.T) {
	f := newFeed(t, kevBody("CVE-2024-00001"))
	f.epss["CVE-2024-00042"] = "0.8"
	s := f.service(t, "", nil)
	if _, _, ok := s.EPSS("CVE-2024-00042"); ok {
		t.Fatal("miss expected")
	}
	if f.epssReqs.Load() != 0 {
		t.Fatal("lookup hit the network")
	}
	if n, err := s.RefreshEPSS(context.Background(), nil); err != nil || n != 1 {
		t.Fatalf("pending not fetched: n=%d err=%v", n, err)
	}
	if sc, _, ok := s.EPSS("CVE-2024-00042"); !ok || sc != 0.8 {
		t.Fatalf("after refresh: %v %v", sc, ok)
	}
}

func TestEPSSFailedBatchNotNegativelyCached(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(fixture(t, "epss.json"))
	}))
	defer srv.Close()
	s, _ := NewService(Options{EPSSURL: srv.URL, HTTPClient: srv.Client(), EPSSOptions: fastOpts()})
	if n, err := s.RefreshEPSS(context.Background(), []string{"CVE-2021-44228"}); err == nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	fail.Store(false)
	if n, err := s.RefreshEPSS(context.Background(), []string{"CVE-2021-44228"}); err != nil || n != 1 {
		t.Fatalf("retry n=%d err=%v", n, err)
	}
	if sc, pct, ok := s.EPSS("CVE-2021-44228"); !ok || sc < 0.94 || pct < 0.99 {
		t.Fatalf("%v %v %v", sc, pct, ok)
	}
}

func TestParseEPSS(t *testing.T) {
	m, err := ParseEPSS(fixture(t, "epss.json"))
	if err != nil || len(m) != 3 || m["CVE-2020-0001"].Score != 0.00043 {
		t.Fatalf("%v %v", m, err)
	}
	if _, err := ParseEPSS([]byte(`{"status":"ERROR"}`)); err == nil {
		t.Error("error status accepted")
	}
	if _, err := ParseEPSS([]byte(`nope`)); err == nil {
		t.Error("invalid json accepted")
	}
	m, _ = ParseEPSS([]byte(`{"status":"OK","data":[{"cve":"CVE-2020-0001","epss":"1.5","percentile":"0.1"},{"cve":"bad","epss":"0.1","percentile":"0.1"}]}`))
	if len(m) != 0 {
		t.Errorf("out-of-range/malformed kept: %v", m)
	}
}

func TestConcurrentLookupsDuringRefresh(t *testing.T) {
	f := newFeed(t, kevBody(manyIDs(50)...))
	s := f.service(t, "", nil)
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			f.etag.Store(fmt.Sprintf(`"c%d"`, i))
			_, _ = s.Refresh(ctx)
			_, _ = s.RefreshEPSS(ctx, manyIDs(5))
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
			s.KEV("CVE-2024-00001")
			s.EPSS("CVE-2024-00002")
			s.Status()
		}
	}
}
