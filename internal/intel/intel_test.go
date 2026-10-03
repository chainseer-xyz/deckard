package intel

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func okHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serveBootstrap(t, w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"v1"`)
		_, _ = fmt.Fprintf(w, `{"host":%q,"path":%q}`, r.Host, r.URL.Path)
	}
}

func TestGetOK(t *testing.T) {
	var ua string
	l := newLab(t, func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("X-Secret", "dropped")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1") // must be ignored
	c := l.client(Options{Contact: "ops@example.com"})
	resp, err := c.Get(context.Background(), ServiceInternetDB, "https://internetdb.shodan.io/198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || string(resp.Body) != `{"ok":true}` || resp.Cached {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Header.Get("ETag") != `"v1"` || resp.Header.Get("X-Secret") != "" {
		t.Errorf("headers = %v", resp.Header)
	}
	if want := "deckard/1.2.3 (+https://github.com/chainseer-xyz/deckard; ops@example.com)"; ua != want {
		t.Errorf("user agent = %q, want %q", ua, want)
	}
	if d := l.dialed(); len(d) != 1 || d[0] != "93.184.215.14:443" {
		t.Errorf("dials = %v, want the vetted ip literal", d)
	}
	if l.rec.count("internetdb/ok") != 1 {
		t.Errorf("metrics = %v", l.rec.results)
	}
}

func TestAllowListEnforcedBeforeAnyConnection(t *testing.T) {
	l := newLab(t, okHandler(t))
	c := l.client(Options{})
	cases := []struct{ service, url string }{
		{ServiceInternetDB, "https://web.archive.org/cdx/search/cdx?url=example.com"}, // another service's host
		{ServiceWayback, "https://evil.example.com/"},
		{ServiceWayback, "http://web.archive.org/"},
		{ServiceWayback, "https://web.archive.org:8443/"},
		{ServiceWayback, "https://user:pw@web.archive.org/"},
		{ServiceWayback, "https://93.184.215.14/"},
		{ServiceWayback, "https://[2606:2800:220:1::1]/"},
		{ServiceWayback, "ftp://web.archive.org/"},
		{ServiceWayback, "://bad"},
		{"nope", "https://web.archive.org/"},
	}
	for _, tc := range cases {
		_, err := c.Get(context.Background(), tc.service, tc.url)
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s %s: err = %v, want ErrBlocked", tc.service, tc.url, err)
		}
	}
	if d := l.dialed(); len(d) != 0 {
		t.Errorf("dialled %v for blocked requests", d)
	}
	if got := l.rec.count("wayback/blocked"); got != 8 {
		t.Errorf("blocked count = %d (%v)", got, l.rec.results)
	}
	logs := l.logText()
	if !strings.Contains(logs, "level=WARN") || strings.Contains(logs, "url=example.com") {
		t.Errorf("blocked requests must warn without the query string:\n%s", logs)
	}
}

func TestRDAPHostsComeFromBootstrap(t *testing.T) {
	l := newLab(t, okHandler(t))
	c := l.client(Options{})
	ctx := context.Background()
	if _, err := c.Get(ctx, ServiceRDAP, "https://rdap.example.net/com/v1/domain/example.com"); err != nil {
		t.Fatalf("bootstrap host refused: %v", err)
	}
	// A host the bootstrap rejected (plain http only for .uk) stays blocked.
	if _, err := c.Get(ctx, ServiceRDAP, "https://rdap.example.uk/domain/example.uk"); !errors.Is(err, ErrBlocked) {
		t.Errorf("non-bootstrap host: err = %v", err)
	}
	// Bootstrap hosts are only for rdap.
	if _, err := c.Get(ctx, ServiceWayback, "https://rdap.example.net/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("rdap host via wayback: err = %v", err)
	}
	if n := l.hitsFor("data.iana.org/rdap/dns.json"); n != 1 {
		t.Errorf("bootstrap fetched %d times", n)
	}
}

func TestRedirects(t *testing.T) {
	l := newLab(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-evil":
			http.Redirect(w, r, "https://evil.example.com/x", http.StatusFound)
		case "/to-http":
			http.Redirect(w, r, "http://web.archive.org/x", http.StatusFound)
		case "/to-other-service":
			http.Redirect(w, r, "https://internetdb.shodan.io/x", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/hop":
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
		default:
			_, _ = w.Write([]byte("final"))
		}
	})
	c := l.client(Options{})
	ctx := context.Background()
	for _, p := range []string{"/to-evil", "/to-http", "/to-other-service"} {
		if _, err := c.Get(ctx, ServiceWayback, "https://web.archive.org"+p); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: err = %v, want ErrBlocked", p, err)
		}
	}
	if n := l.hitsFor("evil.example.com/x") + l.hitsFor("internetdb.shodan.io/x"); n != 0 {
		t.Errorf("redirect target reached %d times", n)
	}

	_, err := c.Get(ctx, ServiceWayback, "https://web.archive.org/loop")
	if err == nil || errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("loop: err = %v", err)
	}
	if n := l.hitsFor("web.archive.org/loop"); n != maxRedirects+1 {
		t.Errorf("loop followed %d requests, want %d", n, maxRedirects+1)
	}

	resp, err := c.Get(ctx, ServiceWayback, "https://web.archive.org/hop")
	if err != nil || string(resp.Body) != "final" {
		t.Errorf("same-host redirect: %v %q", err, resp.Body)
	}
}

func TestResolvedAddressesRefused(t *testing.T) {
	bad := []string{
		"127.0.0.1", "10.1.2.3", "172.16.5.4", "192.168.1.1", "169.254.169.254", "169.254.1.1",
		"100.64.0.1", "100.100.100.200", "168.63.129.16", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "fd00:ec2::254", "fc00::1", "ff02::1", "::ffff:127.0.0.1",
		"64:ff9b::a00:1", "2002:7f00:1::", "2001:db8::1",
	}
	for _, a := range bad {
		t.Run(a, func(t *testing.T) {
			l := newLab(t, okHandler(t))
			l.setResolve(func(string) ([]netip.Addr, error) {
				// One good address does not launder a bad one.
				return []netip.Addr{publicIP, netip.MustParseAddr(a)}, nil
			})
			c := l.client(Options{})
			_, err := c.Get(context.Background(), ServiceInternetDB, "https://internetdb.shodan.io/x")
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("err = %v, want ErrBlocked", err)
			}
			if d := l.dialed(); len(d) != 0 {
				t.Errorf("dialled %v", d)
			}
			if !strings.Contains(l.logText(), "level=WARN") {
				t.Error("blocked resolution not logged at WARN")
			}
		})
	}
}

func TestBlockedReason(t *testing.T) {
	for a, want := range map[string]string{
		"8.8.8.8":           "",
		"2606:4700::1111":   "",
		"64:ff9b::808:808":  "", // NAT64 of a public address
		"169.254.169.254":   "cloud-metadata",
		"fd00:ec2::254":     "cloud-metadata",
		"100.64.1.1":        "cgnat",
		"::ffff:10.0.0.1":   "private",
		"64:ff9b::7f00:1":   "loopback",
		"2001:0:4136::1":    "teredo",
		"198.18.0.1":        "benchmarking",
		"239.255.255.250":   "multicast",
		"::ffff:8.8.8.8":    "",
		"2001:db8:85a3::1":  "documentation",
		"203.0.113.9":       "documentation",
		"fec0::1":           "site-local",
		"64:ff9b:1::a00:1":  "nat64-local",
		"100::1":            "discard",
		"192.0.0.192":       "reserved",
		"240.0.0.1":         "reserved",
		"0.1.2.3":           "unspecified",
		"127.255.255.255":   "loopback",
		"fe80::1%eth0":      "link-local",
		"192.88.99.1":       "reserved",
		"172.31.255.255":    "private",
		"172.32.0.1":        "",
		"100.128.0.1":       "",
		"ff0e::1":           "multicast",
		"2002:808:808::1":   "6to4",
		"::":                "unspecified",
		"::1":               "loopback",
		"fc00::":            "private",
		"169.254.170.2":     "cloud-metadata",
		"168.63.129.16":     "cloud-metadata",
		"100.100.100.200":   "cloud-metadata",
		"192.168.255.255":   "private",
		"198.51.100.1":      "documentation",
		"192.0.2.1":         "documentation",
		"224.0.0.251":       "multicast",
		"64:ff9b::c0a8:101": "private",
	} {
		if got := blockedReason(netip.MustParseAddr(a)); got != want {
			t.Errorf("blockedReason(%s) = %q, want %q", a, got, want)
		}
	}
	if blockedReason(netip.Addr{}) == "" {
		t.Error("zero address allowed")
	}
}

func TestDNSRebindingCannotSwapTheCheckedAddress(t *testing.T) {
	l := newLab(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close") // force a fresh dial (and resolution) per request
		_, _ = w.Write([]byte("ok"))
	})
	var mu sync.Mutex
	calls := 0
	l.setResolve(func(string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return []netip.Addr{publicIP}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	c := l.client(Options{})
	ctx := context.Background()
	if _, err := c.Get(ctx, ServiceWayback, "https://web.archive.org/a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, ServiceWayback, "https://web.archive.org/b"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("rebound answer: err = %v, want ErrBlocked", err)
	}
	for _, d := range l.dialed() {
		if d != "93.184.215.14:443" {
			t.Errorf("dialled %s: only the checked address may be dialled", d)
		}
	}
	if n := l.hitsFor("web.archive.org/b"); n != 0 {
		t.Errorf("rebound request reached the server %d times", n)
	}
}

func TestSizeCaps(t *testing.T) {
	big := bytes.Repeat([]byte("a"), DefaultMaxBytes+1)
	bomb := func() []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(make([]byte, 64<<20)) // 64 MiB of zeros, ~64 KiB compressed
		_ = zw.Close()
		return buf.Bytes()
	}()
	small := func() []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(`{"gz":true}`))
		_ = zw.Close()
		return buf.Bytes()
	}()
	l := newLab(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/declared":
			_, _ = w.Write(big)
		case "/chunked":
			for i := 0; i < len(big); i += 64 << 10 {
				_, _ = w.Write(big[i:min(i+64<<10, len(big))])
				w.(http.Flusher).Flush()
			}
		case "/bomb":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(bomb)
		case "/gzip":
			if r.Header.Get("Accept-Encoding") != "gzip" {
				t.Errorf("Accept-Encoding = %q", r.Header.Get("Accept-Encoding"))
			}
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(small)
		case "/brotli":
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte("x"))
		case "/2k":
			_, _ = w.Write(make([]byte, 2048))
		}
	})
	c := l.client(Options{Services: map[string]ServiceConfig{ServiceInternetDB: {MaxBytes: 1024}}})
	ctx := context.Background()
	for _, p := range []string{"/declared", "/chunked", "/bomb"} {
		if _, err := c.Get(ctx, ServiceWayback, "https://web.archive.org"+p); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: err = %v, want ErrTooLarge", p, err)
		}
		if n := l.hitsFor("web.archive.org" + p); n != 1 {
			t.Errorf("%s: %d attempts, oversize bodies are not retried", p, n)
		}
	}
	resp, err := c.Get(ctx, ServiceWayback, "https://web.archive.org/gzip")
	if err != nil || string(resp.Body) != `{"gz":true}` {
		t.Errorf("gzip: %v %q", err, resp.Body)
	}
	if _, err := c.Get(ctx, ServiceWayback, "https://web.archive.org/brotli"); err == nil {
		t.Error("unsupported content-encoding accepted")
	}
	if _, err := c.Get(ctx, ServiceInternetDB, "https://internetdb.shodan.io/2k"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("per-service cap: err = %v", err)
	}
	if _, err := c.Get(ctx, ServiceWayback, "https://web.archive.org/2k"); err != nil {
		t.Errorf("default cap: %v", err)
	}
}

func TestTimeoutRetriedThenUnavailable(t *testing.T) {
	l := newLab(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	c := l.client(Options{Services: map[string]ServiceConfig{ServiceWayback: {Timeout: 50 * time.Millisecond}}})
	start := time.Now()
	_, err := c.Get(context.Background(), ServiceWayback, "https://web.archive.org/slow")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("timeout not enforced: took %s", time.Since(start))
	}
	if n := l.hitsFor("web.archive.org/slow"); n != maxAttempts {
		t.Errorf("attempts = %d, want %d", n, maxAttempts)
	}
	if l.rec.count("wayback/error") != 1 {
		t.Errorf("metrics = %v", l.rec.results)
	}
}

func TestRetryAfterThenSuccess(t *testing.T) {
	var mu sync.Mutex
	n := 0
	l := newLab(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	c := l.client(Options{})
	resp, err := c.Get(context.Background(), ServiceWayback, "https://web.archive.org/x")
	if err != nil || string(resp.Body) != "ok" {
		t.Fatalf("%v %q", err, resp.Body)
	}
	if s := l.slept(); len(s) != 1 || s[0] != 7*time.Second {
		t.Errorf("waits = %v, want the server's Retry-After of 7s", s)
	}
}

func TestRetryAfterBeyondBoundGivesUp(t *testing.T) {
	l := newLab(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	c := l.client(Options{})
	_, err := c.Get(context.Background(), ServiceWayback, "https://web.archive.org/x")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	if n := l.hitsFor("web.archive.org/x"); n != 1 {
		t.Errorf("attempts = %d: a Retry-After beyond the bound must not be waited out", n)
	}
	if l.rec.count("wayback/rate_limited") != 1 {
		t.Errorf("metrics = %v", l.rec.results)
	}
}

func TestServerErrorsExhaustRetries(t *testing.T) {
	l := newLab(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/400" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := l.client(Options{})
	_, err := c.Get(context.Background(), ServiceWayback, "https://web.archive.org/x")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if n := l.hitsFor("web.archive.org/x"); n != maxAttempts {
		t.Errorf("attempts = %d", n)
	}
	s := l.slept()
	if len(s) != maxAttempts-1 {
		t.Fatalf("waits = %v", s)
	}
	for i, d := range s {
		lo, hi := (baseBackoff<<i)/2, baseBackoff<<i
		if d < lo || d >= hi {
			t.Errorf("wait %d = %s, want jittered in [%s, %s)", i, d, lo, hi)
		}
	}
	if _, err := c.Get(context.Background(), ServiceWayback, "https://web.archive.org/400"); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("400: err = %v", err)
	}
	if n := l.hitsFor("web.archive.org/400"); n != 1 {
		t.Errorf("400 retried %d times", n)
	}
	// Errors are not cached.
	_, _ = c.Get(context.Background(), ServiceWayback, "https://web.archive.org/x")
	if n := l.hitsFor("web.archive.org/x"); n != 2*maxAttempts {
		t.Errorf("errors were cached: %d attempts", n)
	}
}

func TestCache(t *testing.T) {
	l := newLab(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("body"))
	})
	c := l.client(Options{Services: map[string]ServiceConfig{ServiceInternetDB: {CacheTTL: time.Minute}}})
	ctx := context.Background()
	get := func(svc, u string) (Response, error) { return c.Get(ctx, svc, u) }

	r1, _ := get(ServiceWayback, "https://web.archive.org/x")
	r1.Body[0] = 'X' // callers own their copy
	r2, err := get(ServiceWayback, "https://WEB.archive.org/x#frag")
	if err != nil || !r2.Cached || string(r2.Body) != "body" {
		t.Fatalf("cache hit: %v %+v", err, r2)
	}
	if n := l.hitsFor("web.archive.org/x"); n != 1 {
		t.Errorf("upstream hits = %d", n)
	}
	if l.rec.count("wayback/cached") != 1 {
		t.Errorf("metrics = %v", l.rec.results)
	}

	l.clock.advance(DefaultCacheTTL + time.Second)
	if r, _ := get(ServiceWayback, "https://web.archive.org/x"); r.Cached {
		t.Error("expired entry served")
	}
	if n := l.hitsFor("web.archive.org/x"); n != 2 {
		t.Errorf("after expiry upstream hits = %d", n)
	}

	// Negative caching: 15 minutes by default.
	for range 2 {
		if _, err := get(ServiceWayback, "https://web.archive.org/missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
	}
	if n := l.hitsFor("web.archive.org/missing"); n != 1 {
		t.Errorf("not-found not cached: %d hits", n)
	}
	l.clock.advance(DefaultNegativeCacheTTL)
	_, _ = get(ServiceWayback, "https://web.archive.org/missing")
	if n := l.hitsFor("web.archive.org/missing"); n != 2 {
		t.Errorf("negative entry outlived its ttl: %d hits", n)
	}

	// Per-service TTL override.
	_, _ = get(ServiceInternetDB, "https://internetdb.shodan.io/y")
	l.clock.advance(2 * time.Minute)
	_, _ = get(ServiceInternetDB, "https://internetdb.shodan.io/y")
	if n := l.hitsFor("internetdb.shodan.io/y"); n != 2 {
		t.Errorf("cache_ttl override ignored: %d hits", n)
	}
}

func TestCacheBounded(t *testing.T) {
	now := time.Now()
	c := newTTLCache(3, func() time.Time { return now })
	for i, ttl := range []time.Duration{time.Hour, time.Minute, 2 * time.Hour, 3 * time.Hour} {
		c.put(fmt.Sprint(i), cacheEntry{}, ttl)
	}
	if c.len() != 3 {
		t.Fatalf("len = %d", c.len())
	}
	if _, ok := c.get("1"); ok {
		t.Error("the entry closest to expiry should have been evicted")
	}
}

func TestSingleFlight(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	l := newLab(t, func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		_, _ = w.Write([]byte("shared"))
	})
	c := l.client(Options{})
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	cached := make(chan bool, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.Get(context.Background(), ServiceWayback, "https://web.archive.org/sf")
			if err == nil && string(r.Body) != "shared" {
				err = fmt.Errorf("body %q", r.Body)
			}
			errs <- err
			cached <- r.Cached
		}()
	}
	<-started
	time.Sleep(100 * time.Millisecond) // let the other callers queue up behind the first
	close(release)
	wg.Wait()
	close(errs)
	close(cached)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	fresh := 0
	for c := range cached {
		if !c {
			fresh++
		}
	}
	if hits := l.hitsFor("web.archive.org/sf"); hits != 1 {
		t.Errorf("upstream hits = %d, want 1", hits)
	}
	if fresh != 1 || l.rec.count("wayback/ok") != 1 || l.rec.count("wayback/cached") != n-1 {
		t.Errorf("fresh = %d, metrics = %v", fresh, l.rec.results)
	}
}

func TestCallerCancellationDoesNotFailSharedFetch(t *testing.T) {
	release := make(chan struct{})
	l := newLab(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte("late"))
	})
	c := l.client(Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, ServiceWayback, "https://web.archive.org/late"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	close(release)
	// The detached fetch completes and fills the cache.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.cache.len() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	r, err := c.Get(context.Background(), ServiceWayback, "https://web.archive.org/late")
	if err != nil || !r.Cached || string(r.Body) != "late" {
		t.Errorf("%v %+v", err, r)
	}
}

func TestRateLimit(t *testing.T) {
	l := newLab(t, okHandler(t))
	c := l.client(Options{Services: map[string]ServiceConfig{ServiceWayback: {RatePerSecond: 4}}})
	start := time.Now()
	for i := range 6 { // burst of 4, then one token every 250ms
		if _, err := c.Get(context.Background(), ServiceWayback, fmt.Sprintf("https://web.archive.org/%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 400*time.Millisecond {
		t.Errorf("6 requests at 4/s took %s", el)
	}

	// No token before the deadline: rate_limited, without contacting upstream.
	slow := l.client(Options{Services: map[string]ServiceConfig{ServiceWayback: {RatePerSecond: 0.01}}})
	svc := slow.svcs[ServiceWayback]
	_ = svc.limiter.Wait(context.Background()) // drain the burst
	ctx, cancel := context.WithTimeout(withService(context.Background(), ServiceWayback), 100*time.Millisecond)
	defer cancel()
	u, _ := slow.vet(ctx, svc, "https://web.archive.org/limited")
	o := slow.do(ctx, svc, u)
	if o.result != ResultRateLimited || !errors.Is(o.err, ErrRateLimited) {
		t.Errorf("outcome = %+v", o)
	}
	if n := l.hitsFor("web.archive.org/limited"); n != 0 {
		t.Errorf("upstream contacted %d times without a token", n)
	}
}

func TestDisabled(t *testing.T) {
	l := newLab(t, okHandler(t))
	ctx := context.Background()
	off := l.client(Options{Disabled: true})
	if _, err := off.Get(ctx, ServiceWayback, "https://web.archive.org/"); !errors.Is(err, ErrDisabled) {
		t.Errorf("Get: %v", err)
	}
	if _, err := off.RDAPBase(ctx, "example.com"); !errors.Is(err, ErrDisabled) {
		t.Errorf("RDAPBase: %v", err)
	}
	var nilClient *Client
	if _, err := nilClient.Get(ctx, ServiceWayback, "https://web.archive.org/"); !errors.Is(err, ErrDisabled) {
		t.Errorf("nil client: %v", err)
	}
	partly := l.client(Options{Services: map[string]ServiceConfig{ServiceRDAP: {Disabled: true}}})
	if _, err := partly.RDAPBase(ctx, "example.com"); !errors.Is(err, ErrDisabled) {
		t.Errorf("rdap disabled: %v", err)
	}
	if _, err := partly.Get(ctx, ServiceWayback, "https://web.archive.org/"); err != nil {
		t.Errorf("other services stay on: %v", err)
	}
	if d := l.dialed(); len(d) != 1 {
		t.Errorf("dials = %v", d)
	}
	if _, err := New(Options{Services: map[string]ServiceConfig{"pastebin": {}}}); err == nil {
		t.Error("unknown service accepted")
	}
}

func TestLogsNeverCarryQueryOrBody(t *testing.T) {
	l := newLab(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("SECRET-BODY-MARKER"))
	})
	c := l.client(Options{})
	_, _ = c.Get(context.Background(), ServiceWayback, "https://web.archive.org/cdx/search/cdx?url=private-marker.example.com")
	_, _ = c.Get(context.Background(), ServiceWayback, "https://evil.example.com/?token=private-marker")
	logs := l.logText()
	if strings.Contains(logs, "private-marker") || strings.Contains(logs, "SECRET-BODY-MARKER") {
		t.Errorf("query string or body logged:\n%s", logs)
	}
	if !strings.Contains(logs, "path=/cdx/search/cdx") || !strings.Contains(logs, "level=DEBUG") {
		t.Errorf("request not logged at debug:\n%s", logs)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"":                              0,
		"5":                             5 * time.Second,
		"-1":                            0,
		"soon":                          0,
		"Thu, 01 Oct 2026 12:00:10 GMT": 10 * time.Second,
		"Thu, 01 Oct 2026 11:00:00 GMT": 0,
	} {
		if got := retryAfter(v, now); got != want {
			t.Errorf("retryAfter(%q) = %s, want %s", v, got, want)
		}
	}
}

func TestIsPublicAddr(t *testing.T) {
	for a, want := range map[string]bool{
		"1.2.3.4": true, "93.184.216.34": true, "2606:4700:4700::1111": true, "::ffff:1.2.3.4": true,
		"10.0.0.1": false, "127.0.0.1": false, "169.254.169.254": false, "100.64.0.1": false, "192.0.2.1": false,
		"::1": false, "fe80::1": false, "fd00::1": false, "2001:db8::1": false, "224.0.0.1": false, "0.0.0.0": false,
	} {
		if got := IsPublicAddr(netip.MustParseAddr(a)); got != want {
			t.Errorf("IsPublicAddr(%s) = %v, want %v", a, got, want)
		}
	}
	if IsPublicAddr(netip.Addr{}) {
		t.Error("the zero address is not public")
	}
}
