package intel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// publicIP is what the fake resolver answers by default: an ordinary public
// unicast address. Dials to it are routed to the local TLS test server, so no
// test ever leaves the machine.
var publicIP = netip.MustParseAddr("93.184.215.14")

var labHosts = []string{
	"data.iana.org", "rdap.example.net", "rdap.example.org",
	"internetdb.shodan.io", "web.archive.org", "evil.example.com",
}

// lab is a TLS server presenting a certificate for labHosts, plus the seams
// that route the client to it.
type lab struct {
	t     *testing.T
	srv   *httptest.Server
	roots *x509.CertPool

	mu      sync.Mutex
	dials   []string // vetted ip:port the client dialled
	sleeps  []time.Duration
	resolve func(host string) ([]netip.Addr, error)
	hits    map[string]int // host+path -> upstream requests

	clock *fakeClock
	logs  *syncWriter
	rec   *fakeRecorder
}

func newLab(t *testing.T, h http.HandlerFunc) *lab {
	t.Helper()
	l := &lab{t: t, hits: map[string]int{}, clock: &fakeClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		logs: &syncWriter{w: &bytes.Buffer{}}, rec: newFakeRecorder()}
	cert, pool := labCert(t)
	l.roots = pool
	l.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.hits[r.Host+r.URL.Path]++
		l.mu.Unlock()
		h(w, r)
	}))
	l.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	l.srv.StartTLS()
	t.Cleanup(l.srv.Close)
	return l
}

func (l *lab) seams() seams {
	return seams{
		resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			l.mu.Lock()
			f := l.resolve
			l.mu.Unlock()
			if f != nil {
				return f(host)
			}
			return []netip.Addr{publicIP}, nil
		},
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			l.mu.Lock()
			l.dials = append(l.dials, addr)
			l.mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, l.srv.Listener.Addr().String())
		},
		roots: l.roots,
		now:   l.clock.now,
		sleep: func(ctx context.Context, d time.Duration) error {
			l.mu.Lock()
			l.sleeps = append(l.sleeps, d)
			l.mu.Unlock()
			return ctx.Err()
		},
	}
}

func (l *lab) client(o Options) *Client {
	l.t.Helper()
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(l.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	if o.Recorder == nil {
		o.Recorder = l.rec
	}
	if o.Services == nil {
		o.Services = map[string]ServiceConfig{}
	}
	for _, name := range ServiceNames() {
		if sc := o.Services[name]; sc.RatePerSecond == 0 {
			sc.RatePerSecond = 1000 // fast tests; TestRateLimit sets its own
			o.Services[name] = sc
		}
	}
	if o.Version == "" {
		o.Version = "1.2.3"
	}
	c, err := newClient(o, l.seams())
	if err != nil {
		l.t.Fatal(err)
	}
	return c
}

func (l *lab) hitsFor(hostPath string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hits[hostPath]
}

func (l *lab) dialed() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.dials...)
}

func (l *lab) slept() []time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Duration(nil), l.sleeps...)
}

func (l *lab) setResolve(f func(host string) ([]netip.Addr, error)) {
	l.mu.Lock()
	l.resolve = f
	l.mu.Unlock()
}

func (l *lab) logText() string {
	l.logs.mu.Lock()
	defer l.logs.mu.Unlock()
	return l.logs.w.String()
}

// serveBootstrap answers data.iana.org with the fixture.
func serveBootstrap(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	if r.Host != "data.iana.org" {
		return false
	}
	b, err := os.ReadFile("testdata/bootstrap.json")
	if err != nil {
		t.Error(err)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
	return true
}

type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeRecorder struct {
	mu       sync.Mutex
	results  map[string]int // "service/result"
	observed atomic.Int64
}

func newFakeRecorder() *fakeRecorder { return &fakeRecorder{results: map[string]int{}} }

func (r *fakeRecorder) IntelRequest(service, result string) {
	r.mu.Lock()
	r.results[service+"/"+result]++
	r.mu.Unlock()
}

func (r *fakeRecorder) IntelDuration(string, time.Duration) { r.observed.Add(1) }

func (r *fakeRecorder) count(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.results[key]
}

// labCert makes a self-signed certificate valid for labHosts.
func labCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "intel lab"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              labHosts,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
