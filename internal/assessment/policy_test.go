package assessment_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessment"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

type resolver struct {
	mu        sync.Mutex
	addresses []string
	calls     int
	rebindAt  int
}

func (r *resolver) LookupHost(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.rebindAt > 0 && r.calls >= r.rebindAt {
		return []string{"169.254.169.254"}, nil
	}
	return r.addresses, nil
}
func (*resolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (*resolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (*resolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

func guard(t *testing.T, r *resolver) *scope.Guard {
	t.Helper()
	g, err := scope.NewGuard(config.ScopeConfig{Include: []string{"app.example.com", "10.20.30.40/32"}}, scope.WithResolver(r))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func limits() assessment.Limits {
	return assessment.Limits{MaxRequests: 10, MaxRequestBytes: 1024, MaxResponseBytes: 4096, Timeout: time.Minute}
}

func TestPolicyRefreshesOwnershipBeforeConstructionAndEveryAuthorization(t *testing.T) {
	g, err := scope.NewGuard(config.ScopeConfig{}, scope.WithResolver(&resolver{addresses: []string{"10.20.30.40"}}))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	revoked := false
	refresh := func(context.Context) error {
		calls++
		g.SetZones([]string{"example.com"})
		prefixes := []netip.Prefix{netip.MustParsePrefix("10.20.30.40/32")}
		if revoked {
			prefixes = nil
		}
		g.SetOwnedPrefixes(prefixes)
		return nil
	}
	p, err := assessment.NewPolicy(context.Background(), g, []string{"https://app.example.com"}, limits(), assessment.WithOwnershipRefresh(refresh))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if calls != 1 {
		t.Fatalf("initial verification did not refresh persisted ownership: %d calls", calls)
	}
	if _, err := p.AuthorizeURL(context.Background(), "https://app.example.com/path"); err != nil {
		t.Fatal(err)
	}
	revoked = true
	if _, err := p.AuthorizeURL(context.Background(), "https://app.example.com/path"); !errors.Is(err, assessment.ErrDenied) {
		t.Fatalf("persisted ownership withdrawal was ignored: %v", err)
	}
	if calls != 3 || p.Err() == nil {
		t.Fatalf("ownership refresh must run per authorization and refuse sticky: calls=%d err=%v", calls, p.Err())
	}
}

func TestPolicyOwnershipRefreshFailureIsRedactedAndSticky(t *testing.T) {
	fail := false
	refresh := func(context.Context) error {
		if fail {
			return errors.New("private database connection string")
		}
		return nil
	}
	g := guard(t, &resolver{addresses: []string{"10.20.30.40"}})
	p, err := assessment.NewPolicy(context.Background(), g, []string{"https://app.example.com"}, limits(), assessment.WithOwnershipRefresh(refresh))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	fail = true
	_, err = p.AuthorizeURL(context.Background(), "https://app.example.com/")
	if !errors.Is(err, assessment.ErrDenied) || strings.Contains(err.Error(), "private") {
		t.Fatalf("refresh failure must fail closed without exposing callback error: %v", err)
	}
	fail = false
	if _, err := p.AuthorizeURL(context.Background(), "https://app.example.com/"); !errors.Is(err, assessment.ErrDenied) {
		t.Fatalf("refresh failure was not sticky: %v", err)
	}
	fail = true
	if _, err := assessment.NewPolicy(context.Background(), g, []string{"https://app.example.com"}, limits(), assessment.WithOwnershipRefresh(refresh)); !errors.Is(err, assessment.ErrDenied) {
		t.Fatalf("construction ignored unavailable ownership ledger: %v", err)
	}
}

func TestPolicyAuthorizesOnlyExplicitOwnedOrigins(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://app.example.com/path?parameter=value", true},
		{"https://APP.example.com:443/another", true},
		{"https://app.example.com.:443/", true},
		{"http://app.example.com/", false},
		{"https://app.example.com:8443/", false},
		{"https://other.example.com/", false},
		{"https://10.20.30.40/", false},
		{"https://app.example.com.evil.org/", false},
		{"https://user:password@app.example.com/", false},
		{"https://app.example.com/#secret", false},
		{"https://app.example.com\\@evil.org/", false},
		{"file:///etc/passwd", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			p, err := assessment.NewPolicy(context.Background(), guard(t, &resolver{addresses: []string{"10.20.30.40"}}), []string{"https://APP.example.com:443/"}, limits())
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			_, err = p.AuthorizeURL(context.Background(), tc.url)
			if (err == nil) != tc.want {
				t.Fatalf("authorization error = %v, want allowed %v", err, tc.want)
			}
		})
	}
}

type fixtureDialer struct {
	address      string
	mu           sync.Mutex
	destinations []string
}

func (d *fixtureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.destinations = append(d.destinations, address)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func fixturePolicy(t *testing.T, handler http.Handler, r *resolver, bound assessment.Limits) (*assessment.Policy, *fixtureDialer) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	dialer := &fixtureDialer{address: server.Listener.Addr().String()}
	g, err := scope.NewGuard(config.ScopeConfig{Include: []string{"app.example.com", "10.20.30.40/32"}}, scope.WithResolver(r), scope.WithDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	p, err := assessment.NewPolicy(context.Background(), g, []string{"http://app.example.com"}, bound)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, dialer
}

func request(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPolicyHTTPUsesOwnedLiteralAndIgnoresGlobalProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("global proxy received assessment traffic")
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, proxy.URL)
	}
	p, dialer := fixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.example.com:80" {
			t.Errorf("unexpected Host %q", r.Host)
		}
		_, _ = io.WriteString(w, "owned fixture")
	}), &resolver{addresses: []string{"10.20.30.40"}}, limits())
	response, err := p.Do(request(t, http.MethodGet, "http://app.example.com/test", ""))
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "owned fixture" {
		t.Fatalf("body=%q error=%v", body, err)
	}
	if len(dialer.destinations) != 1 || dialer.destinations[0] != "10.20.30.40:80" {
		t.Fatalf("destination must be pinned owned literal, got %v", dialer.destinations)
	}
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
}

func TestPolicyHTTPRejectsRebindingAtActualDial(t *testing.T) {
	p, dialer := fixturePolicy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("rebound request reached a server")
	}), &resolver{addresses: []string{"10.20.30.40"}, rebindAt: 3}, limits())
	response, err := p.Do(request(t, http.MethodGet, "http://app.example.com/", ""))
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || p.Err() == nil {
		t.Fatalf("refused dial must be incomplete: request=%v session=%v", err, p.Err())
	}
	if len(dialer.destinations) != 0 {
		t.Fatalf("rebound address reached base dialer: %v", dialer.destinations)
	}
}

func TestPolicyRefusalRemainsTerminal(t *testing.T) {
	p, err := assessment.NewPolicy(context.Background(), guard(t, &resolver{addresses: []string{"10.20.30.40"}}), []string{"https://app.example.com"}, limits())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.AuthorizeURL(context.Background(), "https://other.example.com/?secret=do-not-log"); !errors.Is(err, assessment.ErrDenied) || strings.Contains(err.Error(), "do-not-log") {
		t.Fatalf("expected redacted denial, got %v", err)
	}
	if _, err := p.AuthorizeURL(context.Background(), "https://app.example.com/"); !errors.Is(err, assessment.ErrDenied) {
		t.Fatalf("refusal must remain terminal: %v", err)
	}
}

func TestPolicyCanceledAuthorizationIsRefused(t *testing.T) {
	p, err := assessment.NewPolicy(context.Background(), guard(t, &resolver{addresses: []string{"10.20.30.40"}}), []string{"https://app.example.com"}, limits())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.AuthorizeURL(ctx, "https://app.example.com/"); err == nil {
		t.Fatal("canceled authorization was accepted")
	}
}

func TestPolicyResponseHeadersConsumeResponseBudget(t *testing.T) {
	bound := limits()
	bound.MaxResponseBytes = 128
	p, _ := fixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", 256))
		_, _ = io.WriteString(w, "small body")
	}), &resolver{addresses: []string{"10.20.30.40"}}, bound)
	response, err := p.Do(request(t, http.MethodGet, "http://app.example.com/", ""))
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || p.Err() == nil {
		t.Fatal("oversized response headers must make session incomplete")
	}
}

func TestPolicyReturnsRedirectWithoutFollowingIt(t *testing.T) {
	p, dialer := fixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://not-authorized.example.org/", http.StatusFound)
	}), &resolver{addresses: []string{"10.20.30.40"}}, limits())
	response, err := p.Do(request(t, http.MethodGet, "http://app.example.com/", ""))
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound || len(dialer.destinations) != 1 {
		t.Fatal("proxy forwarding must preserve redirect responses")
	}
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	if _, err := p.AuthorizeURL(context.Background(), response.Header.Get("Location")); err == nil {
		t.Fatal("redirected request must be independently refused")
	}
}

func TestPolicyRequestCountIsSharedAcrossRequests(t *testing.T) {
	bound := limits()
	bound.MaxRequests = 1
	p, dialer := fixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), &resolver{addresses: []string{"10.20.30.40"}}, bound)
	response, err := p.Do(request(t, http.MethodGet, "http://app.example.com/", ""))
	if response != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	response, err = p.Do(request(t, http.MethodGet, "http://app.example.com/again", ""))
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || p.Err() == nil || len(dialer.destinations) != 1 {
		t.Fatal("exhausted request budget must prevent network I/O and remain incomplete")
	}
}

func TestPolicyRejectsUnboundedOrNonOwnedSessions(t *testing.T) {
	for _, tc := range []struct {
		name      string
		targets   []string
		addresses []string
		bound     assessment.Limits
	}{
		{"no targets", nil, []string{"10.20.30.40"}, limits()},
		{"not owned", []string{"https://other.example.com"}, []string{"10.20.30.40"}, limits()},
		{"external DNS answer", []string{"https://app.example.com"}, []string{"93.184.216.34"}, limits()},
		{"mixed DNS answers", []string{"https://app.example.com"}, []string{"10.20.30.40", "169.254.169.254"}, limits()},
		{"no DNS answers", []string{"https://app.example.com"}, nil, limits()},
		{"target path", []string{"https://app.example.com/private"}, []string{"10.20.30.40"}, limits()},
		{"target secret query", []string{"https://app.example.com/?secret=not-logged"}, []string{"10.20.30.40"}, limits()},
		{"target credential", []string{"https://user:secret@app.example.com"}, []string{"10.20.30.40"}, limits()},
		{"invalid target URL", []string{"https://app.example.com:invalid"}, []string{"10.20.30.40"}, limits()},
		{"missing bounds", []string{"https://app.example.com"}, []string{"10.20.30.40"}, assessment.Limits{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := assessment.NewPolicy(context.Background(), guard(t, &resolver{addresses: tc.addresses}), tc.targets, tc.bound)
			if p != nil {
				p.Close()
			}
			if err == nil || p != nil {
				t.Fatal("invalid or unowned session was created")
			}
			if strings.Contains(err.Error(), "not-logged") {
				t.Fatal("validation error leaked query contents")
			}
		})
	}
}

func TestPolicyCancellationStopsPendingOwnedHTTP(t *testing.T) {
	entered, stopped := make(chan struct{}), make(chan struct{})
	p, _ := fixturePolicy(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(stopped)
	}), &resolver{addresses: []string{"10.20.30.40"}}, limits())
	done := make(chan error, 1)
	go func() {
		response, err := p.Do(request(t, http.MethodGet, "http://app.example.com/", ""))
		if response != nil {
			_ = response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not reach fixture")
	}
	p.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled request looked complete")
		}
	case <-time.After(time.Second):
		t.Fatal("request did not stop after session cancellation")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("upstream connection leaked after cancellation")
	}
	if p.Err() == nil {
		t.Fatal("canceled assessment must remain incomplete")
	}
}
