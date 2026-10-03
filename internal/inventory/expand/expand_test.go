package expand

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// ---- CT ----

func ctServer(t *testing.T, h http.HandlerFunc) (*CT, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := NewCT(WithCTBaseURL(srv.URL+"/"), WithCTHTTPClient(srv.Client()), WithCTRetries(2, time.Millisecond))
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c, srv
}

func TestCTNamesFromRecordedJSON(t *testing.T) {
	body, err := os.ReadFile("testdata/crtsh_example.json")
	if err != nil {
		t.Fatal(err)
	}
	var gotQ, gotOut, gotUA string
	c, _ := ctServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQ, gotOut, gotUA = r.URL.Query().Get("q"), r.URL.Query().Get("output"), r.Header.Get("User-Agent")
		if r.URL.RawQuery == "" || !strings.Contains(r.URL.RawQuery, "q=%25.example.com") {
			t.Errorf("query must be percent-encoded %%.zone: %s", r.URL.RawQuery)
		}
		_, _ = w.Write(body)
	})
	names, err := c.Names(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "example.com", "mail.example.com", "staging.api.example.com", "www.example.com"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v\nwant %v", names, want)
	}
	if gotQ != "%.example.com" || gotOut != "json" || gotUA != "deckard-ct/1" {
		t.Fatalf("q=%q out=%q ua=%q", gotQ, gotOut, gotUA)
	}
}

func TestCTRetries(t *testing.T) {
	var n atomic.Int32
	c, _ := ctServer(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`[{"common_name":"a.example.com","name_value":"a.example.com"}]`))
	})
	names, err := c.Names(context.Background(), "example.com")
	if err != nil || len(names) != 1 || n.Load() != 3 {
		t.Fatalf("names=%v err=%v attempts=%d", names, err, n.Load())
	}
}

func TestCTFailures(t *testing.T) {
	tests := []struct {
		name     string
		h        http.HandlerFunc
		attempts int32
		errSub   string
		// transient: the source is down (5xx, 429), not the answer wrong.
		transient bool
	}{
		{"always 503 exhausts retries", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, 3, "status 503", true},
		{"502 from crt.sh", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(502) }, 3, "ct: status 502", true},
		{"429 retried", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }, 3, "status 429", true},
		{"404 not retried", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }, 1, "unexpected status 404", false},
		{"html body not retried", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>busy</html>")) }, 1, "decode", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var n atomic.Int32
			c, _ := ctServer(t, func(w http.ResponseWriter, r *http.Request) { n.Add(1); tc.h(w, r) })
			_, err := c.Names(context.Background(), "example.com")
			if err == nil || !strings.Contains(err.Error(), tc.errSub) || n.Load() != tc.attempts {
				t.Fatalf("err=%v attempts=%d", err, n.Load())
			}
			var ue *UnavailableError
			if errors.As(err, &ue) != tc.transient {
				t.Fatalf("transient = %v, want %v (err %v)", !tc.transient, tc.transient, err)
			}
		})
	}
}

func TestCTEdgeCases(t *testing.T) {
	c, _ := ctServer(t, func(w http.ResponseWriter, _ *http.Request) {})
	if names, err := c.Names(context.Background(), "example.com"); err != nil || names != nil {
		t.Fatalf("empty body: %v %v", names, err)
	}
	for _, z := range []string{"", "com", "  "} {
		if _, err := c.Names(context.Background(), z); err == nil {
			t.Errorf("zone %q must be rejected", z)
		}
	}
	// Cancelled context aborts quickly and is not retried forever.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Names(ctx, "example.com"); err == nil {
		t.Fatal("want ctx error")
	}
	bad := NewCT(WithCTBaseURL("://bad"))
	if _, err := bad.Names(context.Background(), "example.com"); err == nil {
		t.Fatal("bad url")
	}
	// options
	o := NewCT(WithCTTimeout(time.Second), WithCTUserAgent("x/1"))
	if o.Timeout != time.Second || o.UserAgent != "x/1" || o.HTTP == nil {
		t.Fatalf("%+v", o)
	}
}

func TestCTNetworkErrorRetriedThenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused
	c := NewCT(WithCTBaseURL(url), WithCTRetries(1, time.Millisecond))
	c.sleep = func(context.Context, time.Duration) error { return nil }
	_, err := c.Names(context.Background(), "example.com")
	var ue *UnavailableError
	if err == nil || !strings.Contains(err.Error(), "request") || !errors.As(err, &ue) {
		t.Fatalf("a network error must be a transient UnavailableError: %v", err)
	}
	// sleepCtx honours cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Fatal("sleepCtx must honour ctx")
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

// ---- resolver fake ----

type fakeRes struct {
	hosts map[string][]string
	wild  []string // answers for any name not in hosts under wildZone
	wz    string
	err   error // returned for every lookup when set
	calls atomic.Int32
}

func (f *fakeRes) LookupHost(ctx context.Context, h string) ([]string, error) {
	f.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.hosts[h]; ok {
		return a, nil
	}
	if f.wz != "" && strings.HasSuffix(h, "."+f.wz) {
		return f.wild, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}
func (f *fakeRes) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (f *fakeRes) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (f *fakeRes) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

// ---- wildcard ----

func TestDetectWildcard(t *testing.T) {
	ctx := context.Background()
	t.Run("no wildcard", func(t *testing.T) {
		info, err := DetectWildcard(ctx, &fakeRes{}, "example.com")
		if err != nil || info.IsWildcard || len(info.Answers) != 0 {
			t.Fatalf("%+v %v", info, err)
		}
	})
	t.Run("wildcard", func(t *testing.T) {
		info, err := DetectWildcard(ctx, &fakeRes{wz: "example.com", wild: []string{"192.0.2.9", "192.0.2.8"}}, "example.com")
		if err != nil || !info.IsWildcard || !reflect.DeepEqual(info.Answers, []string{"192.0.2.8", "192.0.2.9"}) {
			t.Fatalf("%+v %v", info, err)
		}
	})
	t.Run("wildcard answering without addresses still counts", func(t *testing.T) {
		info, err := DetectWildcard(ctx, &fakeRes{wz: "example.com"}, "example.com")
		if err != nil || !info.IsWildcard {
			t.Fatalf("%+v %v", info, err)
		}
	})
	t.Run("all probes fail is an error not no-wildcard", func(t *testing.T) {
		_, err := DetectWildcard(ctx, &fakeRes{err: errors.New("scope: denied")}, "example.com")
		if err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatal(err)
		}
	})
	t.Run("empty zone", func(t *testing.T) {
		if _, err := DetectWildcard(ctx, &fakeRes{}, " . "); err == nil {
			t.Fatal()
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		c, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := DetectWildcard(c, &fakeRes{}, "example.com"); err == nil {
			t.Fatal()
		}
	})
	t.Run("three distinct random labels", func(t *testing.T) {
		seen := map[string]bool{}
		for i := 0; i < 50; i++ {
			seen[RandomLabel()] = true
		}
		if len(seen) != 50 || !strings.HasPrefix(RandomLabel(), "deckard-") {
			t.Fatal("labels must be random")
		}
		r := &fakeRes{}
		_, _ = DetectWildcard(ctx, r, "example.com")
		if r.calls.Load() != 3 {
			t.Fatalf("probes: %d", r.calls.Load())
		}
	})
}

func TestWildcardMatchesAndFilter(t *testing.T) {
	ctx := context.Background()
	r := &fakeRes{
		wz: "example.com", wild: []string{"192.0.2.9"},
		hosts: map[string][]string{
			"real.example.com":    {"192.0.2.50"},
			"mixed.example.com":   {"192.0.2.9", "192.0.2.51"},
			"onlywild.example.c":  {"192.0.2.9"},
			"phantom.example.com": {"192.0.2.9"},
		},
	}
	info, _ := DetectWildcard(ctx, r, "example.com")
	got, err := Filter(ctx, r, []string{"Real.example.com", "phantom.example.com", "mixed.example.com", "random-wild.example.com", "dead.other.com"}, info, "ct")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
		if c.Origin != "ct" || c.Zone != "example.com" {
			t.Errorf("%+v", c)
		}
	}
	// phantom and random-wild only exist due to the wildcard; mixed has a distinct address.
	want := []string{"real.example.com", "mixed.example.com", "dead.other.com"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v want %v", names, want)
	}

	// No wildcard: nothing resolved, everything passes.
	quiet := &fakeRes{}
	noW := WildcardInfo{Zone: "example.com"}
	got, _ = Filter(ctx, quiet, []string{"a.example.com", "b.example.com"}, noW, "ct")
	if len(got) != 2 || quiet.calls.Load() != 0 {
		t.Fatalf("no DNS when no wildcard: %v calls=%d", got, quiet.calls.Load())
	}
	if noW.Matches([]string{"192.0.2.9"}) || info.Matches(nil) {
		t.Fatal("Matches edge cases")
	}
	// A failed lookup in a wildcard zone is not added.
	bad := &fakeRes{err: errors.New("timeout")}
	got, _ = Filter(ctx, bad, []string{"x.example.com"}, info, "ct")
	if len(got) != 0 {
		t.Fatalf("%v", got)
	}
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Filter(c, r, []string{"x.example.com"}, info, "ct"); err == nil {
		t.Fatal("ctx")
	}
}

// ---- wordlist ----

func TestWordlist(t *testing.T) {
	d := DefaultWordlist()
	if len(d) < 150 || len(d) > 400 {
		t.Fatalf("default wordlist size %d", len(d))
	}
	seen := map[string]bool{}
	for _, w := range d {
		if !validLabel(w) || seen[w] {
			t.Fatalf("bad/dup word %q", w)
		}
		seen[w] = true
	}
	if !seen["www"] || !seen["staging"] {
		t.Fatal("missing common labels")
	}
	p := filepath.Join(t.TempDir(), "w.txt")
	_ = os.WriteFile(p, []byte("# c\nFoo\n\n  bar  \nfoo\nbad label\n-x\nbaz\n"), 0o600)
	got, err := LoadWordlist(p)
	if err != nil || !reflect.DeepEqual(got, []string{"foo", "bar", "baz"}) {
		t.Fatalf("%v %v", got, err)
	}
	if def, _ := LoadWordlist(""); len(def) != len(d) {
		t.Fatal("empty path must give default")
	}
	if _, err := LoadWordlist(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing file")
	}
}

// ---- bruteforce ----

func TestBruteforce(t *testing.T) {
	ctx := context.Background()
	t.Run("finds existing, ignores bad words", func(t *testing.T) {
		r := &fakeRes{hosts: map[string][]string{"www.example.com": {"192.0.2.1"}, "dev.example.com": {"192.0.2.2"}}}
		got, err := Bruteforce(ctx, r, "Example.com.", []string{"www", "nope", "DEV", "bad label", "", "www"}, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || got[0].Name != "dev.example.com" || got[1].Name != "www.example.com" || got[0].Origin != "dns_bruteforce" {
			// www appears twice in the word list and is queried twice; callers dedupe via AssetInputs.
			t.Fatalf("%+v", got)
		}
		if n := len(AssetInputs(got, "expansion:dns")); n != 2 {
			t.Fatalf("AssetInputs must dedupe: %d", n)
		}
	})
	t.Run("wildcard zone filters phantoms", func(t *testing.T) {
		r := &fakeRes{wz: "example.com", wild: []string{"192.0.2.9"}, hosts: map[string][]string{"vpn.example.com": {"192.0.2.77"}}}
		got, err := Bruteforce(ctx, r, "example.com", []string{"www", "vpn", "mail"}, 1000)
		if err != nil || len(got) != 1 || got[0].Name != "vpn.example.com" {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("rate limited", func(t *testing.T) {
		r := &fakeRes{}
		start := time.Now()
		words := []string{"a", "b", "c", "d", "e", "f"}
		if _, err := Bruteforce(ctx, r, "example.com", words, 50); err != nil {
			t.Fatal(err)
		}
		// 6 words at 50/s with burst 1 take >= ~100ms.
		if el := time.Since(start); el < 90*time.Millisecond {
			t.Fatalf("not rate limited: %v", el)
		}
	})
	t.Run("default rate when zero", func(t *testing.T) {
		r := &fakeRes{hosts: map[string][]string{"www.example.com": {"192.0.2.1"}}}
		got, err := Bruteforce(ctx, r, "example.com", []string{"www"}, 0)
		if err != nil || len(got) != 1 {
			t.Fatalf("%v %v", got, err)
		}
	})
	t.Run("ctx cancel returns partial", func(t *testing.T) {
		r := &fakeRes{hosts: map[string][]string{"a.example.com": {"192.0.2.1"}}}
		c, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		got, err := Bruteforce(c, r, "example.com", []string{"a", "b", "c", "d", "e", "f", "g", "h"}, 20)
		if !errors.Is(err, context.DeadlineExceeded) || len(got) != 1 {
			t.Fatalf("%v %v", got, err)
		}
	})
	t.Run("resolver failure is an error", func(t *testing.T) {
		r := &fakeRes{hosts: map[string][]string{}}
		r.err = nil
		fr := &failAfterProbe{fakeRes: r}
		_, err := Bruteforce(ctx, fr, "example.com", []string{"a", "b"}, 1000)
		if err == nil || !strings.Contains(err.Error(), "all 2 lookups failed") {
			t.Fatal(err)
		}
	})
	t.Run("wildcard detection failure is an error", func(t *testing.T) {
		if _, err := Bruteforce(ctx, &fakeRes{err: errors.New("denied")}, "example.com", []string{"a"}, 1000); err == nil {
			t.Fatal()
		}
	})
	t.Run("empty zone", func(t *testing.T) {
		if _, err := Bruteforce(ctx, &fakeRes{}, "", nil, 1); err == nil {
			t.Fatal()
		}
	})
}

// failAfterProbe lets the 3 wildcard probes through (NXDOMAIN) then fails.
type failAfterProbe struct{ *fakeRes }

func (f *failAfterProbe) LookupHost(ctx context.Context, h string) ([]string, error) {
	if strings.HasPrefix(h, "deckard-") {
		return f.fakeRes.LookupHost(ctx, h)
	}
	return nil, errors.New("servfail")
}

// ---- converter ----

func TestCandidateAssetInput(t *testing.T) {
	c := Candidate{Name: "vpn.example.com", Zone: "example.com", Origin: "ct", Addrs: []string{"192.0.2.2", "192.0.2.1"}}
	a := c.AssetInput("expansion:ct")
	if a.Kind != model.KindHostname || a.Key != "vpn.example.com" || a.Source != "expansion:ct" || a.Zone != "example.com" ||
		a.Attrs["discovered_by"] != "ct" || !reflect.DeepEqual(a.Attrs["resolved"], []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("%+v", a)
	}
	if _, has := (Candidate{Name: "x.example.com"}).AssetInput("s").Attrs["resolved"]; has {
		t.Fatal("no resolved attr without addrs")
	}
}
