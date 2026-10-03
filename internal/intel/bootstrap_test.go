package intel

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseBootstrap(t *testing.T) {
	raw, err := os.ReadFile("testdata/bootstrap.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBootstrap(raw)
	if err != nil {
		t.Fatal(err)
	}
	for domain, want := range map[string]string{
		"example.com":          "https://rdap.example.net/com/v1/",
		"EXAMPLE.NET.":         "https://rdap.example.net/com/v1/",
		"example.org":          "https://rdap.example.org/", // https URL chosen over http, "/" appended
		"shop.co.example":      "https://rdap.example.org/co/",
		"deep.shop.co.example": "https://rdap.example.org/co/", // longest suffix wins
		"example.uk":           "",                             // http only
		"example.io":           "",                             // ip literal
		"example.ch":           "",                             // non-443 port
		"example.de":           "",                             // userinfo
		"example.fr":           "",                             // query
		"example.example":      "",                             // no entry for the bare TLD
	} {
		got, _ := b.Base(domain)
		if got != want {
			t.Errorf("Base(%q) = %q, want %q", domain, got, want)
		}
	}
	if got := b.Hosts(); !slices.Equal(got, []string{"rdap.example.net", "rdap.example.org"}) {
		t.Errorf("hosts = %v", got)
	}
}

func TestParseBootstrapRejects(t *testing.T) {
	for name, body := range map[string]string{
		"malformed":      `{"services": [`,
		"not an object":  `[1,2,3]`,
		"no services":    `{"version":"1.0","services":[]}`,
		"only http":      `{"services":[[["com"],["http://rdap.example.net/"]]]}`,
		"only ip":        `{"services":[[["com"],["https://192.0.2.1/"],["https://[2001:db8::1]/"]]]}`,
		"numeric host":   `{"services":[[["com"],["https://rdap.123/"]]]}`,
		"single label":   `{"services":[[["com"],["https://localhost/"]]]}`,
		"bad tld labels": `{"services":[[["", "a b", "-x"],["https://rdap.example.net/"]]]}`,
		"wrong shape":    `{"services":[["com","https://rdap.example.net/"]]}`,
		"javascript":     `{"services":[[["com"],["javascript:alert(1)"]]]}`,
	} {
		if _, err := ParseBootstrap([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRDAPBaseLoadsAndCachesBootstrap(t *testing.T) {
	var fail atomic.Bool
	l := newLab(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		serveBootstrap(t, w, r)
	})
	c := l.client(Options{})
	ctx := context.Background()
	base, err := c.RDAPBase(ctx, "example.com")
	if err != nil || base != "https://rdap.example.net/com/v1/" {
		t.Fatalf("RDAPBase = %q, %v", base, err)
	}
	if _, err := c.RDAPBase(ctx, "example.uk"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unsupported tld: %v", err)
	}
	if n := l.hitsFor("data.iana.org/rdap/dns.json"); n != 1 {
		t.Errorf("bootstrap fetched %d times within its ttl", n)
	}

	// After 24h it is refreshed; a failed refresh keeps the previous copy.
	l.clock.advance(bootstrapTTL + time.Minute)
	fail.Store(true)
	if base, err := c.RDAPBase(ctx, "example.org"); err != nil || base != "https://rdap.example.org/" {
		t.Errorf("stale bootstrap not served: %q %v", base, err)
	}
	if n := l.hitsFor("data.iana.org/rdap/dns.json"); n != 1+maxAttempts {
		t.Errorf("refresh attempts = %d", n-1)
	}
	// ...and is not retried immediately.
	_, _ = c.RDAPBase(ctx, "example.org")
	if n := l.hitsFor("data.iana.org/rdap/dns.json"); n != 1+maxAttempts {
		t.Errorf("failed refresh retried at once (%d fetches)", n)
	}
	fail.Store(false)
	l.clock.advance(bootstrapRetry)
	_, _ = c.RDAPBase(ctx, "example.org")
	if n := l.hitsFor("data.iana.org/rdap/dns.json"); n != 2+maxAttempts {
		t.Errorf("refresh not retried after the back-off (%d fetches)", n)
	}
}

func TestRDAPBaseWithoutBootstrap(t *testing.T) {
	huge := append([]byte(`{"services":[[["com"],["https://rdap.example.net/"]]],"pad":"`), bytes.Repeat([]byte("x"), 4096)...)
	huge = append(huge, `"}`...)
	for name, h := range map[string]http.HandlerFunc{
		"unavailable": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) },
		"not found":   func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"malformed":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"services":`)) },
		"huge":        func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(huge) },
	} {
		t.Run(name, func(t *testing.T) {
			l := newLab(t, h)
			c := l.client(Options{Services: map[string]ServiceConfig{ServiceRDAP: {MaxBytes: 1024}}})
			_, err := c.RDAPBase(context.Background(), "example.com")
			if err == nil || errors.Is(err, ErrUnsupported) {
				t.Fatalf("err = %v", err)
			}
			// Without a bootstrap no RDAP server is reachable at all.
			if _, err := c.Get(context.Background(), ServiceRDAP, "https://rdap.example.net/domain/example.com"); err == nil {
				t.Error("rdap host allowed without a bootstrap")
			}
			if n := l.hitsFor("rdap.example.net/domain/example.com"); n != 0 {
				t.Errorf("rdap server contacted %d times", n)
			}
		})
	}
}
