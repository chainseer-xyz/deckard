package gcpdns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const fakeToken = "ya29.fake-access-token-do-not-log"

type staticTokens struct{ err error }

func (s staticTokens) Token() (*oauth2.Token, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &oauth2.Token{AccessToken: fakeToken, TokenType: "Bearer"}, nil
}

func testClient(t *testing.T, h http.Handler, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	all := append([]Option{
		WithBaseURL(srv.URL + "/dns/v1"), WithRetry(3, time.Millisecond, 20*time.Millisecond), WithRateLimit(0),
	}, opts...)
	return NewClient(staticTokens{}, all...), srv
}

func TestClientListsEveryPageWithAuth(t *testing.T) {
	var calls atomic.Int32
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer "+fakeToken {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path != "/dns/v1/projects/my-project-a/managedZones" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("maxResults") == "" {
			t.Error("maxResults not set")
		}
		switch r.URL.Query().Get("pageToken") {
		case "":
			_, _ = fmt.Fprint(w, `{"managedZones":[{"name":"z1","dnsName":"a.example.com.","id":"111"}],"nextPageToken":"p2"}`)
		case "p2":
			_, _ = fmt.Fprint(w, `{"managedZones":[{"name":"z2","dnsName":"b.example.com.","id":222,"dnssecConfig":{"state":"on"}}],"nextPageToken":"p3"}`)
		case "p3":
			_, _ = fmt.Fprint(w, `{"managedZones":[{"name":"z3","dnsName":"c.example.com.","visibility":"private"}]}`)
		default:
			t.Errorf("unexpected pageToken %q", r.URL.Query().Get("pageToken"))
		}
	}))
	zs, err := c.ListManagedZones(context.Background(), "my-project-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(zs) != 3 || zs[0].Name != "z1" || zs[1].ID.String() != "222" || zs[1].DNSSECConfig.State != "on" || zs[2].Visibility != "private" {
		t.Fatalf("zones: %+v", zs)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
}

func TestClientListRRSetsPaginatesAndDecodesPolicies(t *testing.T) {
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns/v1/projects/my-project-a/managedZones/prod-zone/rrsets" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("pageToken") == "" {
			_, _ = fmt.Fprint(w, `{"rrsets":[{"name":"www.example.com.","type":"A","ttl":300,"rrdatas":["192.0.2.10"]}],"nextPageToken":"n"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"rrsets":[{"name":"lb.example.com.","type":"A","routingPolicy":{"wrr":{"items":[
			{"weight":1,"rrdatas":["192.0.2.1"]},
			{"weight":2,"healthCheckedTargets":{"internalLoadBalancers":[{"ipAddress":"10.0.0.5","project":"p","region":"r"}]}}]}}}]}`)
	}))
	rs, err := c.ListRRSets(context.Background(), "my-project-a", "prod-zone")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].RRDatas[0] != "192.0.2.10" {
		t.Fatalf("rrsets: %+v", rs)
	}
	items := rs[1].RoutingPolicy.WRR.Items
	if len(items) != 2 || items[0].RRDatas[0] != "192.0.2.1" || items[1].HealthCheckedTargets.InternalLoadBalancers[0].IPAddress != "10.0.0.5" {
		t.Fatalf("routing policy not decoded: %+v", rs[1].RoutingPolicy)
	}
}

func TestClientRetriesTooManyRequestsHonouringRetryAfter(t *testing.T) {
	var calls atomic.Int32
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "3600") // capped by WithRetry's maxWait
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, `{"error":{"code":429,"message":"slow down","status":"RESOURCE_EXHAUSTED"}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"managedZones":[{"name":"z","dnsName":"example.com."}]}`)
	}))
	start := time.Now()
	zs, err := c.ListManagedZones(context.Background(), "p-project-1")
	if err != nil || len(zs) != 1 {
		t.Fatalf("zs=%v err=%v", zs, err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
	if time.Since(start) > 5*time.Second {
		t.Error("an absurd Retry-After must be capped")
	}
}

func TestClientRetriesServerErrorsThenGivesUp(t *testing.T) {
	t.Run("recovers", func(t *testing.T) {
		var calls atomic.Int32
		c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) < 3 {
				http.Error(w, "backend error", http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprint(w, `{"rrsets":[]}`)
		}))
		if _, err := c.ListRRSets(context.Background(), "p-project-1", "z"); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 3 {
			t.Errorf("calls = %d, want 3", calls.Load())
		}
	})
	t.Run("exhausted", func(t *testing.T) {
		var calls atomic.Int32
		c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"error":{"code":503,"message":"unavailable"}}`)
		}))
		_, err := c.ListRRSets(context.Background(), "p-project-1", "z")
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != 503 {
			t.Fatalf("want APIError 503, got %v", err)
		}
		if calls.Load() != 4 { // 1 + 3 retries
			t.Errorf("calls = %d, want 4", calls.Load())
		}
	})
}

func TestClientDoesNotRetryClientErrors(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusBadRequest, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"Cloud DNS API has not been used in project my-project-a","status":"PERMISSION_DENIED"}}`, status)
			}))
			_, err := c.ListManagedZones(context.Background(), "my-project-a")
			var ae *APIError
			if !errors.As(err, &ae) || ae.Status != status {
				t.Fatalf("want APIError %d, got %v", status, err)
			}
			if ae.Denied() != (status == 403 || status == 404) {
				t.Errorf("Denied() = %v for %d", ae.Denied(), status)
			}
			if !strings.Contains(ae.Error(), "Cloud DNS API has not been used") {
				t.Errorf("upstream message lost: %v", ae)
			}
			if calls.Load() != 1 {
				t.Errorf("calls = %d, client errors must not be retried", calls.Load())
			}
		})
	}
}

// truncated answers 200 with a Content-Length it does not honour.
func truncated(w http.ResponseWriter) {
	w.Header().Set("Content-Length", "500")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `{"managedZones":[{"name":"z`)
}

func TestClientTruncatedBody(t *testing.T) {
	t.Run("retried then ok", func(t *testing.T) {
		var calls atomic.Int32
		c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				truncated(w)
				return
			}
			_, _ = fmt.Fprint(w, `{"managedZones":[{"name":"z","dnsName":"example.com."}]}`)
		}))
		zs, err := c.ListManagedZones(context.Background(), "p-project-1")
		if err != nil || len(zs) != 1 {
			t.Fatalf("zs=%v err=%v", zs, err)
		}
	})
	t.Run("always truncated is an error, never a short list", func(t *testing.T) {
		c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { truncated(w) }))
		zs, err := c.ListManagedZones(context.Background(), "p-project-1")
		if err == nil || zs != nil {
			t.Fatalf("want error and no zones, got %v %v", zs, err)
		}
	})
	t.Run("malformed JSON is final", func(t *testing.T) {
		var calls atomic.Int32
		c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			_, _ = fmt.Fprint(w, `{"managedZones": [`)
		}))
		if _, err := c.ListManagedZones(context.Background(), "p-project-1"); err == nil || !strings.Contains(err.Error(), "decode") {
			t.Fatalf("want decode error, got %v", err)
		}
	})
}

func TestClientBoundsResponseSize(t *testing.T) {
	var calls atomic.Int32
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		chunk := []byte(strings.Repeat(" ", 1<<20))
		for range maxBody/(1<<20) + 2 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	zs, err := c.ListManagedZones(context.Background(), "p-project-1")
	if err == nil || !strings.Contains(err.Error(), "exceeds") || zs != nil {
		t.Fatalf("want size error, got %v %v", zs, err)
	}
	if calls.Load() != 1 {
		t.Errorf("an oversized body must not be retried, calls = %d", calls.Load())
	}
}

func TestClientDetectsPaginationLoop(t *testing.T) {
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"rrsets":[],"nextPageToken":"same"}`)
	}))
	if _, err := c.ListRRSets(context.Background(), "p-project-1", "z"); err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("want pagination loop error, got %v", err)
	}
}

func TestClientRateLimit(t *testing.T) {
	var calls atomic.Int32
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, `{"rrsets":[]}`)
	}), WithRateLimit(50))
	start := time.Now()
	for range 6 {
		if _, err := c.ListRRSets(context.Background(), "p-project-1", "z"); err != nil {
			t.Fatal(err)
		}
	}
	// 6 requests at 50/s with burst 1: the 5 waits take at least ~100ms.
	if el := time.Since(start); el < 80*time.Millisecond {
		t.Errorf("6 requests took %v; the rate limit is not applied", el)
	}
}

func TestClientContextCancelDuringBackoff(t *testing.T) {
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}), WithRetry(5, time.Hour, time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.ListManagedZones(ctx, "p-project-1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"": 0, "5": 5 * time.Second, "-3": 0, "junk": 0,
		now.Add(90 * time.Second).Format(http.TimeFormat): 90 * time.Second,
		now.Add(-time.Minute).Format(http.TimeFormat):     0,
	} {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
}

func TestClientNeverLeaksCredentials(t *testing.T) {
	leaks := func(t *testing.T, err error, secrets ...string) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, s := range secrets {
			if strings.Contains(err.Error(), s) {
				t.Errorf("error leaks %q: %v", s, err)
			}
		}
	}

	t.Run("upstream echoes the bearer token", func(t *testing.T) {
		c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, `{"error":{"code":403,"message":"bad credential %s (%s)"}}`, r.Header.Get("Authorization"), fakeToken)
		}))
		_, err := c.ListManagedZones(context.Background(), "p-project-1")
		leaks(t, err, fakeToken, "Bearer ya29")
	})

	t.Run("transport failure does not print the url query", func(t *testing.T) {
		var calls atomic.Int32
		c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				_, _ = fmt.Fprint(w, `{"rrsets":[],"nextPageToken":"SECRET-PAGE-TOKEN"}`)
				return
			}
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}))
		_, err := c.ListRRSets(context.Background(), "p-project-1", "z")
		leaks(t, err, "SECRET-PAGE-TOKEN", "pageToken", "?")
	})

	t.Run("token source failure is redacted", func(t *testing.T) {
		raw := errors.New(`oauth2: cannot fetch token: {"refresh_token":"1//abc-refresh","private_key":"-----BEGIN KEY-----", "access_token": "` + fakeToken + `"} Authorization: Bearer ` + fakeToken)
		c := NewClient(staticTokens{err: raw}, WithBaseURL("http://127.0.0.1:1"), WithRateLimit(0))
		_, err := c.ListManagedZones(context.Background(), "p-project-1")
		leaks(t, err, fakeToken, "1//abc-refresh", "BEGIN KEY")
		var ce *CredentialsError
		if !errors.As(err, &ce) {
			t.Errorf("want CredentialsError, got %T", err)
		}
	})
}
