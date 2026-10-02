package refdata

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tlsFetcher(srv *httptest.Server) *Fetcher {
	return &Fetcher{Client: srv.Client(), UserAgent: "deckard-test", Backoff: time.Millisecond, Timeout: 5 * time.Second}
}

func TestGetOKSendsUAAndNoCredentials(t *testing.T) {
	var gotUA, gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotAuth = r.UserAgent(), r.Header.Get("Authorization")
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	res, err := tlsFetcher(srv).Get(context.Background(), srv.URL, Validators{})
	if err != nil || string(res.Body) != "hello" || res.Validators.ETag != `"v1"` {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if gotUA != "deckard-test" || gotAuth != "" {
		t.Errorf("ua=%q auth=%q", gotUA, gotAuth)
	}
}

func TestGetConditional304(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` && r.Header.Get("If-Modified-Since") == "yesterday" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		t.Errorf("missing validators: %v", r.Header)
	}))
	defer srv.Close()
	res, err := tlsFetcher(srv).Get(context.Background(), srv.URL, Validators{ETag: `"v1"`, LastModified: "yesterday"})
	if err != nil || !res.NotModified {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestGetRejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("must not be contacted") }))
	defer srv.Close()
	_, err := (&Fetcher{}).Get(context.Background(), srv.URL, Validators{})
	if !errors.Is(err, ErrNotHTTPS) {
		t.Fatalf("err=%v", err)
	}
}

func TestGetRefusesRedirectToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("must not be followed") }))
	defer plain.Close()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer srv.Close()
	_, err := tlsFetcher(srv).Get(context.Background(), srv.URL, Validators{})
	if !errors.Is(err, ErrNotHTTPS) {
		t.Fatalf("err=%v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("hits=%d: an https-refusal must not be retried", hits.Load())
	}
}

func TestGetFollowsHTTPSRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("b")) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	res, err := tlsFetcher(srv).Get(context.Background(), srv.URL+"/a", Validators{})
	if err != nil || string(res.Body) != "b" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestGetSizeCap(t *testing.T) {
	for name, chunked := range map[string]bool{"content-length": false, "chunked": true} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write([]byte(strings.Repeat("x", 100)))
			}))
			defer srv.Close()
			f := tlsFetcher(srv)
			f.MaxBytes = 50
			if _, err := f.Get(context.Background(), srv.URL, Validators{}); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err=%v", err)
			}
			f.MaxBytes = 100
			if _, err := f.Get(context.Background(), srv.URL, Validators{}); err != nil {
				t.Fatalf("exactly at cap must pass: %v", err)
			}
		})
	}
}

func TestGetRetriesTransient(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, err := tlsFetcher(srv).Get(context.Background(), srv.URL, Validators{})
	if err != nil || string(res.Body) != "ok" || n.Load() != 3 {
		t.Fatalf("res=%+v err=%v n=%d", res, err, n.Load())
	}
}

func TestGetNoRetryOn404AndGivesUp(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, err := tlsFetcher(srv).Get(context.Background(), srv.URL, Validators{}); err == nil || n.Load() != 1 {
		t.Fatalf("err=%v n=%d", err, n.Load())
	}
	n.Store(0)
	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Error(w, "x", 500)
	}))
	defer srv2.Close()
	if _, err := tlsFetcher(srv2).Get(context.Background(), srv2.URL, Validators{}); err == nil || n.Load() != 3 {
		t.Fatalf("err=%v n=%d", err, n.Load())
	}
}

func TestGetContextCancel(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "x", 500)
	}))
	defer srv.Close()
	f := tlsFetcher(srv)
	f.Backoff = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := f.Get(ctx, srv.URL, Validators{}); err == nil {
		t.Fatal("want error")
	}
}
