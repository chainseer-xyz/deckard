package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/chainseer-xyz/deckard/internal/api/ui"
)

func get(h http.Handler, method, target string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":               {Data: []byte("<html>spa</html>")},
		"assets/index-Ab12Cd34.js": {Data: []byte("console.log(1)")},
		"favicon.svg":              {Data: []byte("<svg/>")},
		"app-0123456789.css":       {Data: []byte("body{}")},
	}
	h := ui.Handler(fsys)
	tests := []struct {
		name, method, path string
		status             int
		body               string // substring
		cache              string // exact Cache-Control
	}{
		{"root", "GET", "/", 200, "spa", "no-cache"},
		{"index direct", "GET", "/index.html", 200, "spa", "no-cache"},
		{"spa route fallback", "GET", "/findings/42", 200, "spa", "no-cache"},
		{"hashed asset immutable", "GET", "/assets/index-Ab12Cd34.js", 200, "console", "public, max-age=31536000, immutable"},
		{"hashed outside assets", "GET", "/app-0123456789.css", 200, "body", "public, max-age=31536000, immutable"},
		{"plain file short cache", "GET", "/favicon.svg", 200, "svg", "public, max-age=3600"},
		{"missing asset is 404 not html", "GET", "/assets/missing.js", 404, "", ""},
		{"api never falls back", "GET", "/api/v1/nope", 404, "", ""},
		{"api exact", "GET", "/api", 404, "", ""},
		{"auth never falls back", "GET", "/auth/whatever", 404, "", ""},
		{"traversal cleaned", "GET", "/../../etc/passwd", 200, "spa", "no-cache"},
		{"head ok", "HEAD", "/", 200, "", "no-cache"},
		{"post rejected", "POST", "/", 405, "", ""},
		{"directory falls back", "GET", "/assets/", 200, "spa", "no-cache"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(h, tt.method, tt.path)
			if rec.Code != tt.status {
				t.Fatalf("status %d want %d", rec.Code, tt.status)
			}
			if !strings.Contains(rec.Body.String(), tt.body) {
				t.Errorf("body %q lacks %q", rec.Body, tt.body)
			}
			if tt.cache != "" && rec.Header().Get("Cache-Control") != tt.cache {
				t.Errorf("Cache-Control = %q want %q", rec.Header().Get("Cache-Control"), tt.cache)
			}
		})
	}
}

func TestConditionalRequest(t *testing.T) {
	h := ui.Handler(fstest.MapFS{"index.html": {Data: []byte("x")}})
	first := get(h, "GET", "/")
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no etag")
	}
	if rec := get(h, "GET", "/", "If-None-Match", etag); rec.Code != 304 {
		t.Errorf("conditional = %d", rec.Code)
	}
}

func TestPlaceholderWhenNoUIBuilt(t *testing.T) {
	for name, fsys := range map[string]fstest.MapFS{
		"empty":        {},
		"only gitkeep": {".gitkeep": {}},
	} {
		h := ui.Handler(fsys)
		for _, p := range []string{"/", "/some/route"} {
			rec := get(h, "GET", p)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "not built") ||
				!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
				t.Errorf("%s %s: %d %s", name, p, rec.Code, rec.Body)
			}
		}
	}
}

func TestNilFS(t *testing.T) {
	if rec := get(ui.Handler(nil), "GET", "/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "not built") {
		t.Fatalf("nil fs: %d", rec.Code)
	}
}

func TestEmbeddedDefaultIsUsable(t *testing.T) {
	// Whatever is embedded (placeholder dist today, real build later) must serve.
	rec := get(ui.Handler(ui.Default()), "GET", "/")
	if rec.Code != 200 {
		t.Fatalf("default fs: %d", rec.Code)
	}
}
