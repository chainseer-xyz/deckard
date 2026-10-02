// Package ui serves the embedded single-page app.
package ui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Default returns the embedded dist directory (may contain only .gitkeep when
// the UI has not been built).
func Default() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	return sub
}

const placeholder = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>deckard</title>
<style>body{font:16px system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#222}
code{background:#eee;padding:.1em .3em;border-radius:3px}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}code{background:#222}}</style>
</head><body><h1>deckard</h1>
<p>The web UI is not built into this binary. The API is available under <code>/api/v1/</code>
(spec at <code>/api/v1/openapi.yaml</code>).</p></body></html>`

// hashed matches Vite-style fingerprinted filenames such as index-Ab12Cd34.js.
var hashed = regexp.MustCompile(`[-.][A-Za-z0-9_]{8,}\.[A-Za-z0-9]+$`)

// Handler serves fsys as an SPA: existing files are served directly,
// extensionless unknown paths fall back to index.html (history API routing),
// and /api and /auth are never shadowed. A missing index.html yields a small
// placeholder page instead of an error.
func Handler(fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if reserved(p) {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(p, "/")
		if name == "" {
			name = "index.html"
		}
		if name != "index.html" {
			if data, ok := readFile(fsys, name); ok {
				cache := "public, max-age=3600"
				if strings.HasPrefix(name, "assets/") || hashed.MatchString(name) {
					cache = "public, max-age=31536000, immutable"
				}
				serve(w, r, name, data, cache)
				return
			}
			// A missing file with an extension is a real 404, not an SPA route.
			if strings.Contains(path.Base(name), ".") {
				http.NotFound(w, r)
				return
			}
		}
		if data, ok := readFile(fsys, "index.html"); ok {
			serve(w, r, "index.html", data, "no-cache")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(placeholder))
	})
}

func reserved(p string) bool {
	for _, prefix := range []string{"/api", "/auth"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func readFile(fsys fs.FS, name string) ([]byte, bool) {
	if fsys == nil || !fs.ValidPath(name) {
		return nil, false
	}
	st, err := fs.Stat(fsys, name)
	if err != nil || st.IsDir() {
		return nil, false
	}
	data, err := fs.ReadFile(fsys, name)
	return data, err == nil
}

func serve(w http.ResponseWriter, r *http.Request, name string, data []byte, cache string) {
	sum := sha256.Sum256(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
	w.Header().Set("Cache-Control", cache)
	http.ServeContent(w, r, name, zeroTime, bytes.NewReader(data))
}
