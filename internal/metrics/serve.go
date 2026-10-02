package metrics

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler returns the /metrics handler for reg.
func Handler(reg prometheus.Gatherer) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// Option customises Serve and ServeListener.
type Option func(*serveOpts)

type serveOpts struct{ token string }

// WithToken requires "Authorization: Bearer <token>" on /metrics. An empty
// token leaves the endpoint open (the default; rely on network policy).
func WithToken(token string) Option { return func(o *serveOpts) { o.token = token } }

// RequireToken wraps h so only requests bearing token are served. The compare
// is constant-time over fixed-size digests, so neither content nor length leaks.
func RequireToken(h http.Handler, token string) http.Handler {
	if token == "" {
		return h
	}
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, val, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		got := sha256.Sum256([]byte(strings.TrimSpace(val)))
		if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="deckard-metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Serve listens on addr and serves /metrics until ctx is cancelled.
func Serve(ctx context.Context, addr string, reg prometheus.Gatherer, opts ...Option) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ServeListener(ctx, ln, reg, opts...)
}

// ServeListener serves /metrics on ln until ctx is cancelled, then shuts down
// gracefully. A clean shutdown returns nil.
func ServeListener(ctx context.Context, ln net.Listener, reg prometheus.Gatherer, opts ...Option) error {
	var o serveOpts
	for _, f := range opts {
		f(&o)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", RequireToken(Handler(reg), o.token))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() { // #nosec G118 -- shutdown must outlive the cancelled request context
		defer close(done)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}
