// Package api is deckard's HTTP layer: REST + SSE endpoints, authentication
// middleware and the embedded UI.
package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/ui"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Clock abstracts time for tests.
type Clock = auth.Clock

// Errors Actions implementations may return; the API maps them to statuses.
var (
	ErrNotSupported  = errors.New("action not supported")
	ErrUnknownSource = errors.New("unknown source")
	ErrBusy          = errors.New("already in progress")
	ErrNotScannable  = errors.New("asset has no applicable checks")
)

// Actions are operator-triggered operations the API delegates to the engine.
// Implementations must enqueue and return promptly; the API reports 202.
type Actions interface {
	RescanAsset(ctx context.Context, assetID int64) error
	TriggerSync(ctx context.Context, source string) error
}

// NoActions is the default Actions: every call returns ErrNotSupported.
type NoActions struct{}

// RescanAsset implements Actions.
func (NoActions) RescanAsset(context.Context, int64) error { return ErrNotSupported }

// TriggerSync implements Actions.
func (NoActions) TriggerSync(context.Context, string) error { return ErrNotSupported }

// Deps are the Server's collaborators.
type Deps struct {
	Store store.Store
	Auth  config.AuthConfig
	// AuthOptions carries SessionSecretEnv, Getenv, Discover and SessionTTL.
	// BaseURL, Clock and Logger are filled in from Deps.
	AuthOptions auth.Options
	// Authenticator overrides the one built from Auth (tests, embedding).
	Authenticator auth.Authenticator
	BaseURL       string
	Actions       Actions
	Clock         Clock
	Logger        *slog.Logger
	// Registry, when set, receives HTTP request metrics.
	Registry prometheus.Registerer
	// Broadcaster wakes SSE streams on changes; optional.
	Broadcaster *Broadcaster
	// UIFS overrides the embedded UI (tests).
	UIFS fs.FS
	// CORSOrigins is empty by default (CORS off).
	CORSOrigins []string

	// Ingester applies POST /api/v1/ingest (finding.Processor); nil answers
	// 501. Ingest is its policy: the zero value is disabled (403).
	Ingester Ingester
	Ingest   config.IngestConfig

	// Tunables; zero values pick defaults.
	RequestTimeout   time.Duration // default 30s
	MaxBodyBytes     int64         // default 64KiB
	SSEPollInterval  time.Duration // default 5s
	SSEHeartbeat     time.Duration // default 15s
	SSEReplayWindow  time.Duration // default 24h; how far back Last-Event-ID can replay
	ReadyzTimeout    time.Duration // default 2s
	ShutdownTimeout  time.Duration // default 10s
	MaxGraphNodes    int           // default 500
	MaxFindingsEmbed int           // default 200

	// SSE admission limits; over either, /events answers 429 + Retry-After.
	MaxSSEStreams            int           // default 100 (global)
	MaxSSEStreamsPerIdentity int           // default 10
	SSEMinDrainInterval      time.Duration // default 250ms; floor between broadcaster-triggered store reads per stream
}

// Server is the HTTP API.
type Server struct {
	d       Deps
	log     *slog.Logger
	clock   Clock
	authn   auth.Authenticator
	authErr error
	router  *chi.Mux
	sse     *sseGate
	ing     *ingestState

	reqTotal *prometheus.CounterVec
	reqDur   *prometheus.HistogramVec
}

// New builds the server. If authentication is misconfigured (for example a
// missing token or session secret) the server still starts but fails closed:
// every authenticated endpoint returns 503. Check Err to fail fast.
func New(d Deps) *Server {
	s := &Server{d: d, log: d.Logger, clock: d.Clock}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.clock == nil {
		s.clock = auth.SystemClock{}
	}
	if d.Actions == nil {
		s.d.Actions = NoActions{}
	}
	def := func(p *time.Duration, v time.Duration) {
		if *p <= 0 {
			*p = v
		}
	}
	def(&s.d.RequestTimeout, 30*time.Second)
	def(&s.d.SSEPollInterval, 5*time.Second)
	def(&s.d.SSEHeartbeat, 15*time.Second)
	def(&s.d.SSEReplayWindow, 24*time.Hour)
	def(&s.d.ReadyzTimeout, 2*time.Second)
	def(&s.d.ShutdownTimeout, 10*time.Second)
	if s.d.MaxBodyBytes <= 0 {
		s.d.MaxBodyBytes = 64 << 10
	}
	if s.d.MaxGraphNodes <= 0 {
		s.d.MaxGraphNodes = 500
	}
	if s.d.MaxFindingsEmbed <= 0 {
		s.d.MaxFindingsEmbed = 200
	}
	if s.d.MaxSSEStreams <= 0 {
		s.d.MaxSSEStreams = 100
	}
	if s.d.MaxSSEStreamsPerIdentity <= 0 {
		s.d.MaxSSEStreamsPerIdentity = 10
	}
	def(&s.d.SSEMinDrainInterval, 250*time.Millisecond)
	s.sse = newSSEGate(s.d.MaxSSEStreams, s.d.MaxSSEStreamsPerIdentity)

	s.authn = d.Authenticator
	if s.authn == nil {
		opts := d.AuthOptions
		opts.BaseURL, opts.Clock, opts.Logger = d.BaseURL, s.clock, s.log
		a, err := auth.New(d.Auth, opts)
		if err != nil {
			s.authErr = err
			s.log.Error("authentication misconfigured; API fails closed", "err", err)
			a = auth.Deny{}
		}
		s.authn = a
	}
	s.initIngest()
	s.registerMetrics()
	s.registerIngestMetrics()
	s.router = s.routes()
	return s
}

// Err reports an authentication configuration error, if any.
func (s *Server) Err() error { return s.authErr }

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.router }

func (s *Server) registerMetrics() {
	if s.d.Registry == nil {
		return
	}
	s.reqTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deckard_http_requests_total", Help: "HTTP requests by method, route pattern and status code.",
	}, []string{"method", "route", "code"})
	s.reqDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "deckard_http_request_duration_seconds", Help: "HTTP request duration by method and route pattern.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})
	for _, c := range []prometheus.Collector{s.reqTotal, s.reqDur} {
		if err := s.d.Registry.Register(c); err != nil {
			s.log.Warn("could not register http metrics", "err", err)
			s.reqTotal, s.reqDur = nil, nil
			return
		}
	}
}

func (s *Server) observeHTTP(method, route string, status int, d time.Duration) {
	if s.reqTotal == nil {
		return
	}
	s.reqTotal.WithLabelValues(method, route, statusClass(status)).Inc()
	s.reqDur.WithLabelValues(method, route).Observe(d.Seconds())
}

func statusClass(code int) string {
	return strconv.Itoa(code/100) + "xx"
}

func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()
	r.Use(requestID, s.accessLog, s.recoverer,
		securityHeaders(strings.HasPrefix(s.d.BaseURL, "https://")),
		cors(s.d.CORSOrigins), gzipMiddleware)

	uiFS := s.d.UIFS
	if uiFS == nil {
		uiFS = ui.Default()
	}
	uiHandler := ui.Handler(uiFS)
	api404 := func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/api" || strings.HasPrefix(p, "/api/") || p == "/auth" || strings.HasPrefix(p, "/auth/") {
			w.Header().Set("Cache-Control", "no-store")
			writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
			return
		}
		uiHandler.ServeHTTP(w, r)
	}
	r.NotFound(api404)
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		uiHandler.ServeHTTP(w, r)
	})

	// Unauthenticated probes.
	r.Get("/healthz", s.healthz)
	r.Get("/readyz", s.readyz)

	if m, ok := s.authn.(auth.Router); ok {
		r.Group(func(r chi.Router) {
			r.Use(noStore)
			m.Mount(r)
		})
	}

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(noStore, s.authenticate)

		// Ingest carries up to 10 MiB and may write thousands of rows: its
		// own body cap and timeout. It is a write like the operator actions.
		r.Group(func(r chi.Router) {
			r.Use(maxBody(ingest.MaxBodyBytes), timeout(s.d.Ingest.Timeout), s.csrf)
			r.Post("/ingest", s.ingest)
		})

		r.Group(func(r chi.Router) {
			r.Use(maxBody(s.d.MaxBodyBytes))

			// Streaming endpoint: no request timeout.
			r.Get("/events", s.events)

			r.Group(func(r chi.Router) {
				r.Use(timeout(s.d.RequestTimeout))
				r.Get("/me", s.me)
				r.Get("/openapi.yaml", s.openapi)
				r.Get("/stats", s.stats)
				r.Get("/assets", s.listAssets)
				r.Get("/assets/{id}", s.getAsset)
				r.Get("/assets/{id}/graph", s.assetGraph)
				r.Get("/findings", s.listFindings)
				r.Get("/findings/{id}", s.getFinding)
				r.Get("/sources", s.listSources)
				r.Get("/scans", s.listScans)
				r.Get("/changes", s.changes)

				r.Group(func(r chi.Router) {
					r.Use(s.csrf)
					r.Post("/findings/{id}/acknowledge", s.findingAction("acknowledge"))
					r.Post("/findings/{id}/suppress", s.findingAction("suppress"))
					r.Post("/findings/{id}/false-positive", s.findingAction("false-positive"))
					r.Post("/findings/{id}/reopen", s.findingAction("reopen"))
					r.Post("/assets/{id}/rescan", s.rescanAsset)
					r.Post("/sources/{name}/sync", s.syncSource)
				})
			})
		})
	})
	return r
}

// authenticate resolves the caller or rejects with 401.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authErr != nil {
			writeError(w, http.StatusServiceUnavailable, "auth_misconfigured", "authentication is not configured correctly")
			return
		}
		id, err := s.authn.Authenticate(r)
		if err != nil || id == nil {
			if s.authn.Mode() == "token" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="deckard"`)
			}
			msg := "authentication required"
			if s.authn.Mode() == "oidc" {
				msg = "authentication required; sign in at /auth/login"
			}
			writeError(w, http.StatusUnauthorized, "unauthenticated", msg)
			return
		}
		if li, ok := r.Context().Value(ctxLogInfo).(*logInfo); ok {
			li.actor = id.Actor()
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxIdentity, id)))
	})
}

// csrf enforces the double-submit header for cookie-authenticated
// state-changing requests. Bearer-token and proxy-authenticated callers are
// not ambient-credential clients and are exempt.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identityFrom(r.Context())
		if id != nil && id.Method == auth.MethodCookie {
			got := r.Header.Get("X-CSRF-Token")
			if got == "" || id.CSRFToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(id.CSRFToken)) != 1 {
				writeError(w, http.StatusForbidden, "csrf", "missing or invalid X-CSRF-Token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func identityFrom(ctx context.Context) *auth.Identity {
	id, _ := ctx.Value(ctxIdentity).(*auth.Identity)
	return id
}

// Serve runs the API on ln until ctx is cancelled, then drains gracefully.
// Active SSE streams end when ctx is cancelled (it is the request base context).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: it would sever SSE streams.
		BaseContext: func(net.Listener) context.Context { return ctx },
		ErrorLog:    slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	done := make(chan struct{})
	go func() { // #nosec G118 -- shutdown must outlive the cancelled request context
		defer close(done)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), s.d.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			_ = srv.Close()
		}
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

// ListenAndServe listens on addr and calls Serve.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}
