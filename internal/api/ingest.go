package api

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Ingester applies validated ingest requests; the finding processor
// implements it (finding.Processor.Ingest), filling in Now and ResolveAfter.
type Ingester interface {
	Ingest(ctx context.Context, in store.IngestInput) (store.IngestResult, error)
}

// Results of deckard_ingest_requests_total.
const (
	ingestOK          = "ok"           // applied as sent
	ingestPartial     = "partial"      // applied, but items were rejected or complete was not applied
	ingestReplay      = "replay"       // repeated the last accepted request: no-op
	ingestRejected    = "rejected"     // 422: failed validation, nothing applied
	ingestInvalid     = "invalid"      // 400/415: not a well-formed request
	ingestTooLarge    = "too_large"    // 413
	ingestRateLimited = "rate_limited" // 429
	ingestDisabled    = "disabled"     // 403: ingest.enabled is false
	ingestError       = "error"        // 5xx
)

// ingestMaxToolLabels bounds the tool label of deckard_ingest_requests_total
// for tools not listed in ingest.tools (any write identity can name a tool).
const ingestMaxToolLabels = 32

type ingestState struct {
	sem   chan struct{}
	limit *identityLimiter
	total *prometheus.CounterVec

	mu    sync.Mutex
	tools map[string]bool // unlisted tools given their own label
}

func (s *Server) initIngest() {
	c := &s.d.Ingest
	if c.RateLimit == "" {
		c.RateLimit = "60/m"
	}
	if c.Burst <= 0 {
		c.Burst = 10
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 4
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Minute
	}
	perSec, err := config.ParseRate(c.RateLimit)
	if err != nil || perSec <= 0 {
		s.log.Warn("invalid ingest.rate_limit; using 60/m", "rate_limit", c.RateLimit)
		perSec = 1
	}
	s.ing = &ingestState{
		sem:   make(chan struct{}, c.MaxConcurrent),
		limit: newIdentityLimiter(rate.Limit(perSec), c.Burst),
		tools: map[string]bool{},
	}
}

func (s *Server) registerIngestMetrics() {
	if s.d.Registry == nil {
		return
	}
	total := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deckard_ingest_requests_total",
		Help: "POST /api/v1/ingest requests by tool and result (ok, partial, replay, rejected, invalid, too_large, rate_limited, disabled, error). Tools not listed in ingest.tools share tool=\"other\" past a cap; unparseable bodies count as tool=\"unknown\".",
	}, []string{"tool", "result"})
	if err := s.d.Registry.Register(total); err != nil {
		s.log.Warn("could not register ingest metrics", "err", err)
		return
	}
	// Listed tools start at zero so increase() sees their first failure.
	for tool := range s.d.Ingest.Tools {
		for _, res := range []string{ingestOK, ingestPartial, ingestRejected, ingestInvalid, ingestTooLarge} {
			total.WithLabelValues(tool, res)
		}
	}
	s.ing.total = total
}

func (s *Server) countIngest(tool, result string) {
	if s.ing.total == nil {
		return
	}
	s.ing.total.WithLabelValues(s.ingestToolLabel(tool), result).Inc()
}

func (s *Server) ingestToolLabel(tool string) string {
	switch {
	case tool == "":
		return "unknown"
	case !model.ValidIngestTool(tool):
		return "invalid"
	}
	if _, listed := s.d.Ingest.Tools[tool]; listed {
		return tool
	}
	s.ing.mu.Lock()
	defer s.ing.mu.Unlock()
	if s.ing.tools[tool] || len(s.ing.tools) < ingestMaxToolLabels {
		s.ing.tools[tool] = true
		return tool
	}
	return "other"
}

// ingest handles POST /api/v1/ingest. See internal/ingest and docs/ingest.md
// for the contract; in short: a request that fails validation changes
// nothing, and only a valid, complete, newer run with no rejected item can
// resolve findings.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Ingest
	if !cfg.Enabled {
		s.countIngest("", ingestDisabled)
		writeError(w, http.StatusForbidden, "ingest_disabled", "ingest is disabled on this instance (ingest.enabled)")
		return
	}
	if s.d.Ingester == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "ingest is not available on this instance")
		return
	}
	if newQuery(r).reject(w) {
		s.countIngest("", ingestInvalid)
		return
	}
	ctx := r.Context()
	id := identityFrom(ctx)
	if wait, ok := s.ing.limit.allow(id.Actor(), s.clock.Now()); !ok {
		s.countIngest("", ingestRateLimited)
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many ingest requests for this identity; retry later")
		return
	}
	select {
	case s.ing.sem <- struct{}{}:
		defer func() { <-s.ing.sem }()
	default:
		s.countIngest("", ingestRateLimited)
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "busy", "too many ingest requests in progress; retry later")
		return
	}
	if ct := strings.ToLower(r.Header.Get("Content-Type")); !strings.HasPrefix(ct, "application/json") {
		s.countIngest("", ingestInvalid)
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			s.countIngest("", ingestTooLarge)
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "request body larger than 10 MiB; split the run into several incomplete requests or raise the producer's filtering")
			return
		}
		s.countIngest("", ingestError)
		s.storeError(w, r, err)
		return
	}
	req, err := ingest.Decode(body)
	if err != nil {
		s.countIngest("", ingestInvalid)
		writeError(w, http.StatusBadRequest, "invalid_body", "malformed request: "+err.Error())
		return
	}
	tc := cfg.Tools[req.Tool]
	if problems := ingest.Validate(req, ingest.Options{MaxFindings: tc.MaxFindings, Now: s.clock.Now()}); len(problems) > 0 {
		s.countIngest(req.Tool, ingestRejected)
		var out ingest.ErrorResponse
		out.Error.Code = "invalid_request"
		out.Error.Message = "request rejected, nothing was changed: " + ingest.Summary(problems)
		out.Rejected = problems
		writeJSON(w, http.StatusUnprocessableEntity, out)
		return
	}

	in := store.IngestInput{
		Tool: req.Tool, Scope: req.Scope, Check: model.IngestCheck(req.Tool), Source: model.IngestSource(req.Tool),
		AssetScope: model.ScopeExternal, Complete: req.Complete, ObservedAt: req.ObservedAt.UTC(), Digest: ingest.Digest(req),
		Items: make([]store.IngestItem, len(req.Findings)),
	}
	if tc.Owned {
		in.AssetScope = model.ScopeOwned
	}
	for i, f := range req.Findings {
		it := store.IngestItem{Index: i, AssetKind: f.Asset.Kind, AssetKey: f.Asset.Key, Finding: model.FindingInput{
			Key: f.Key, Severity: f.Severity, Title: f.Title, Description: f.Description,
			Evidence: f.Evidence, Remediation: f.Remediation, Tags: f.Tags,
		}}
		if f.Asset.Ref != nil {
			it.AssetKind, it.AssetKey, it.Ref = f.Asset.Ref.Kind, f.Asset.Ref.Key, true
		}
		in.Items[i] = it
	}
	res, err := s.d.Ingester.Ingest(ctx, in)
	if err != nil {
		s.countIngest(req.Tool, ingestError)
		s.storeError(w, r, err)
		return
	}

	out := ingest.Response{
		Opened: len(res.Opened), Reopened: len(res.Reopened), Refreshed: res.Refreshed - len(res.Reopened),
		ResolvedPending: res.Pending, Resolved: len(res.Resolved), Complete: res.Complete, Replay: res.Replay,
		Note: res.NotCompleteReason, Rejected: make([]ingest.Rejection, 0, len(res.Rejected)),
	}
	for _, rj := range res.Rejected {
		out.Rejected = append(out.Rejected, ingest.Rejection{Index: rj.Index, Reason: rj.Reason})
	}
	result := ingestOK
	switch {
	case res.Replay:
		result = ingestReplay
		out.Note = "same request as the last accepted one for this tool and scope: nothing changed"
	case len(res.Rejected) > 0 || req.Complete && !res.Complete:
		result = ingestPartial
		out.Accepted = len(req.Findings) - len(res.Rejected)
	default:
		out.Accepted = len(req.Findings)
	}
	s.countIngest(req.Tool, result)
	s.log.Info("ingest applied", "tool", req.Tool, "scope", req.Scope, "result", result, "findings", len(req.Findings),
		"opened", out.Opened, "reopened", out.Reopened, "refreshed", out.Refreshed, "resolved", out.Resolved,
		"resolved_pending", out.ResolvedPending, "rejected", len(out.Rejected), "complete", out.Complete, "actor", id.Actor())
	writeJSON(w, http.StatusOK, out)
}

// identityLimiter is a token bucket per identity. The map is bounded: past
// maxIdentities it is reset, which at worst briefly lifts the limit for
// identities that were already throttled.
type identityLimiter struct {
	mu    sync.Mutex
	every rate.Limit
	burst int
	m     map[string]*rate.Limiter
}

const maxIdentities = 10000

func newIdentityLimiter(every rate.Limit, burst int) *identityLimiter {
	return &identityLimiter{every: every, burst: burst, m: map[string]*rate.Limiter{}}
}

// allow takes a token for key at now, or reports the seconds to wait.
func (l *identityLimiter) allow(key string, now time.Time) (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.m[key]
	if !ok {
		if len(l.m) >= maxIdentities {
			l.m = map[string]*rate.Limiter{}
		}
		lim = rate.NewLimiter(l.every, l.burst)
		l.m[key] = lim
	}
	if lim.AllowN(now, 1) {
		return 0, true
	}
	return int(math.Ceil(1 / float64(l.every))), false
}
