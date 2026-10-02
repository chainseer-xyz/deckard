package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/inventory/expand"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Origins passed to Inventory.AddDiscovered.
const (
	OriginExpansionCT  = "expansion:ct"
	OriginExpansionDNS = "expansion:dns"
)

// ExpandRequest asks an Expander to find names under one owned zone.
type ExpandRequest struct {
	Zone string
	CT   bool // query certificate-transparency logs
	DNS  bool // bruteforce the wordlist over DNS
	// Resolver is already scope-guarded (class owned, passive tier) and rate
	// limited; an Expander must do all DNS through it.
	Resolver check.Resolver
	// RatePerSec is the passive per-host rate for bruteforce lookups.
	RatePerSec float64
}

// ExpandResult holds wildcard-filtered candidates. It is valid even when
// Expand also returns an error (a partial result is still worth adding).
type ExpandResult struct {
	CT  []expand.Candidate
	DNS []expand.Candidate
}

// Expander discovers candidate hostnames for a zone. Candidates are only
// candidates: Inventory.AddDiscovered drops everything that is not owned.
type Expander interface {
	Expand(ctx context.Context, req ExpandRequest) (ExpandResult, error)
}

// CTSource lists names seen in CT logs for a zone; *expand.CT satisfies it.
type CTSource interface {
	Names(ctx context.Context, zone string) ([]string, error)
}

// DefaultExpander is the production Expander: CT names and bruteforce results,
// both filtered against wildcard DNS so a wildcard zone cannot flood the
// inventory.
type DefaultExpander struct {
	CT    CTSource
	Words []string
}

func (e *DefaultExpander) Expand(ctx context.Context, req ExpandRequest) (ExpandResult, error) {
	var res ExpandResult
	if req.Resolver == nil {
		return res, errors.New("expand: no resolver")
	}
	var errs []error
	if req.CT && e.CT != nil {
		names, err := e.CT.Names(ctx, req.Zone)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("ct %s: %w", req.Zone, err))
		case len(names) > 0:
			// One wildcard probe per run. If it fails we cannot tell wildcard
			// answers from real names, so add nothing rather than flood.
			info, err := expand.DetectWildcard(ctx, req.Resolver, req.Zone)
			if err != nil {
				errs = append(errs, fmt.Errorf("ct %s: %w", req.Zone, err))
				break
			}
			cands, err := expand.Filter(ctx, req.Resolver, names, info, "ct")
			res.CT = cands
			if err != nil {
				errs = append(errs, fmt.Errorf("ct %s: %w", req.Zone, err))
			}
		}
	}
	if req.DNS && len(e.Words) > 0 && ctx.Err() == nil {
		cands, err := expand.Bruteforce(ctx, req.Resolver, req.Zone, e.Words, req.RatePerSec)
		res.DNS = cands
		if err != nil {
			errs = append(errs, err)
		}
	}
	return res, errors.Join(errs...)
}

// NewCT builds a crt.sh client that identifies itself and honours Retry-After
// on 429 (the wait happens before the client's own backoff retry).
func NewCT(userAgent string) *expand.CT {
	hc := &http.Client{Transport: &politeTransport{base: http.DefaultTransport, maxWait: 2 * time.Minute}}
	return expand.NewCT(expand.WithCTHTTPClient(hc), expand.WithCTUserAgent(userAgent),
		expand.WithCTTimeout(60*time.Second), expand.WithCTRetries(2, 5*time.Second))
}

// politeTransport sleeps for a 429/503 response's Retry-After (capped) before
// handing the response back, so the caller's retry lands after the wait.
type politeTransport struct {
	base    http.RoundTripper
	maxWait time.Duration
	sleep   func(ctx context.Context, d time.Duration) error // test hook
}

func (t *politeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		if d := retryAfter(resp.Header.Get("Retry-After")); d > 0 {
			if d > t.maxWait {
				d = t.maxWait
			}
			sleep := t.sleep
			if sleep == nil {
				sleep = sleepCtx
			}
			if err := sleep(req.Context(), d); err != nil {
				_ = resp.Body.Close()
				return nil, err
			}
		}
	}
	return resp, nil
}

func retryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---- runner ----------------------------------------------------------------

func (e *Engine) expansionEnabled() bool { return e.r.expansionEnabled() }

func (r *runner) expansionEnabled() bool {
	x := r.Config.Expansion
	return r.Expander != nil && x.Interval > 0 && (x.CTLogs || x.DNSBruteforce)
}

// maxExpansionJitter bounds how far a zone's expansion is delayed so zones do
// not all query crt.sh in the same instant.
const maxExpansionJitter = 5 * time.Minute

// ownedZone reports whether a is a live zone asset that the Guard freshly
// classifies as owned and whose passive tier is allowed and enabled.
func (r *runner) ownedZone(a model.Asset) (model.ScopeClass, Resolved, bool) {
	if a.Kind != model.KindZone {
		return "", Resolved{}, false
	}
	class, prof, why := r.scannable(a, model.TierPassive)
	return class, prof, why == "" && class == model.ScopeOwned
}

// scheduleExpansion enqueues one expand_zone job per owned zone. With jitter
// the jobs are spread over a few minutes. It never removes anything.
func (r *runner) scheduleExpansion(ctx context.Context, jitter bool) (int, error) {
	if !r.expansionEnabled() {
		return 0, nil
	}
	assets, _, err := r.Store.ListAssets(ctx, store.AssetFilter{Kind: model.KindZone, Scope: model.ScopeOwned})
	if err != nil {
		return 0, fmt.Errorf("list zones: %w", err)
	}
	maxJ := maxExpansionJitter
	if iv := r.Config.Expansion.Interval / 4; iv < maxJ {
		maxJ = iv
	}
	queued := 0
	for _, a := range assets {
		if _, _, ok := r.ownedZone(a); !ok {
			continue
		}
		var delay time.Duration
		if jitter && maxJ > 0 {
			delay = time.Duration(rand.Int64N(int64(maxJ))) // #nosec G404 -- scheduling jitter, not security sensitive
		}
		ok, err := r.q.enqueueExpand(ctx, a.ID, delay)
		if err != nil {
			return queued, fmt.Errorf("enqueue expansion: %w", err)
		}
		if ok {
			queued++
		}
	}
	if queued > 0 {
		r.log.Debug("scheduled zone expansions", "zones", queued)
	}
	return queued, nil
}

// expandNewZones queues an expansion for zones that just appeared, so a new
// zone is explored now rather than at the next interval. Failures are logged;
// the periodic tick still catches them.
func (r *runner) expandNewZones(ctx context.Context, groups ...[]model.Asset) {
	if !r.expansionEnabled() {
		return
	}
	for _, g := range groups {
		for _, a := range g {
			if _, _, ok := r.ownedZone(a); !ok {
				continue
			}
			if _, err := r.q.enqueueExpand(ctx, a.ID, 0); err != nil {
				r.log.Warn("enqueue expansion", "zone", a.Key, "err", err)
			}
		}
	}
}

// runExpand expands one owned zone and feeds the result to the inventory. It
// only ever adds. Errors (crt.sh down, DNS failures, timeouts) are returned so
// River retries with backoff, after whatever partial result was obtained has
// been added; they never affect other jobs.
func (r *runner) runExpand(ctx context.Context, assetID int64) error {
	if r.Expander == nil {
		return nil
	}
	x := r.Config.Expansion
	if !x.CTLogs && !x.DNSBruteforce {
		return nil
	}
	a, err := r.Store.GetAsset(ctx, assetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("expand: load asset %d: %w", assetID, err)
	}
	class, prof, ok := r.ownedZone(*a)
	if !ok {
		r.log.Info("expansion skipped: not an owned, live zone with passive scanning enabled", "asset", a.Key, "class", class)
		return nil
	}
	zone := normName(a.Key)
	limiter := r.limiters.get(model.TierPassive, prof.RatePerSec)
	req := ExpandRequest{
		Zone: zone, CT: x.CTLogs, DNS: x.DNSBruteforce, RatePerSec: prof.RatePerSec,
		Resolver: r.Guard.Resolver(model.TierPassive, class, limiter),
	}
	res, xerr := r.Expander.Expand(ctx, req)

	var errs []error
	if xerr != nil {
		r.log.Warn("expansion incomplete", "zone", zone, "err", xerr)
		errs = append(errs, fmt.Errorf("expand %s: %w", zone, xerr))
	}
	for _, g := range []struct {
		origin string
		cands  []expand.Candidate
	}{{OriginExpansionCT, res.CT}, {OriginExpansionDNS, res.DNS}} {
		if len(g.cands) == 0 {
			continue
		}
		if err := r.addInputs(context.WithoutCancel(ctx), g.origin, expand.AssetInputs(g.cands, g.origin)); err != nil {
			errs = append(errs, fmt.Errorf("expand %s: add discovered: %w", zone, err))
		}
	}
	r.log.Info("expansion complete", "zone", zone, "ct", len(res.CT), "dns", len(res.DNS), "failed", xerr != nil)
	return errors.Join(errs...)
}

// addInputs adds discovered assets and queues immediate scans for new ones.
func (r *runner) addInputs(ctx context.Context, origin string, in []model.AssetInput) error {
	diff, err := r.Inventory.AddDiscovered(ctx, origin, in, nil)
	if err != nil {
		return err
	}
	r.reportDiff(diff)
	r.enqueueImmediate(ctx, diff.Added, diff.Revived)
	return nil
}
