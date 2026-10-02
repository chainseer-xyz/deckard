// Package headers implements http.headers: security-header, cookie, banner and
// CORS hygiene for owned URLs.
//
// Config keys:
//
//	required_headers []string  header classes to require (default: hsts, csp,
//	                            x-content-type-options, x-frame-options,
//	                            referrer-policy)
//	hsts_min_age     int        minimum acceptable HSTS max-age seconds (default 15552000)
//	timeout_seconds  int        request timeout (default 10)
//	min_severity     string     drop findings below this severity (default
//	                            info, i.e. keep everything)
//
// Header findings are only produced when the response comes from the asset's
// own scheme and host; if the URL redirects elsewhere (e.g. http -> https) the
// destination URL asset is assessed on its own. To avoid reporting the same
// missing headers on both schemes, an http:// URL is evaluated only for "HTTP
// does not redirect to HTTPS" (the security-header set is judged on the https
// URL), and 3xx responses are never judged for headers.
package headers

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "http.headers"

// Check is the http.headers check.
type Check struct{ base map[string]any }

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

// Applies matches owned URL assets.
func (*Check) Applies(a model.Asset) bool {
	return a.Kind == model.KindURL && a.Scope == model.ScopeOwned
}

// Run fetches the URL once (sending a synthetic Origin to test CORS).
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	res := &check.Result{}
	obs := map[string]any{"url": t.Asset.Key}
	defer func() { res.Observations = append(res.Observations, model.ObservationInput{Check: Name, Data: obs}) }()

	u, err := url.Parse(t.Asset.Key)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		obs["error"] = "unsupported url"
		return res, nil
	}
	resp, err := checkutil.Fetch(ctx, t.HTTP, t.Asset.Key, checkutil.FetchOpts{
		Timeout: time.Duration(checkutil.Int(cfg, "timeout_seconds", 10)) * time.Second,
		Header:  http.Header{"Origin": {CORSProbeOrigin}},
		MaxBody: 64 << 10, // body is irrelevant here
	})
	if err != nil {
		obs["error"] = err.Error()
		return res, nil
	}
	fu, _ := url.Parse(resp.FinalURL)
	finalHTTPS := fu != nil && fu.Scheme == "https"
	redirect := resp.Status >= 300 && resp.Status < 400
	if redirect && !finalHTTPS { // redirect that was not followed: does it point at https?
		if loc, err := fu.Parse(resp.Header.Get("Location")); err == nil && loc.Scheme == "https" {
			finalHTTPS = true
		}
	}
	minSev := model.Severity(checkutil.Str(cfg, "min_severity", string(model.SeverityInfo)))
	if !minSev.Valid() {
		minSev = model.SeverityInfo
	}
	defer func() {
		kept := res.Findings[:0]
		for _, f := range res.Findings {
			if f.Severity.AtLeast(minSev) {
				kept = append(kept, f)
			}
		}
		res.Findings = kept
	}()
	obs["status"], obs["final_url"] = resp.Status, resp.FinalURL
	obs["hsts"] = resp.Header.Get("Strict-Transport-Security")
	obs["csp"] = resp.Header.Get("Content-Security-Policy") != ""

	if u.Scheme == "http" {
		if f := NoHTTPSRedirect(t.Asset.Key, finalHTTPS, resp.Status); f != nil {
			res.Findings = append(res.Findings, *f)
		}
	}
	sameOrigin := fu != nil && fu.Scheme == u.Scheme && strings.EqualFold(fu.Host, u.Host)
	// http:// URLs are judged only for the redirect above; redirects carry no content.
	analyse := sameOrigin && u.Scheme == "https" && !redirect
	obs["analysed"] = analyse
	if analyse {
		res.Findings = append(res.Findings, Analyze(
			Input{URL: t.Asset.Key, HTTPS: u.Scheme == "https", Header: resp.Header},
			Config{
				Required:   checkutil.Strings(cfg, "required_headers", DefaultRequired),
				HSTSMinAge: checkutil.Int(cfg, "hsts_min_age", 15552000),
			})...)
	}
	return res, nil
}
