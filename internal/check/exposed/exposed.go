// Package exposed implements http.exposed: a curated, read-only probe for
// well-known exposure paths (.git, .env, backups, debug endpoints, directory
// listings). Every hit must pass strict content validation, soft-404 pages
// are filtered, bodies are capped at 64 KiB and secret values are never
// stored: evidence carries key names only.
package exposed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const (
	checkName   = "http.exposed"
	maxBodySize = 64 << 10
)

// Checks returns the http.exposed check. defaults is the global per-check
// config map; Target.Config overlays it at run time.
func Checks(defaults map[string]map[string]any) []check.Check {
	return []check.Check{&exposedCheck{defaults: defaults[checkName]}}
}

type exposedCheck struct{ defaults map[string]any }

func (*exposedCheck) Name() string     { return checkName }
func (*exposedCheck) Tier() model.Tier { return model.TierActive }
func (*exposedCheck) Applies(a model.Asset) bool {
	return a.Kind == model.KindURL && a.Scope != model.ScopeExcluded && a.Scope != model.ScopeExternal
}

// response is the capped result of one GET.
type response struct {
	status int
	ctype  string
	body   []byte
	size   int
	hash   string
}

func fetch(ctx context.Context, c *http.Client, u string) (*response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "deckard-audit/1")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// A redirect to a different path (e.g. a login page) is not the resource.
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Path != req.URL.Path {
		return &response{status: 0}, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return &response{status: resp.StatusCode, ctype: resp.Header.Get("Content-Type"), body: body,
		size: len(body), hash: hex.EncodeToString(sum[:])}, nil
}

func randomPath() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "/deckard-nf-" + hex.EncodeToString(b)
}

// isSoft404 reports whether r looks like the site's catch-all response.
func isSoft404(r, nf *response) bool {
	if nf == nil || nf.status == 0 || r.status != nf.status {
		return false
	}
	return r.hash == nf.hash || r.size == nf.size
}

func (c *exposedCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if t.HTTP == nil {
		return nil, fmt.Errorf("http.exposed: no HTTP client in target")
	}
	base, err := baseURL(t.Asset.Key)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	for k, v := range c.defaults {
		cfg[k] = v
	}
	for k, v := range t.Config {
		cfg[k] = v
	}
	skip := stringSet(cfg["exclude_paths"])
	delay := durationOf(cfg["delay"])

	nf, err := fetch(ctx, t.HTTP, base+randomPath())
	if err != nil {
		return nil, fmt.Errorf("http.exposed: %w", err)
	}
	res := &check.Result{}
	var hits []string
	checked := 0
	for _, p := range probes {
		if skip[p.path] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		checked++
		r, err := fetch(ctx, t.HTTP, base+p.path)
		if err != nil || r.status != http.StatusOK || isSoft404(r, nf) {
			continue
		}
		ev, ok := p.validate(r)
		if !ok {
			continue
		}
		hits = append(hits, p.path)
		res.Findings = append(res.Findings, p.finding(base, r, ev))
	}
	res.Observations = []model.ObservationInput{{Check: checkName, Data: map[string]any{
		"checked": checked, "exposed": nonNil(hits), "soft_404": nf.status == http.StatusOK,
	}}}
	return res, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func baseURL(key string) (string, error) {
	u, err := url.Parse(key)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", fmt.Errorf("http.exposed: asset key %q is not an http(s) URL", key)
	}
	return u.Scheme + "://" + u.Host, nil
}

func stringSet(v any) map[string]bool {
	out := map[string]bool{}
	switch l := v.(type) {
	case []string:
		for _, s := range l {
			out[s] = true
		}
	case []any:
		for _, s := range l {
			out[fmt.Sprint(s)] = true
		}
	}
	return out
}

func durationOf(v any) time.Duration {
	switch d := v.(type) {
	case time.Duration:
		return d
	case string:
		if x, err := time.ParseDuration(d); err == nil {
			return x
		}
	case int:
		return time.Duration(d) * time.Millisecond
	}
	return 0
}

func (p probe) finding(base string, r *response, ev map[string]any) model.FindingInput {
	e := map[string]any{"url": base + p.path, "status": r.status, "content_type": r.ctype, "size": r.size}
	for k, v := range ev {
		e[k] = v
	}
	return model.FindingInput{
		Check: checkName, Key: p.path, Severity: p.severity, Title: p.title,
		Description: p.desc + " The response was validated against the expected content; values are not stored.",
		Evidence:    e, Remediation: p.fix, Tags: append([]string{"http", "exposure"}, p.tags...),
	}
}
