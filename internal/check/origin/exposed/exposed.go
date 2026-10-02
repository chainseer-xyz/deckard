// Package exposed implements origin.exposed: an origin IP that sits behind a
// CDN/WAF proxy but still answers directly on 80/443, letting attackers bypass
// the proxy's protections.
//
// For each hostname related to the origin IP the check makes one request
// through the normal (proxied) path to learn what the real site looks like,
// then at most one direct connection per configured port to the origin IP
// with that hostname as Host/SNI, and compares status and title. Only owned
// IPs flagged attrs.origin=true are contacted, via the scope-guarded Dialer.
//
// Config keys:
//
//	ports            []int  origin ports to try directly (default [443 80])
//	max_hostnames    int    cap on related hostnames tried (default 5)
//	timeout_seconds  int    per-connection timeout (default 10)
package exposed

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/check/http/probe"
	"github.com/chainseer-xyz/deckard/internal/check/origin/correlation"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "origin.exposed"

// Page is the comparable summary of an HTTP response.
type Page struct {
	Status   int
	Title    string
	BodyHash [32]byte
}

// Summarise builds a Page from a response body.
func Summarise(status int, body []byte) Page {
	return Page{Status: status, Title: probe.ExtractTitle(body), BodyHash: sha256.Sum256(body)}
}

func tokens(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(strings.ToLower(s)) {
		m[w] = true
	}
	return m
}

// TitleSimilarity is the Jaccard similarity of the title word sets (0..1).
func TitleSimilarity(a, b string) float64 {
	ta, tb := tokens(a), tokens(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	inter := 0
	for w := range ta {
		if tb[w] {
			inter++
		}
	}
	return float64(inter) / float64(len(ta)+len(tb)-inter)
}

// Similar reports whether the direct response looks like the real site.
// Error responses never count: a default 4xx/5xx page is not "the site".
func Similar(expected, got Page) bool {
	if expected.Status >= 400 || got.Status != expected.Status {
		return false
	}
	if expected.Title != "" || got.Title != "" {
		return TitleSimilarity(expected.Title, got.Title) >= 0.8
	}
	return expected.BodyHash == got.BodyHash
}

// Check is the origin.exposed check.
type Check struct{ base map[string]any }

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

// Applies matches owned IPs flagged as an origin behind a proxy.
func (*Check) Applies(a model.Asset) bool {
	v, _ := a.Attrs["origin"].(bool)
	return a.Kind == model.KindIP && a.Scope == model.ScopeOwned && v
}

func relatedHostnames(t check.Target, max int) []string {
	set := map[string]bool{}
	for _, n := range t.Neighbours {
		if n.Asset.Kind == model.KindHostname {
			set[checkutil.Norm(n.Asset.Key)] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// direct sends one GET to ip:port with Host=hostname and returns the page.
func direct(ctx context.Context, d check.Dialer, ip string, port int, hostname string, timeout time.Duration) (Page, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return Page{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if port == 443 || port == 8443 {
		// Only the response's look matters here, not certificate validity.
		tc := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) // #nosec G402 -- origin probe must accept any certificate to compare content
		if err := tc.HandshakeContext(ctx); err != nil {
			return Page{}, fmt.Errorf("tls: %w", err)
		}
		conn = tc
	}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", hostname, checkutil.UserAgent)
	if _, err := io.WriteString(conn, req); err != nil {
		return Page{}, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return Page{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, checkutil.DefaultMaxBody))
	return Summarise(resp.StatusCode, body), nil
}

// Run compares the proxied and direct responses for each related hostname.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	timeout := time.Duration(checkutil.Int(cfg, "timeout_seconds", 10)) * time.Second
	ports := checkutil.Ints(cfg, "ports", []int{443, 80})
	ip := t.Asset.Key
	res := &check.Result{}
	var tried []map[string]any
	pub := correlation.Publish(t.Neighbours)

	for _, host := range relatedHostnames(t, checkutil.Int(cfg, "max_hostnames", 5)) {
		entry := map[string]any{"hostname": host}
		exp, ok := expected(ctx, t, host, timeout)
		if !ok {
			entry["skipped"] = "could not fetch expected content through the proxy"
			tried = append(tried, entry)
			continue
		}
		entry["expected_status"], entry["expected_title"] = exp.Status, exp.Title
		direct_ := map[string]any{}
		for _, port := range ports {
			got, err := direct(ctx, t.Dialer, ip, port, host, timeout)
			if err != nil {
				direct_[strconv.Itoa(port)] = "unreachable: " + err.Error()
				continue
			}
			direct_[strconv.Itoa(port)] = map[string]any{"status": got.Status, "title": got.Title}
			if Similar(exp, got) {
				f := finding(ip, host, port, exp, got)
				// Name the DNS records that publish this origin, when known.
				if len(pub.Proxied) > 0 {
					f.Evidence["proxied_hostnames"] = correlation.Names(pub.Proxied)
				}
				if len(pub.Unproxied) > 0 {
					f.Evidence["unproxied_hostnames"] = correlation.Names(pub.Unproxied)
				}
				res.Findings = append(res.Findings, f)
			}
		}
		entry["direct"] = direct_
		tried = append(tried, entry)
	}
	res.Observations = append(res.Observations, model.ObservationInput{Check: Name,
		Data: map[string]any{"ip": ip, "hostnames": tried}})
	return res, nil
}

// expected fetches the site as normal clients see it (through the proxy).
func expected(ctx context.Context, t check.Target, host string, timeout time.Duration) (Page, bool) {
	for _, scheme := range []string{"https", "http"} {
		r, err := checkutil.Fetch(ctx, t.HTTP, scheme+"://"+host+"/", checkutil.FetchOpts{Timeout: timeout})
		if err == nil {
			return Summarise(r.Status, r.Body), true
		}
	}
	return Page{}, false
}

func finding(ip, host string, port int, exp, got Page) model.FindingInput {
	return model.FindingInput{
		Check: Name, Key: fmt.Sprintf("direct:%s:%d", host, port), Severity: model.SeverityHigh,
		Title:       fmt.Sprintf("origin %s reachable directly on port %d, bypassing the CDN/WAF for %s", ip, port, host),
		Description: fmt.Sprintf("Connecting straight to the origin IP %s:%d with Host %s returns the real site (status %d, title %q). Attackers who learn the origin IP (certificate transparency, DNS history, mail headers) can bypass the CDN's WAF, DDoS protection and rate limits.", ip, port, host, got.Status, got.Title),
		Remediation: "Firewall the origin so ports 80/443 accept traffic only from the CDN's published IP ranges (or use an authenticated origin pull / tunnel such as Cloudflare Tunnel or mTLS), then rotate the origin IP if it was exposed for long.",
		Evidence: map[string]any{
			"ip": ip, "port": port, "hostname": host,
			"expected_status": exp.Status, "expected_title": exp.Title,
			"direct_status": got.Status, "direct_title": got.Title,
		},
		Tags: []string{"origin", "waf-bypass", "network"},
	}
}
