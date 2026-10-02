package headers

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// CORSProbeOrigin is the synthetic Origin sent to detect origin reflection.
const CORSProbeOrigin = "https://deckard-cors-probe.example.invalid"

// Input is everything the pure analyser needs about one response.
type Input struct {
	URL    string
	HTTPS  bool
	Header http.Header
}

// Config selects which findings are produced.
type Config struct {
	// Required lists header classes to require: hsts, csp,
	// x-content-type-options, x-frame-options, referrer-policy.
	Required []string
	// HSTSMinAge is the minimum acceptable max-age in seconds.
	HSTSMinAge int
}

// DefaultRequired is the default Required list.
var DefaultRequired = []string{"hsts", "csp", "x-content-type-options", "x-frame-options", "referrer-policy"}

func fnd(key string, sev model.Severity, title, desc, rem string, ev map[string]any) model.FindingInput {
	return model.FindingInput{Check: Name, Key: key, Severity: sev, Title: title, Description: desc,
		Remediation: rem, Evidence: ev, Tags: []string{"http", "headers"}}
}

func has(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Analyze inspects response headers and returns findings. It performs no I/O.
func Analyze(in Input, cfg Config) []model.FindingInput {
	var out []model.FindingInput
	h := in.Header
	ev := func(extra ...any) map[string]any {
		m := map[string]any{"url": in.URL}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i].(string)] = extra[i+1]
		}
		return m
	}

	if has(cfg.Required, "hsts") && in.HTTPS {
		v := h.Get("Strict-Transport-Security")
		if v == "" {
			out = append(out, fnd("missing-hsts", model.SeverityLow, "Missing Strict-Transport-Security on "+in.URL,
				"Without HSTS browsers can be downgraded to HTTP by a network attacker (SSL stripping) on the first or later visits.",
				"Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.", ev()))
		} else if age := hstsMaxAge(v); cfg.HSTSMinAge > 0 && age < cfg.HSTSMinAge {
			out = append(out, fnd("weak-hsts", model.SeverityLow, "Short HSTS max-age on "+in.URL,
				fmt.Sprintf("HSTS max-age is %d seconds, below the %d-second minimum.", age, cfg.HSTSMinAge),
				"Raise max-age to at least 31536000 (one year).", ev("header", v)))
		}
	}
	csp := h.Get("Content-Security-Policy")
	if has(cfg.Required, "csp") && csp == "" {
		out = append(out, fnd("missing-csp", model.SeverityLow, "Missing Content-Security-Policy on "+in.URL,
			"No CSP is set, so injected scripts are not restricted by the browser, increasing XSS impact.",
			"Define a Content-Security-Policy (start with `default-src 'self'` in report-only mode and tighten).", ev()))
	}
	if has(cfg.Required, "x-content-type-options") && !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		out = append(out, fnd("missing-x-content-type-options", model.SeverityLow, "Missing X-Content-Type-Options on "+in.URL,
			"Browsers may MIME-sniff responses and execute content as a different type.",
			"Send `X-Content-Type-Options: nosniff`.", ev()))
	}
	if has(cfg.Required, "x-frame-options") && h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		out = append(out, fnd("missing-frame-protection", model.SeverityLow, "No clickjacking protection on "+in.URL,
			"Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be framed by other sites (clickjacking).",
			"Send `X-Frame-Options: DENY` (or SAMEORIGIN), or a CSP `frame-ancestors 'self'` directive.", ev()))
	}
	if has(cfg.Required, "referrer-policy") && h.Get("Referrer-Policy") == "" {
		out = append(out, fnd("missing-referrer-policy", model.SeverityInfo, "Missing Referrer-Policy on "+in.URL,
			"Without a Referrer-Policy browsers may leak full URLs (including paths and query strings) to other origins.",
			"Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).", ev()))
	}

	out = append(out, cookieFindings(in)...)
	out = append(out, bannerFindings(in)...)
	out = append(out, corsFindings(in)...)
	return out
}

func hstsMaxAge(v string) int {
	for _, p := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(k, "max-age") {
			n, _ := strconv.Atoi(strings.Trim(val, `"`))
			return n
		}
	}
	return 0
}

var sessionCookieRE = regexp.MustCompile(`(?i)(sess|sid$|^sid|auth|token|jwt|login|remember)`)

// IsSessionCookie guesses whether a cookie name carries session/authn state.
func IsSessionCookie(name string) bool { return sessionCookieRE.MatchString(name) }

func cookieFindings(in Input) []model.FindingInput {
	var out []model.FindingInput
	resp := http.Response{Header: in.Header}
	for _, c := range resp.Cookies() {
		if !IsSessionCookie(c.Name) {
			continue
		}
		var missing []string
		if in.HTTPS && !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if c.SameSite == 0 { // attribute absent
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		sev := model.SeverityLow
		if has(missing, "Secure") {
			sev = model.SeverityMedium
		}
		out = append(out, fnd("cookie:"+strings.ToLower(c.Name), sev,
			fmt.Sprintf("Session cookie %q on %s lacks %s", c.Name, in.URL, strings.Join(missing, ", ")),
			"Session-looking cookies should be Secure (HTTPS only), HttpOnly (not readable by scripts) and SameSite (not sent cross-site) to limit theft and CSRF.",
			"Set the "+strings.Join(missing, ", ")+" attribute(s) on the cookie in the application or reverse-proxy configuration.",
			map[string]any{"url": in.URL, "cookie": c.Name, "missing": missing}))
	}
	return out
}

var versionRE = regexp.MustCompile(`\d+\.\d+|/\d`)

func bannerFindings(in Input) []model.FindingInput {
	leaks := map[string]any{}
	if s := in.Header.Get("Server"); versionRE.MatchString(s) {
		leaks["Server"] = s
	}
	if p := in.Header.Get("X-Powered-By"); p != "" {
		leaks["X-Powered-By"] = p
	}
	if len(leaks) == 0 {
		return nil
	}
	names := make([]string, 0, len(leaks))
	for k := range leaks {
		names = append(names, k)
	}
	sort.Strings(names)
	return []model.FindingInput{fnd("banner-disclosure", model.SeverityInfo,
		"Server software disclosed by "+strings.Join(names, ", ")+" on "+in.URL,
		"Version banners help attackers pick known exploits for the exact software in use.",
		"Strip or genericise the headers (nginx `server_tokens off`, Apache `ServerTokens Prod`, remove X-Powered-By in the framework or proxy).",
		map[string]any{"url": in.URL, "headers": leaks})}
}

func corsFindings(in Input) []model.FindingInput {
	acao := in.Header.Get("Access-Control-Allow-Origin")
	creds := strings.EqualFold(in.Header.Get("Access-Control-Allow-Credentials"), "true")
	switch {
	case acao == "*" && creds:
		return []model.FindingInput{fnd("cors-wildcard-credentials", model.SeverityMedium,
			"CORS allows any origin with credentials on "+in.URL,
			"Access-Control-Allow-Origin is `*` together with Access-Control-Allow-Credentials: true. Browsers refuse this combination, which signals a misconfigured policy that is often 'fixed' by reflecting the Origin header.",
			"Replace the wildcard with an explicit allow-list of trusted origins; never combine credentials with a broad policy.",
			map[string]any{"url": in.URL, "allow_origin": acao, "allow_credentials": true})}
	case acao == CORSProbeOrigin && creds:
		return []model.FindingInput{fnd("cors-reflected-origin", model.SeverityMedium,
			"CORS reflects arbitrary Origin with credentials on "+in.URL,
			"The server echoed an arbitrary, unregistered Origin and allowed credentials, so any website can read authenticated responses from a victim's browser.",
			"Validate Origin against an explicit allow-list before echoing it; do not allow credentials for untrusted origins.",
			map[string]any{"url": in.URL, "probe_origin": CORSProbeOrigin, "allow_credentials": true})}
	}
	return nil
}

// NoHTTPSRedirect flags a plain-HTTP endpoint that serves content instead of
// redirecting to HTTPS.
func NoHTTPSRedirect(url string, finalHTTPS bool, status int) *model.FindingInput {
	if finalHTTPS || status >= 400 {
		return nil
	}
	f := fnd("no-https-redirect", model.SeverityLow, "HTTP does not redirect to HTTPS on "+url,
		"The site serves content over plain HTTP without redirecting to HTTPS, exposing sessions and content to interception and tampering.",
		"Redirect all HTTP requests to HTTPS with a 301 at the edge/load balancer, then enable HSTS.",
		map[string]any{"url": url, "status": status})
	return &f
}
