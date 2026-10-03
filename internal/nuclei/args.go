package nuclei

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// ScopeVerifier reports whether host (hostname or IP literal) is owned, and for
// names resolves only to owned addresses, so it may be handed to a tool that
// makes its own connections (see scope.Guard.VerifyOwnedTarget).
type ScopeVerifier func(ctx context.Context, host string) bool

var (
	hostRe = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]+$`)
	tagRe  = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)
)

// severityList returns the severities >= min, comma separated.
func severityList(min string) (string, error) {
	if strings.TrimSpace(min) == "" {
		min = "low"
	}
	m := model.Severity(strings.ToLower(strings.TrimSpace(min)))
	if !m.Valid() {
		return "", fmt.Errorf("invalid severity_min %q", min)
	}
	var out []string
	for _, s := range []model.Severity{model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical} {
		if s.AtLeast(m) {
			out = append(out, string(s))
		}
	}
	return strings.Join(out, ","), nil
}

// target is a validated nuclei target and the host to scope-check.
type target struct {
	arg  string
	host string
}

func hasBadChars(s string) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// buildTarget derives and validates the nuclei target for an asset. It never
// trusts the key blindly: leading '-', whitespace/control characters,
// userinfo and non-http(s) schemes are rejected.
func buildTarget(a model.Asset) (target, error) {
	switch a.Kind {
	case model.KindURL:
		return urlTarget(a.Key)
	case model.KindService:
		return serviceTarget(a)
	}
	return target{}, fmt.Errorf("nuclei: unsupported asset kind %q", a.Kind)
}

func urlTarget(key string) (target, error) {
	if strings.HasPrefix(key, "-") || hasBadChars(key) {
		return target{}, fmt.Errorf("nuclei: rejected target %q", key)
	}
	u, err := url.Parse(key)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return target{}, fmt.Errorf("nuclei: rejected target %q", key)
	}
	h := u.Hostname()
	if h == "" || strings.HasPrefix(h, "-") || !hostRe.MatchString(h) {
		return target{}, fmt.Errorf("nuclei: rejected target host %q", h)
	}
	return target{arg: u.String(), host: h}, nil
}

var webPorts = map[int]bool{80: true, 443: true, 3000: true, 8000: true, 8008: true, 8080: true, 8081: true, 8443: true, 8888: true, 9000: true, 9090: true, 9200: true, 9443: true}

func serviceAddr(a model.Asset) (string, int, error) {
	if ip, ok := a.Attrs["ip"].(string); ok && ip != "" {
		switch p := a.Attrs["port"].(type) {
		case int:
			return ip, p, nil
		case float64:
			return ip, int(p), nil
		}
	}
	h, ps, err := net.SplitHostPort(strings.TrimSuffix(a.Key, "/tcp"))
	if err != nil {
		return "", 0, fmt.Errorf("nuclei: service key %q is not ip:port/tcp", a.Key)
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("nuclei: service key %q has invalid port", a.Key)
	}
	return h, p, nil
}

func serviceTarget(a model.Asset) (target, error) {
	h, p, err := serviceAddr(a)
	if err != nil {
		return target{}, err
	}
	if h == "" || strings.HasPrefix(h, "-") || !hostRe.MatchString(h) {
		return target{}, fmt.Errorf("nuclei: rejected service host %q", h)
	}
	scheme := "http"
	if a.Attrs["tls"] == true || p == 443 || p == 8443 || p == 9443 {
		scheme = "https"
	}
	return target{arg: scheme + "://" + net.JoinHostPort(h, strconv.Itoa(p)), host: h}, nil
}

// appliesTo reports whether the asset is a web-ish target nuclei can scan.
func appliesTo(a model.Asset) bool {
	if a.Scope != model.ScopeOwned {
		return false
	}
	switch a.Kind {
	case model.KindURL:
		return true
	case model.KindService:
		if a.Attrs["tls"] == true {
			return true
		}
		if prod, _ := a.Attrs["product"].(string); prod == "http" || prod == "https" || prod == "elasticsearch" {
			return true
		}
		_, p, err := serviceAddr(a)
		return err == nil && webPorts[p]
	}
	return false
}

// runOptions are the tunables that become nuclei flags.
type runOptions struct {
	cfg         config.NucleiConfig
	intrusive   bool
	lifted      []string
	rateLimit   int
	concurrency int
	timeoutSec  int
	interactsh  bool
	// explicit, when set, replaces the template directory and tag selection
	// with exactly these template files (already verified to lie inside the
	// active set): the re-verification run of open findings.
	explicit  []string
	extraDirs []string
}

// excludeTags returns -etags: configured exclusions, always including dos
// and (for the active variant) intrusive. The intrusive variant lifts only
// the tags the operator listed (default: intrusive); dos stays excluded
// unless it is explicitly listed.
func (o runOptions) excludeTags() []string {
	lift := map[string]bool{}
	for _, t := range o.lifted {
		lift[strings.ToLower(t)] = true
	}
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || !tagRe.MatchString(t) || seen[t] {
			return
		}
		if o.intrusive && lift[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, t := range o.cfg.TagsExclude {
		add(t)
	}
	add("dos")
	if !o.intrusive {
		add("intrusive")
	}
	return out
}

// networkProtocols is the only set of template protocols deckard ever runs:
// code, headless, file, javascript and DAST templates are never requested
// (nuclei enables javascript by default, so the restriction is explicit).
const networkProtocols = "http,ssl,dns,tcp"

// resolveDir follows symlinks: nuclei does not descend into a symlinked -t
// root, and the template updater's "current" is a symlink to the release.
func resolveDir(d string) string {
	if real, err := filepath.EvalSymlinks(d); err == nil {
		return real
	}
	return d
}

// tagsFor returns the template tags the tech selection runs for a.
func (o runOptions) tagsFor(a model.Asset) []string {
	tags := selectTags(a, o.cfg.ExtraTags)
	if o.intrusive {
		tags = append(tags, "intrusive")
	}
	return tags
}

// buildArgs builds the nuclei argv (no shell involved anywhere).
func buildArgs(tg target, a model.Asset, o runOptions) ([]string, error) {
	sev, err := severityList(o.cfg.SeverityMin)
	if err != nil {
		return nil, err
	}
	tags := o.tagsFor(a)
	// -dr (disable redirects): nuclei runs its own HTTP stack, so the scope
	// guard cannot re-vet where a template's request chain goes. A template
	// with redirects:true would otherwise follow a cross-host Location header
	// and probe a third party only because an owned host pointed at it.
	args := []string{"-u", tg.arg, "-jsonl", "-silent", "-no-color", "-duc", "-dr"}
	if len(o.explicit) > 0 {
		for _, p := range o.explicit {
			if !filepath.IsAbs(p) || strings.HasPrefix(filepath.Base(p), "-") {
				return nil, fmt.Errorf("nuclei: template %q rejected", p)
			}
			args = append(args, "-t", p)
		}
	} else if d := o.cfg.TemplatesDir; d != "" {
		if strings.HasPrefix(d, "-") {
			return nil, fmt.Errorf("nuclei: templates_dir %q rejected", d)
		}
		args = append(args, "-t", resolveDir(d))
	}
	args = customTemplateArgs(args, o.extraDirs)
	if o.cfg.ScanMode != "all" && len(o.explicit) == 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, "-pt", networkProtocols, "-severity", sev)
	if ex := o.excludeTags(); len(ex) > 0 {
		args = append(args, "-etags", strings.Join(ex, ","))
	}
	args = append(args, "-rate-limit", strconv.Itoa(o.rateLimit), "-c", strconv.Itoa(o.concurrency), "-timeout", strconv.Itoa(o.timeoutSec))
	if !o.interactsh {
		args = append(args, "-no-interactsh")
	}
	return args, nil
}
