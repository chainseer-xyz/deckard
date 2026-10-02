package nuclei

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei/templates"
)

// maxBulkHosts bounds how many hosts nuclei probes in parallel per template
// (-bs). The global -rate-limit is scaled by it so each host still sees at most
// the profile's per-host rate.
const maxBulkHosts = 25

// ScanTarget is one web target of a template-limited scan. ID is opaque to
// this package (the engine passes the asset id) and keys the result.
type ScanTarget struct {
	ID  int64
	URL string
}

// ScanRequest describes one batch run of an explicit template set.
type ScanRequest struct {
	Targets []ScanTarget
	// Templates are absolute paths of template files inside the active
	// template directory (see Scanner.Resolve).
	Templates []string
	// RatePerSec is the allowed request rate per target host (0 = the
	// checks.cve.nuclei rate_limit, default 50). Concurrency caps concurrent
	// templates per host (0 = the checks.cve.nuclei concurrency, default 10).
	RatePerSec  float64
	Concurrency int
	// Config overlays checks.cve.nuclei for this run (rate_limit, concurrency,
	// timeout, run_timeout, interactsh).
	Config map[string]any
}

// ScanResult is the outcome of a batch.
type ScanResult struct {
	// Findings per ScanTarget.ID. Check is cve.nuclei and Key the template id
	// (":matcher" when the template names one), so fingerprints equal those of
	// the regular full scan.
	Findings map[int64][]model.FindingInput
	// Refused are targets that failed validation or scope verification. They
	// never reached the nuclei binary.
	Refused []ScanTarget
	// Scanned is the number of targets handed to nuclei.
	Scanned int
}

// Scanner runs nuclei against many targets with an explicit template list:
// the engine's new-template and CVE-targeted scans. Every target is validated
// and scope-verified before it can reach the binary.
type Scanner struct {
	cfg      config.NucleiConfig
	verify   ScopeVerifier
	runner   Runner
	defaults map[string]any
	opts     options

	mu    sync.Mutex
	cache struct {
		root string
		tree *templates.Tree
	}
}

// NewScanner builds a Scanner. A nil verify refuses every target. defaults is
// the checks.cve.nuclei option map.
func NewScanner(cfg config.NucleiConfig, verify ScopeVerifier, runner Runner, defaults map[string]any, opts ...Option) *Scanner {
	if cfg.Binary == "" {
		cfg.Binary = "nuclei"
	}
	return &Scanner{cfg: cfg, verify: verify, runner: runner, defaults: defaults, opts: buildOptions(opts)}
}

// TargetURL returns the validated URL nuclei scans for a URL or web-service
// asset (the same derivation the regular cve.nuclei check uses). It fails for
// assets nuclei does not apply to. The result still has to pass the scope
// verifier; Scan does that.
func TargetURL(a model.Asset) (string, error) {
	if !appliesTo(a) {
		return "", fmt.Errorf("%w: asset %s (%s) not applicable", ErrOutOfScope, a.Key, a.Scope)
	}
	tg, err := buildTarget(a)
	if err != nil {
		return "", err
	}
	return tg.arg, nil
}

// TemplateRoot returns the resolved directory of the active template set.
func (s *Scanner) TemplateRoot() (string, error) {
	dir := s.cfg.TemplatesDir
	if s.opts.templateDir != nil {
		d, err := s.opts.templateDir()
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrNoTemplates, err)
		}
		dir = d
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("%w: no template directory configured", ErrNoTemplates)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoTemplates, err)
	}
	return real, nil
}

// Resolve maps template paths relative to the active set to absolute paths,
// dropping those that no longer exist (a newer release may have removed or
// moved them) or that would resolve outside the set.
func (s *Scanner) Resolve(rel []string) ([]string, error) {
	root, err := s.TemplateRoot()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rel {
		if p, ok := safeTemplate(root, filepath.Join(root, filepath.FromSlash(r))); ok && templates.IsTemplatePath(r) && templates.ProtocolOf(r) != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// safeTemplate reports whether p is a regular YAML file whose real path lies
// inside root, and returns that real path.
func safeTemplate(root, p string) (string, bool) {
	if strings.ContainsAny(p, "\n\r\x00") || strings.HasPrefix(filepath.Base(p), "-") {
		return "", false
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	if r, err := filepath.Rel(root, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", false
	}
	if ext := strings.ToLower(filepath.Ext(real)); ext != ".yaml" && ext != ".yml" {
		return "", false
	}
	if st, err := os.Stat(real); err != nil || !st.Mode().IsRegular() {
		return "", false
	}
	return real, true
}

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,19}$`)

// maxCVEs bounds one CVE-targeted request.
const maxCVEs = 100

// NormalizeCVEs upper-cases, trims and deduplicates CVE ids and rejects
// anything that is not CVE-YYYY-NNNN+.
func NormalizeCVEs(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if !cveRe.MatchString(c) {
			return nil, fmt.Errorf("nuclei: %q is not a CVE id (want CVE-YYYY-NNNN)", c)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("nuclei: no CVE ids given")
	}
	if len(out) > maxCVEs {
		return nil, fmt.Errorf("nuclei: %d CVE ids exceeds the limit of %d", len(out), maxCVEs)
	}
	return out, nil
}

// LookupCVEs finds the scannable templates (http, ssl, dns, tcp) of the active
// set whose id or classification.cve-id names any of cves, as paths relative
// to the set. Only template headers are read; nothing is executed.
func (s *Scanner) LookupCVEs(cves []string) ([]string, error) {
	want, err := NormalizeCVEs(cves)
	if err != nil {
		return nil, err
	}
	root, err := s.TemplateRoot()
	if err != nil {
		return nil, err
	}
	tree, err := s.tree(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range tree.Templates {
		if !m.Scannable() {
			continue
		}
		for _, c := range want {
			if m.MatchesCVE(c) {
				out = append(out, m.Path)
				break
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out), nil
}

// tree returns the parsed header index of root, cached per release directory
// (releases are immutable once installed).
func (s *Scanner) tree(root string) (*templates.Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache.tree != nil && s.cache.root == root {
		return s.cache.tree, nil
	}
	t, err := templates.Scan(root)
	if err != nil {
		return nil, err
	}
	s.cache.root, s.cache.tree = root, t
	return t, nil
}

func (s *Scanner) runSettings(req ScanRequest, hosts int) (args []string, runTimeout time.Duration, err error) {
	cfg := map[string]any{}
	for k, v := range s.defaults {
		cfg[k] = v
	}
	for k, v := range req.Config {
		cfg[k] = v
	}
	sev, err := severityList(s.cfg.SeverityMin)
	if err != nil {
		return nil, 0, err
	}
	rate := req.RatePerSec
	if rate <= 0 {
		rate = float64(intOf(cfg["rate_limit"], 50))
	}
	conc := req.Concurrency
	if conc <= 0 {
		conc = intOf(cfg["concurrency"], 10)
	}
	bulk := max(1, min(hosts, maxBulkHosts))
	global := max(1, int(math.Ceil(rate*float64(bulk))))
	// Never intrusive, always dos-excluded, whatever the operator lists.
	ro := runOptions{cfg: s.cfg}
	args = []string{
		"-jsonl", "-silent", "-no-color", "-duc",
		"-pt", networkProtocols, "-severity", sev,
	}
	if ex := ro.excludeTags(); len(ex) > 0 {
		args = append(args, "-etags", strings.Join(ex, ","))
	}
	args = append(args, "-rate-limit", fmt.Sprint(global), "-c", fmt.Sprint(conc), "-bs", fmt.Sprint(bulk),
		"-timeout", fmt.Sprint(secondsOf(cfg["timeout"], 10)))
	if cfg["interactsh"] != true {
		args = append(args, "-no-interactsh")
	}
	return args, time.Duration(secondsOf(cfg["run_timeout"], 600)) * time.Second, nil
}

// Scan runs req.Templates against req.Targets in one nuclei process. Targets
// failing validation or scope verification are refused and never written to
// the target list; with nothing left the binary is not started. The returned
// findings are valid even when the error is non-nil (nuclei may have crashed
// after matching); the caller should process them and still surface the error.
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	res := ScanResult{Findings: map[int64][]model.FindingInput{}}
	root, err := s.TemplateRoot()
	if err != nil {
		return res, err
	}
	var tpls []string
	for _, p := range req.Templates {
		if real, ok := safeTemplate(root, p); ok && filepath.IsAbs(p) {
			tpls = append(tpls, real)
		}
	}
	if len(tpls) == 0 {
		return res, fmt.Errorf("%w: none of the %d requested templates exists in the active set", ErrNoTemplates, len(req.Templates))
	}
	slices.Sort(tpls)
	tpls = slices.Compact(tpls)

	byOrigin := map[string][]ScanTarget{}
	byHost := map[string][]ScanTarget{}
	hosts := map[string]bool{}
	var lines []string
	seenURL := map[string]bool{}
	for _, t := range req.Targets {
		tg, err := urlTarget(t.URL)
		if err != nil || s.verify == nil || !s.verify(ctx, tg.host) {
			res.Refused = append(res.Refused, t)
			continue
		}
		o := OriginOfURL(tg.arg)
		byOrigin[o] = append(byOrigin[o], t)
		h := strings.ToLower(tg.host)
		byHost[h] = append(byHost[h], t)
		hosts[h] = true
		if !seenURL[tg.arg] {
			seenURL[tg.arg] = true
			lines = append(lines, tg.arg)
		}
		res.Scanned++
	}
	if len(lines) == 0 {
		return res, nil
	}

	args, runTimeout, err := s.runSettings(req, len(hosts))
	if err != nil {
		return res, err
	}
	dir, err := os.MkdirTemp("", "deckard-nuclei-")
	if err != nil {
		return res, fmt.Errorf("nuclei: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	targetsFile := filepath.Join(dir, "targets.txt")
	templatesFile := filepath.Join(dir, "templates.txt")
	if err := os.WriteFile(targetsFile, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return res, fmt.Errorf("nuclei: %w", err)
	}
	if err := os.WriteFile(templatesFile, []byte(strings.Join(tpls, "\n")+"\n"), 0o600); err != nil {
		return res, fmt.Errorf("nuclei: %w", err)
	}
	// A template list file is accepted by -t (verified against nuclei v3.11.1);
	// it keeps argv small however many templates a release adds.
	args = append([]string{"-l", targetsFile, "-t", templatesFile}, args...)

	rctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	out, runErr := s.runner.Run(rctx, s.cfg.Binary, args)
	matches, perr := ParseMatches(bytes.NewReader(out))
	if perr != nil {
		return res, perr
	}
	merged := map[int64]map[string]int{}
	for _, m := range matches {
		targets := byOrigin[m.Origin()]
		if len(targets) == 0 && m.Scheme == "" {
			targets = byHost[strings.ToLower(m.Host)] // ssl/dns/tcp events carry no scheme
		}
		if len(targets) == 0 {
			slog.Debug("nuclei: result for an unknown target ignored", "origin", m.Origin(), "template", m.Key)
			continue
		}
		for _, t := range targets {
			f := m.FindingInput
			f.Check = NameActive
			idx := merged[t.ID]
			if idx == nil {
				idx = map[string]int{}
				merged[t.ID] = idx
			}
			if i, dup := idx[f.Key]; dup {
				mergeMatch(&res.Findings[t.ID][i], f)
				continue
			}
			f.Evidence = cloneEvidence(f.Evidence)
			idx[f.Key] = len(res.Findings[t.ID])
			res.Findings[t.ID] = append(res.Findings[t.ID], f)
		}
	}
	if runErr != nil {
		return res, runErr
	}
	return res, nil
}

// cloneEvidence copies the evidence map so one match attributed to several
// assets does not share mutable state.
func cloneEvidence(e map[string]any) map[string]any {
	out := make(map[string]any, len(e))
	for k, v := range e {
		if l, ok := v.([]string); ok {
			v = slices.Clone(l)
		}
		out[k] = v
	}
	return out
}
