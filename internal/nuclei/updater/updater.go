// Package updater keeps a nuclei template set fresh without ever running a
// template. It drives the pinned nuclei binary's own template installer
// (`nuclei -update-templates -update-template-dir <staging>`), validates what
// was downloaded, and publishes it with an atomic symlink swap:
//
//	<dir>/current   -> releases/<version>-<ts>   (what scans read)
//	<dir>/previous  -> releases/<older release>  (fallback, kept until pruned)
//	<dir>/releases/ one directory per installed release
//	<dir>/staging-* in-flight downloads (removed on success and failure)
//	<dir>/run/      per-scan HOME/XDG/config directories (the container root
//	                filesystem is read-only; nuclei must write somewhere)
//	<dir>/state.json last update status
//
// Any failure leaves the last good release serving and is reported to the
// caller. nuclei is always started with a throwaway config directory so the
// installer cannot decide "already up to date" from stale state and leave the
// staging directory empty. Note that nuclei silently does nothing when
// -update-templates is combined with -disable-update-check (-duc), so the
// updater never passes it.
package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/nuclei/templates"
)

// Defaults for Config limits, sized for the real nuclei-templates release
// (about 13.5k templates, 80 MB, 20k files at v10.4.9) with generous headroom.
const (
	DefaultMinTemplates     = 1000
	DefaultMinHTTPTemplates = 100
	DefaultMaxBytes         = 512 << 20
	DefaultMaxFiles         = 200_000
	DefaultMaxNew           = 5000
	defaultStagingMaxAge    = time.Hour
	runDirMaxAge            = 6 * time.Hour
)

// Exec runs the nuclei binary and returns its combined output.
type Exec func(ctx context.Context, binary string, args, env []string) ([]byte, error)

// Config configures an Updater.
type Config struct {
	// Dir is the writable state root (nuclei.update.dir).
	Dir string
	// BakedDir is the read-only template snapshot shipped in the full image.
	// It is used when the writable current release is absent or invalid.
	BakedDir string
	// Binary is the nuclei executable (default "nuclei").
	Binary string
	// Timeout bounds one update, download included (default 10m).
	Timeout time.Duration
	// MinTemplates and MinHTTPTemplates reject a release that is too small to
	// be real (an empty or truncated download).
	MinTemplates     int
	MinHTTPTemplates int
	// MaxBytes and MaxFiles cap the release size on disk.
	MaxBytes int64
	MaxFiles int
	// MaxNew caps Update.NewTemplates (a long outage can add thousands).
	MaxNew int
	// PruneGrace keeps releases younger than this even when they are neither
	// current nor previous, so a scan that started on a release moments ago is
	// never cut off by a burst of updates (default 1h).
	PruneGrace time.Duration
	// Now overrides time.Now in tests.
	Now func() time.Time
	// Exec overrides the process runner in tests.
	Exec Exec
	// Logger receives progress; nil discards.
	Logger *slog.Logger
}

// Update is the outcome of one successful update run.
type Update struct {
	// Version is the nuclei-templates release (e.g. v10.4.9).
	Version string
	// TemplateCount is the number of templates in the active release.
	TemplateCount int
	// NewTemplates are the scannable (http, ssl, dns, tcp) templates this
	// release added compared with the previous one, as paths relative to Dir.
	// Empty on the first install and when nothing changed.
	NewTemplates []string
	// NewIDs are the template ids of NewTemplates.
	NewIDs []string
	// UpdatedAt is when the active release was installed.
	UpdatedAt time.Time
	// Changed is false when the upstream release equals the active one.
	Changed bool
	// Dir is the resolved path of the active release.
	Dir string
}

// Status is the persisted state of the updater, for metrics and diagnostics.
type Status struct {
	Version       string    `json:"version"`
	Release       string    `json:"release"`
	TemplateCount int       `json:"template_count"`
	UpdatedAt     time.Time `json:"updated_at"`
	// CheckedAt is the last successful check (new release installed or the
	// active one confirmed current).
	CheckedAt   time.Time `json:"checked_at"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitempty"`
}

// Updater downloads, validates and publishes nuclei template releases.
type Updater struct {
	cfg     Config
	mu      sync.Mutex
	validMu sync.Mutex
	valid   map[string]bool
}

// New validates cfg and returns an Updater. It does not touch the disk.
func New(cfg Config) (*Updater, error) {
	if strings.TrimSpace(cfg.Dir) == "" || !filepath.IsAbs(cfg.Dir) {
		return nil, fmt.Errorf("updater: dir %q must be an absolute path", cfg.Dir)
	}
	cfg.Dir = filepath.Clean(cfg.Dir)
	if cfg.Binary == "" {
		cfg.Binary = "nuclei"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Minute
	}
	if cfg.MinTemplates <= 0 {
		cfg.MinTemplates = DefaultMinTemplates
	}
	if cfg.MinHTTPTemplates <= 0 {
		cfg.MinHTTPTemplates = DefaultMinHTTPTemplates
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = DefaultMaxFiles
	}
	if cfg.MaxNew <= 0 {
		cfg.MaxNew = DefaultMaxNew
	}
	if cfg.PruneGrace <= 0 {
		cfg.PruneGrace = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Exec == nil {
		cfg.Exec = execCommand
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Updater{cfg: cfg, valid: map[string]bool{}}, nil
}

// Dir returns the state root.
func (u *Updater) Dir() string { return u.cfg.Dir }

// CurrentLink is the path of the current-release symlink.
func (u *Updater) CurrentLink() string { return filepath.Join(u.cfg.Dir, "current") }

// CurrentDir resolves the current symlink to the real release directory. It
// fails when no release has been installed yet.
func (u *Updater) CurrentDir() (string, error) {
	return filepath.EvalSymlinks(u.CurrentLink())
}

// ActiveDir returns the current validated release, or the validated baked
// snapshot when the writable volume is empty or damaged. source is either
// "downloaded" or "baked".
func (u *Updater) ActiveDir() (dir, source string, err error) {
	if current, currentErr := u.CurrentDir(); currentErr == nil {
		if u.validated(current) {
			return current, "downloaded", nil
		}
	}
	if strings.TrimSpace(u.cfg.BakedDir) != "" {
		if u.validated(u.cfg.BakedDir) {
			real, realErr := filepath.EvalSymlinks(u.cfg.BakedDir)
			if realErr == nil {
				return real, "baked", nil
			}
		}
	}
	return "", "", fmt.Errorf("no valid downloaded or baked nuclei templates")
}

func (u *Updater) validated(dir string) bool {
	dir = filepath.Clean(dir)
	u.validMu.Lock()
	if ok, found := u.valid[dir]; found {
		u.validMu.Unlock()
		return ok
	}
	u.validMu.Unlock()
	_, err := u.validate(dir)
	u.validMu.Lock()
	u.valid[dir] = err == nil
	u.validMu.Unlock()
	return err == nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Update fetches the latest templates. On any failure the previous release
// stays current and the error is recorded in the state file and returned.
// Concurrent calls are serialised.
func (u *Updater) Update(ctx context.Context) (Update, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout)
	defer cancel()
	res, err := u.update(ctx)
	if err != nil {
		u.recordError(err)
		return Update{}, err
	}
	return res, nil
}

// UpdateIfOlderThan runs Update only when the active release was not confirmed
// current within maxAge (or none is installed). The freshness check happens
// under the updater lock, so concurrent callers (the scheduled job and a
// worker's catch-up loop) never download twice. ran reports whether an update
// was attempted.
func (u *Updater) UpdateIfOlderThan(ctx context.Context, maxAge time.Duration) (res Update, ran bool, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if st, serr := u.Status(); serr == nil && !st.CheckedAt.IsZero() && u.cfg.Now().Sub(st.CheckedAt) < maxAge {
		if _, cerr := u.CurrentDir(); cerr == nil {
			return Update{}, false, nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout)
	defer cancel()
	res, err = u.update(ctx)
	if err != nil {
		u.recordError(err)
		return Update{}, true, err
	}
	return res, true, nil
}

func (u *Updater) update(ctx context.Context) (Update, error) {
	now := u.cfg.Now()
	if err := os.MkdirAll(filepath.Join(u.cfg.Dir, "releases"), 0o750); err != nil {
		return Update{}, fmt.Errorf("updater: %w", err)
	}
	u.cleanStaging(now)

	stage := filepath.Join(u.cfg.Dir, fmt.Sprintf("staging-%d", now.UnixNano()))
	defer func() { _ = os.RemoveAll(stage) }()
	tpl := filepath.Join(stage, "templates")
	for _, d := range []string{tpl, filepath.Join(stage, "config", "nuclei"), filepath.Join(stage, "cache"), filepath.Join(stage, "tmp")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return Update{}, fmt.Errorf("updater: %w", err)
		}
	}

	// Never executes a template: -ut only downloads and installs.
	out, err := u.cfg.Exec(ctx, u.cfg.Binary, []string{"-update-templates", "-update-template-dir", tpl, "-no-color"}, nucleiEnv(stage, ""))
	if err != nil {
		return Update{}, fmt.Errorf("updater: nuclei template update failed: %w: %s", err, tail(out))
	}
	version := readVersion(filepath.Join(stage, "config", "nuclei"))
	if version == "" {
		return Update{}, fmt.Errorf("updater: nuclei did not report a templates version (output: %s)", tail(out))
	}

	tree, err := u.validate(tpl)
	if err != nil {
		return Update{}, fmt.Errorf("updater: release %s rejected: %w", version, err)
	}

	st, _ := u.Status() // zero when nothing is installed yet
	curDir, curErr := u.CurrentDir()
	if curErr == nil && st.Version == version {
		st.CheckedAt, st.LastError, st.LastErrorAt = now, "", time.Time{}
		if err := u.writeState(st); err != nil {
			return Update{}, err
		}
		u.cfg.Logger.Info("nuclei templates already current", "version", version, "templates", st.TemplateCount)
		return Update{Version: version, TemplateCount: st.TemplateCount, UpdatedAt: st.UpdatedAt, Changed: false, Dir: curDir}, nil
	}

	var newPaths, newIDs []string
	if curErr == nil {
		newPaths, newIDs = u.diff(curDir, tree, tpl)
	}

	name := fmt.Sprintf("%s-%s", unsafeName.ReplaceAllString(version, "_"), now.UTC().Format("20060102T150405"))
	rel := filepath.Join(u.cfg.Dir, "releases", name)
	if err := os.Rename(tpl, rel); err != nil {
		return Update{}, fmt.Errorf("updater: publish release: %w", err)
	}
	if curErr == nil {
		if oldRel, err := os.Readlink(u.CurrentLink()); err == nil && oldRel != "" {
			if err := swapSymlink(filepath.Join(u.cfg.Dir, "previous"), oldRel); err != nil {
				u.cfg.Logger.Warn("nuclei templates: could not record previous release", "err", err)
			}
		}
	}
	if err := swapSymlink(u.CurrentLink(), filepath.Join("releases", name)); err != nil {
		_ = os.RemoveAll(rel) // not published: do not leave an orphan release
		return Update{}, fmt.Errorf("updater: switch current release: %w", err)
	}
	st = Status{Version: version, Release: name, TemplateCount: len(tree.Templates), UpdatedAt: now, CheckedAt: now}
	if err := u.writeState(st); err != nil {
		return Update{}, err
	}
	u.prune(name)
	u.cfg.Logger.Info("nuclei templates updated", "version", version, "templates", st.TemplateCount, "new", len(newPaths))
	if real, err := filepath.EvalSymlinks(rel); err == nil {
		rel = real
	}
	u.validMu.Lock()
	u.valid[rel] = true
	u.validMu.Unlock()
	return Update{
		Version: version, TemplateCount: st.TemplateCount, NewTemplates: newPaths, NewIDs: newIDs,
		UpdatedAt: now, Changed: true, Dir: rel,
	}, nil
}

// diff lists the scannable templates in the new tree that the previous release
// did not have: ids missing from the old tree, plus paths named by the
// release's .new-additions that the old tree lacks.
func (u *Updater) diff(oldDir string, tree *templates.Tree, newDir string) (paths, ids []string) {
	old, err := templates.Scan(oldDir)
	if err != nil {
		u.cfg.Logger.Warn("nuclei templates: cannot read previous release, skipping new-template detection", "err", err)
		return nil, nil
	}
	oldIDs, oldPaths := old.IDs(), old.Paths()
	additions := ParseNewAdditions(filepath.Join(newDir, ".new-additions"))
	seen := map[string]bool{}
	byPath := map[string]templates.Meta{}
	for _, m := range tree.Templates {
		byPath[m.Path] = m
	}
	add := func(m templates.Meta) {
		if m.Scannable() && !seen[m.Path] {
			seen[m.Path] = true
			paths = append(paths, m.Path)
			ids = append(ids, m.ID)
		}
	}
	for _, m := range tree.Templates {
		if !oldIDs[m.ID] {
			add(m)
		}
	}
	for _, p := range additions {
		if m, ok := byPath[p]; ok && !oldPaths[p] {
			add(m)
		}
	}
	idx := make([]int, len(paths))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return paths[idx[a]] < paths[idx[b]] })
	sp, si := make([]string, 0, len(paths)), make([]string, 0, len(paths))
	for _, i := range idx {
		sp, si = append(sp, paths[i]), append(si, ids[i])
	}
	if len(sp) > u.cfg.MaxNew {
		u.cfg.Logger.Warn("nuclei templates: new-template list capped", "found", len(sp), "cap", u.cfg.MaxNew)
		sp, si = sp[:u.cfg.MaxNew], si[:u.cfg.MaxNew]
	}
	return sp, si
}

// ParseNewAdditions reads a nuclei .new-additions file: one template path
// (relative to the templates root) per line. Missing file, blank lines,
// comments, absolute paths and ".." escapes are ignored.
func ParseNewAdditions(path string) []string {
	b, err := os.ReadFile(path) // #nosec G304 -- path is inside the release being validated
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || filepath.IsAbs(line) {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(line))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			continue
		}
		out = append(out, clean)
	}
	return out
}

func readVersion(cfgDir string) string {
	b, err := os.ReadFile(filepath.Join(cfgDir, ".templates-config.json")) // #nosec G304 -- our own staging dir
	if err != nil {
		return ""
	}
	var c struct {
		Version string `json:"nuclei-templates-version"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return strings.TrimSpace(c.Version)
}

// ---- validation --------------------------------------------------------------

// validate checks a downloaded release before it can become current: no
// links escaping the tree, no special files, bounded size and file count, and
// enough real templates (including http ones) to be a plausible release.
func (u *Updater) validate(root string) (*templates.Tree, error) {
	return templates.Validate(root, templates.Limits{
		MinTemplates: u.cfg.MinTemplates, MinHTTPTemplates: u.cfg.MinHTTPTemplates,
		MaxBytes: u.cfg.MaxBytes, MaxFiles: u.cfg.MaxFiles,
	})
}

// ---- layout, state, pruning ---------------------------------------------------

// swapSymlink atomically points link at target (symlink + rename).
func swapSymlink(link, target string) error {
	tmp := fmt.Sprintf("%s.tmp-%d", link, os.Getpid())
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if st, err := os.Lstat(link); err == nil && st.Mode()&fs.ModeSymlink == 0 {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s exists and is not a symlink", link)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (u *Updater) statePath() string { return filepath.Join(u.cfg.Dir, "state.json") }

// Status returns the persisted updater state. A missing file yields the zero
// Status and no error.
func (u *Updater) Status() (Status, error) {
	var st Status
	b, err := os.ReadFile(u.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return Status{}, fmt.Errorf("updater: corrupt %s: %w", u.statePath(), err)
	}
	return st, nil
}

func (u *Updater) writeState(st Status) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := u.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("updater: write state: %w", err)
	}
	if err := os.Rename(tmp, u.statePath()); err != nil {
		return fmt.Errorf("updater: write state: %w", err)
	}
	return nil
}

func (u *Updater) recordError(cause error) {
	st, err := u.Status()
	if err != nil {
		st = Status{}
	}
	st.LastError, st.LastErrorAt = cause.Error(), u.cfg.Now()
	if err := os.MkdirAll(u.cfg.Dir, 0o750); err == nil {
		if werr := u.writeState(st); werr != nil {
			u.cfg.Logger.Warn("nuclei templates: could not record update error", "err", werr)
		}
	}
	u.cfg.Logger.Warn("nuclei template update failed; keeping the last good templates", "err", cause)
}

// prune removes releases that are neither current nor previous.
func (u *Updater) prune(current string) {
	keep := map[string]bool{current: true}
	if t, err := os.Readlink(filepath.Join(u.cfg.Dir, "previous")); err == nil {
		keep[filepath.Base(t)] = true
	}
	ents, err := os.ReadDir(filepath.Join(u.cfg.Dir, "releases"))
	if err != nil {
		return
	}
	for _, e := range ents {
		if keep[e.Name()] || u.withinGrace(e.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(u.cfg.Dir, "releases", e.Name())); err != nil {
			u.cfg.Logger.Warn("nuclei templates: prune failed", "release", e.Name(), "err", err)
		}
	}
}

// withinGrace reports whether a release directory (named <version>-<UTC
// timestamp>) was installed less than PruneGrace ago.
func (u *Updater) withinGrace(name string) bool {
	i := strings.LastIndexByte(name, '-')
	if i < 0 {
		return false
	}
	ts, err := time.Parse("20060102T150405", name[i+1:])
	return err == nil && u.cfg.Now().Sub(ts) < u.cfg.PruneGrace
}

// cleanStaging removes staging directories left by a crashed update and
// per-scan state directories left by a crashed process (a scan is bounded by
// its run timeout, far below runDirMaxAge).
func (u *Updater) cleanStaging(now time.Time) {
	if runs, err := os.ReadDir(filepath.Join(u.cfg.Dir, "run")); err == nil {
		for _, e := range runs {
			if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > runDirMaxAge {
				_ = os.RemoveAll(filepath.Join(u.cfg.Dir, "run", e.Name()))
			}
		}
	}
	ents, err := os.ReadDir(u.cfg.Dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "staging-") {
			continue
		}
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > defaultStagingMaxAge {
			_ = os.RemoveAll(filepath.Join(u.cfg.Dir, e.Name()))
		}
	}
}

// ---- process environment -----------------------------------------------------

// passthrough are the only variables inherited from deckard's environment:
// enough for DNS/TLS/proxy/GitHub rate limits, nothing that holds secrets.
var passthrough = []string{"PATH", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GITHUB_TOKEN"}

// nucleiEnv builds the environment for a nuclei process whose writable state
// lives under root. templatesDir, when set, is nuclei's template directory.
func nucleiEnv(root, templatesDir string) []string {
	cfg := filepath.Join(root, "config")
	env := []string{
		"HOME=" + root,
		"XDG_CONFIG_HOME=" + cfg,
		"XDG_CACHE_HOME=" + filepath.Join(root, "cache"),
		"NUCLEI_CONFIG_DIR=" + filepath.Join(cfg, "nuclei"),
		"TMPDIR=" + filepath.Join(root, "tmp"),
	}
	if templatesDir != "" {
		env = append(env, "NUCLEI_TEMPLATES_DIR="+templatesDir)
	}
	for _, k := range passthrough {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// ScanEnv returns the environment for one nuclei scan run plus a cleanup
// function. Each run gets its own throwaway HOME/XDG tree under <dir>/run so
// concurrent runs never share nuclei's config files and a read-only root
// filesystem is no obstacle. NUCLEI_TEMPLATES_DIR points at the active
// release so templates resolve their relative includes.
func (u *Updater) ScanEnv() ([]string, func(), error) {
	run := filepath.Join(u.cfg.Dir, "run")
	if err := os.MkdirAll(run, 0o750); err != nil {
		return nil, func() {}, err
	}
	root, err := os.MkdirTemp(run, "scan-")
	if err != nil {
		return nil, func() {}, err
	}
	for _, d := range []string{"config/nuclei", "cache", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			_ = os.RemoveAll(root)
			return nil, func() {}, err
		}
	}
	active, _, err := u.ActiveDir()
	if err != nil {
		_ = os.RemoveAll(root)
		return nil, func() {}, err
	}
	return nucleiEnv(root, active), func() { _ = os.RemoveAll(root) }, nil
}

func tail(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 512 {
		b = b[len(b)-512:]
	}
	return string(b)
}
