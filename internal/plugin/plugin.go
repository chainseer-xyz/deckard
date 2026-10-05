// Package plugin implements deckard's exec plugin protocol (v1): an external
// executable receives one JSON request on stdin and answers with one JSON
// object on stdout. See docs/plugins.md.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const (
	// ProtocolVersion is the only protocol version spoken.
	ProtocolVersion = 1
	maxStdout       = 4 << 20
	maxStderr       = 16 << 10
	logStderrMax    = 1024
	defaultTimeout  = 60 * time.Second
	maxItems        = 5000
)

// ScopeVerifier reports whether host is owned and resolves only to owned
// addresses. Plugin processes cannot open sockets; their broker uses guarded
// clients and repeats this check for every request.
type ScopeVerifier func(ctx context.Context, host string) bool

// Checks builds one check per configured plugin. Plugins with no exec
// command are skipped (and logged).
func Checks(cfgs []config.PluginConfig, verify ScopeVerifier) []check.Check {
	var out []check.Check
	for _, c := range cfgs {
		if c.Name == "" || len(c.Exec) == 0 {
			slog.Warn("plugin skipped: name and exec are required", "plugin", c.Name)
			continue
		}
		out = append(out, New(c, verify))
	}
	return out
}

type pluginCheck struct {
	cfg    config.PluginConfig
	name   string
	tier   model.Tier
	verify ScopeVerifier
}

// New builds the check for one plugin. The check name is "plugin.<name>". An
// unknown tier is treated as intrusive, the most restrictive.
func New(cfg config.PluginConfig, verify ScopeVerifier) check.Check {
	tier := model.Tier(cfg.Tier)
	if !tier.Valid() {
		slog.Warn("plugin has invalid tier, treating as intrusive", "plugin", cfg.Name, "tier", cfg.Tier)
		tier = model.TierIntrusive
	}
	// The plugin runs in a fresh temp directory, which os/exec would resolve a
	// relative path such as "plugins/check.py" against; anchor it to ours.
	if len(cfg.Exec) > 0 && !filepath.IsAbs(cfg.Exec[0]) && filepath.Base(cfg.Exec[0]) != cfg.Exec[0] {
		if abs, err := filepath.Abs(cfg.Exec[0]); err == nil {
			cfg.Exec = append([]string{abs}, cfg.Exec[1:]...)
		}
	}
	return &pluginCheck{cfg: cfg, name: "plugin." + cfg.Name, tier: tier, verify: verify}
}

func (p *pluginCheck) Name() string                    { return p.name }
func (p *pluginCheck) Tier() model.Tier                { return p.tier }
func (p *pluginCheck) RequiresOwnedDestinations() bool { return true }
func (p *pluginCheck) Applies(a model.Asset) bool {
	return p.cfg.Applies.Kind != "" && string(a.Kind) == p.cfg.Applies.Kind
}

type request struct {
	Version    int             `json:"version"`
	Check      string          `json:"check"`
	Asset      model.Asset     `json:"asset"`
	Neighbours []neighbourJSON `json:"neighbours"`
	Config     map[string]any  `json:"config"`
	Network    networkChannel  `json:"network"`
}

type neighbourJSON struct {
	Asset    model.Asset        `json:"asset"`
	Relation model.RelationType `json:"relation"`
	Outbound bool               `json:"outbound"`
}

type response struct {
	Observations []model.ObservationInput `json:"observations"`
	Findings     []model.FindingInput     `json:"findings"`
	Discovered   []model.AssetInput       `json:"discovered"`
	Relations    []model.RelationInput    `json:"relations"`
}

// assetHost returns the host to scope-check for an asset.
func assetHost(a model.Asset) string {
	switch a.Kind {
	case model.KindURL:
		if u, err := url.Parse(a.Key); err == nil {
			return u.Hostname()
		}
		return ""
	case model.KindService:
		if ip, ok := a.Attrs["ip"].(string); ok && ip != "" {
			return ip
		}
		if h, _, err := net.SplitHostPort(strings.TrimSuffix(a.Key, "/tcp")); err == nil {
			return h
		}
		return ""
	case model.KindHostname, model.KindIP:
		return a.Key
	}
	return "" // zones, certificates, cloud resources have no network host
}

func (p *pluginCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	host := assetHost(t.Asset)
	if host == "" || p.verify == nil || !p.verify(ctx, host) {
		return nil, fmt.Errorf("%s: asset %s is not in scope for plugins", p.name, t.Asset.Key)
	}
	req := request{Version: ProtocolVersion, Check: p.name, Asset: t.Asset, Neighbours: []neighbourJSON{}, Config: p.cfg.Config,
		Network: networkChannel{RequestFD: 4, ResponseFD: 3}}
	if req.Config == nil {
		req.Config = map[string]any{}
	}
	for _, n := range t.Neighbours {
		if h := assetHost(n.Asset); h != "" && p.verify(ctx, h) { // only in-scope neighbours are shared
			req.Neighbours = append(req.Neighbours, neighbourJSON{Asset: n.Asset, Relation: n.Relation, Outbound: n.Outbound})
		}
	}
	stdin, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%s: encode request: %w", p.name, err)
	}
	out, err := p.exec(ctx, stdin, t)
	if err != nil {
		return nil, err
	}
	return p.decode(out)
}

func (p *pluginCheck) timeout() time.Duration {
	if p.cfg.Timeout > 0 {
		return p.cfg.Timeout
	}
	return defaultTimeout
}

// passthroughEnv lists env var names the operator allowed via
// config.passthrough_env.
func (p *pluginCheck) passthroughEnv() []string {
	var names []string
	switch v := p.cfg.Config["passthrough_env"].(type) {
	case []string:
		names = v
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				names = append(names, s)
			}
		}
	}
	return names
}

func (p *pluginCheck) env() []string {
	env := []string{"PATH=" + os.Getenv("PATH")}
	for _, n := range p.passthroughEnv() {
		if n == "" || strings.ContainsAny(n, "=\x00") || n == "PATH" {
			continue
		}
		if v, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+v)
		}
	}
	return env
}

type limitWriter struct {
	buf    bytes.Buffer
	max    int
	over   bool
	cancel context.CancelFunc
}

func (l *limitWriter) Write(b []byte) (int, error) {
	if l.buf.Len()+len(b) > l.max {
		l.over = true
		if l.cancel != nil {
			l.cancel()
		}
		return 0, errors.New("output limit exceeded")
	}
	return l.buf.Write(b)
}

// truncWriter keeps the first max bytes and silently drops the rest: a
// write error would make os/exec stop draining the pipe, killing the child
// with SIGPIPE or failing Wait, so log volume alone would fail a good run.
type truncWriter struct {
	buf bytes.Buffer
	max int
}

func (l *truncWriter) Write(b []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		l.buf.Write(b[:min(len(b), room)])
	}
	return len(b), nil
}

func (p *pluginCheck) exec(ctx context.Context, stdin []byte, target check.Target) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	dir, err := os.MkdirTemp("", "deckard-plugin-*")
	if err != nil {
		return nil, fmt.Errorf("%s: temp dir: %w", p.name, err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	cmd, err := sandboxCommand(ctx, p.cfg.Exec)
	if err != nil {
		return nil, fmt.Errorf("%s: network sandbox: %w", p.name, err)
	}
	channel, err := newBroker(p, target)
	if err != nil {
		return nil, err
	}
	defer channel.close()
	cmd.ExtraFiles = []*os.File{channel.responsesRead, channel.requestsWrite}
	cmd.Dir = dir
	cmd.Env = p.env()
	cmd.Stdin = bytes.NewReader(stdin)
	stdout := &limitWriter{max: maxStdout, cancel: cancel}
	stderr := &truncWriter{max: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	setProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: start: %w", p.name, err)
	}
	// Only the child owns these ends after Start. EOF now tracks child exit.
	_ = channel.responsesRead.Close()
	_ = channel.requestsWrite.Close()
	brokerCtx, stopBroker := context.WithCancel(ctx)
	defer stopBroker()
	done := make(chan error, 1)
	go func() { done <- channel.serve(brokerCtx) }()
	runErr := cmd.Wait()
	stopBroker()
	// A plugin need not read its response. Closing both ends also releases a
	// broker blocked by a malformed or abandoned request when the child exits.
	_ = channel.requestsRead.Close()
	_ = channel.responsesWrite.Close()
	brokerErr := <-done
	if s := strings.TrimSpace(stderr.buf.String()); s != "" {
		if len(s) > logStderrMax {
			s = s[:logStderrMax] + "...(truncated)"
		}
		slog.Warn("plugin stderr", "plugin", p.name, "stderr", s)
	}
	switch {
	case stdout.over:
		return nil, fmt.Errorf("%s: stdout exceeded %d bytes", p.name, maxStdout)
	case ctx.Err() != nil:
		return nil, fmt.Errorf("%s: %w", p.name, ctx.Err())
	case runErr != nil:
		return nil, fmt.Errorf("%s: %w", p.name, runErr)
	case brokerErr != nil:
		return nil, fmt.Errorf("%s: guarded network request failed: %w", p.name, brokerErr)
	}
	return stdout.buf.Bytes(), nil
}

// decode parses exactly one JSON object and validates its contents.
func (p *pluginCheck) decode(out []byte) (*check.Result, error) {
	dec := json.NewDecoder(bytes.NewReader(out))
	var resp response
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON on stdout: %w", p.name, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: stdout must contain exactly one JSON object", p.name)
	}
	res := &check.Result{}
	for i, o := range resp.Observations {
		if i >= maxItems {
			break
		}
		if o.Data == nil {
			o.Data = map[string]any{}
		}
		o.Check = p.name
		res.Observations = append(res.Observations, o)
	}
	for i, f := range resp.Findings {
		if i >= maxItems {
			break
		}
		f.Check = p.name
		if !f.Severity.Valid() || strings.TrimSpace(f.Title) == "" {
			slog.Warn("plugin finding dropped", "plugin", p.name, "index", i, "severity", f.Severity)
			continue
		}
		if f.Key == "" {
			f.Key = f.Title
		}
		res.Findings = append(res.Findings, f)
	}
	p.keepAssets(&resp, res)
	return res, nil
}

var validKinds = map[model.AssetKind]bool{
	model.KindZone: true, model.KindHostname: true, model.KindIP: true, model.KindService: true,
	model.KindURL: true, model.KindCertificate: true, model.KindCloudResource: true,
}

var validRels = map[model.RelationType]bool{
	model.RelResolvesTo: true, model.RelCNAMETo: true, model.RelAliasTo: true, model.RelProxiedBy: true,
	model.RelOriginOf: true, model.RelServes: true, model.RelExposes: true, model.RelHasCert: true, model.RelInZone: true,
}

func (p *pluginCheck) keepAssets(resp *response, res *check.Result) {
	for i, a := range resp.Discovered {
		if i >= maxItems {
			break
		}
		if !validKinds[a.Kind] || strings.TrimSpace(a.Key) == "" {
			slog.Warn("plugin discovered asset dropped", "plugin", p.name, "kind", a.Kind, "key", a.Key)
			continue
		}
		// A check's discoveries are derived assets, garbage-collected once no
		// longer observed. A plugin-chosen source would make them source-owned
		// (never collected) or let a plugin write as a real source.
		a.Source = checkutil.Source(p.name)
		res.Discovered = append(res.Discovered, a)
	}
	for i, r := range resp.Relations {
		if i >= maxItems {
			break
		}
		if !validKinds[r.FromKind] || !validKinds[r.ToKind] || r.FromKey == "" || r.ToKey == "" || !validRels[r.Type] {
			slog.Warn("plugin relation dropped", "plugin", p.name, "type", r.Type)
			continue
		}
		res.Relations = append(res.Relations, r)
	}
}
