package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// TestMain doubles as the plugin: when DECKARD_PLUGIN_MODE is set the test
// binary behaves as an exec plugin instead of running tests.
func TestMain(m *testing.M) {
	if mode := os.Getenv("DECKARD_PLUGIN_MODE"); mode != "" {
		os.Exit(helperPlugin(mode))
	}
	os.Exit(m.Run())
}

func helperPlugin(mode string) int {
	in, _ := io.ReadAll(os.Stdin)
	var req map[string]any
	_ = json.Unmarshal(in, &req)
	switch mode {
	case "echo":
		asset, _ := req["asset"].(map[string]any)
		cwd, _ := os.Getwd()
		var envNames []string
		for _, e := range os.Environ() {
			envNames = append(envNames, strings.SplitN(e, "=", 2)[0])
		}
		out := map[string]any{
			"observations": []any{map[string]any{"check": "spoofed", "data": map[string]any{
				"version": req["version"], "check": req["check"], "cwd": cwd, "env": envNames,
				"neighbours": len(req["neighbours"].([]any)), "config": req["config"]}}},
			"findings": []any{
				map[string]any{"check": "spoofed", "key": "k1", "severity": "high", "title": "found " + fmt.Sprint(asset["key"]), "description": "d"},
				map[string]any{"key": "bad-sev", "severity": "catastrophic", "title": "x"},
				map[string]any{"key": "no-title", "severity": "low", "title": "  "},
			},
			"discovered": []any{
				map[string]any{"kind": "hostname", "key": "x.example.com"},
				map[string]any{"kind": "hostname", "key": "z.example.com", "source": "cloudflare"},
				map[string]any{"kind": "banana", "key": "y"},
				map[string]any{"kind": "ip", "key": ""},
			},
			"relations": []any{
				map[string]any{"from_kind": "hostname", "from_key": "a", "to_kind": "ip", "to_key": "192.0.2.1", "type": "resolves_to"},
				map[string]any{"from_kind": "hostname", "from_key": "a", "to_kind": "ip", "to_key": "192.0.2.1", "type": "nonsense"},
			},
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
	case "noisy": // verbose logging must not fail an otherwise good run
		for i := 0; i < 64; i++ {
			_, _ = os.Stderr.WriteString(strings.Repeat("x", 1023) + "\n")
		}
		_, _ = os.Stdout.WriteString(`{"findings":[{"severity":"low","title":"ok"}]}`)
	case "badjson":
		_, _ = os.Stdout.WriteString("not json at all")
	case "twoobjects":
		_, _ = os.Stdout.WriteString(`{"findings":[]} {"findings":[]}`)
	case "fail":
		_, _ = os.Stdout.WriteString(`{"findings":[{"severity":"high","title":"partial"}]}`)
		_, _ = os.Stderr.WriteString("boom: something broke\n")
		return 3
	case "sleep":
		time.Sleep(30 * time.Second)
	case "bigout":
		chunk := strings.Repeat("a", 1<<20)
		_, _ = os.Stdout.WriteString(`{"findings":[],"pad":"`)
		for i := 0; i < 8; i++ {
			_, _ = os.Stdout.WriteString(chunk)
		}
	case "spawn": // child that would outlive the plugin; the pgid kill must reap it
		pid := os.Getpid()
		_ = os.WriteFile(os.Getenv("DECKARD_PIDFILE"), []byte(fmt.Sprint(pid)), 0o600)
		time.Sleep(30 * time.Second)
	}
	return 0
}

func scope(hosts ...string) ScopeVerifier {
	return func(_ context.Context, h string) bool {
		for _, x := range hosts {
			if x == h {
				return true
			}
		}
		return false
	}
}

func cfgFor(mode string, extra map[string]any) config.PluginConfig {
	cfg := map[string]any{"passthrough_env": []any{"DECKARD_PLUGIN_MODE", "DECKARD_PIDFILE"}}
	for k, v := range extra {
		cfg[k] = v
	}
	t := os.Setenv("DECKARD_PLUGIN_MODE", mode)
	_ = t
	return config.PluginConfig{Name: "demo", Exec: []string{os.Args[0]}, Tier: "active",
		Applies: config.PluginApplies{Kind: "url"}, Timeout: 10 * time.Second, Config: cfg}
}

func urlTarget() check.Target {
	return check.Target{Asset: model.Asset{Kind: model.KindURL, Key: "https://app.example.com/x", Scope: model.ScopeOwned},
		Neighbours: []check.Neighbour{
			{Asset: model.Asset{Kind: model.KindHostname, Key: "app.example.com"}, Relation: model.RelServes},
			{Asset: model.Asset{Kind: model.KindHostname, Key: "other.example.net"}, Relation: model.RelServes},
		}}
}

func TestProtocolRoundTrip(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "should-not-leak")
	c := New(cfgFor("echo", map[string]any{"threshold": 3}), scope("app.example.com"))
	if c.Name() != "plugin.demo" || c.Tier() != model.TierActive {
		t.Fatal("identity")
	}
	res, err := c.Run(context.Background(), urlTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("invalid findings not dropped: %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Check != "plugin.demo" || f.Title != "found https://app.example.com/x" || f.Severity != model.SeverityHigh {
		t.Errorf("finding %+v", f)
	}
	if len(res.Discovered) != 2 || res.Discovered[0].Key != "x.example.com" || res.Discovered[1].Key != "z.example.com" {
		t.Errorf("discovered %+v", res.Discovered)
	}
	// What a check discovers is derived (garbage-collected when no longer
	// observed), never source-owned, whatever source the plugin claims.
	for _, a := range res.Discovered {
		if a.Source != "check:plugin.demo" || !store.IsDerivedSource(a.Source) {
			t.Errorf("discovered %s has source %q, want derived check:plugin.demo", a.Key, a.Source)
		}
	}
	if len(res.Relations) != 1 {
		t.Errorf("relations %+v", res.Relations)
	}
	if len(res.Observations) != 1 || res.Observations[0].Check != "plugin.demo" {
		t.Fatalf("obs %+v", res.Observations)
	}
	d := res.Observations[0].Data
	if d["version"] != float64(1) || d["check"] != "plugin.demo" {
		t.Errorf("request fields: %v", d)
	}
	if d["neighbours"] != float64(1) {
		t.Errorf("out-of-scope neighbour leaked: %v", d["neighbours"])
	}
	if cfg := d["config"].(map[string]any); cfg["threshold"] != float64(3) {
		t.Errorf("config: %v", cfg)
	}
	cwd := d["cwd"].(string)
	if !strings.Contains(cwd, "deckard-plugin-") {
		t.Errorf("cwd %s", cwd)
	}
	if _, err := os.Stat(cwd); err == nil {
		t.Error("temp dir not cleaned")
	}
	var names []string
	for _, e := range d["env"].([]any) {
		names = append(names, e.(string))
	}
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "SECRET_TOKEN") {
		t.Errorf("env leaked: %v", names)
	}
	for _, want := range []string{"PATH", "DECKARD_PLUGIN_MODE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("env missing %s: %v", want, names)
		}
	}
}

func TestFailureModesYieldNoPartialResults(t *testing.T) {
	tests := []struct {
		mode    string
		timeout time.Duration
		wantErr string
	}{
		{"badjson", 0, "invalid JSON"},
		{"twoobjects", 0, "exactly one"},
		{"fail", 0, "exit status 3"},
		{"bigout", 0, "exceeded"},
		{"sleep", 300 * time.Millisecond, "deadline exceeded"},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := cfgFor(tc.mode, nil)
			if tc.timeout > 0 {
				cfg.Timeout = tc.timeout
			}
			start := time.Now()
			res, err := New(cfg, scope("app.example.com")).Run(context.Background(), urlTarget())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v want %q", err, tc.wantErr)
			}
			if res != nil {
				t.Errorf("partial result returned: %+v", res)
			}
			if time.Since(start) > 8*time.Second {
				t.Error("too slow: timeout not enforced")
			}
		})
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	pidfile := t.TempDir() + "/pid"
	t.Setenv("DECKARD_PIDFILE", pidfile)
	cfg := cfgFor("spawn", nil)
	cfg.Timeout = 500 * time.Millisecond
	if _, err := New(cfg, scope("app.example.com")).Run(context.Background(), urlTarget()); err == nil {
		t.Fatal("expected timeout")
	}
	b, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	_, _ = fmt.Sscan(string(b), &pid)
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		t.Errorf("plugin process %d still alive", pid)
	}
}

func TestOutOfScopeAssetNotSent(t *testing.T) {
	cfg := cfgFor("echo", nil)
	cfg.Exec = []string{"/nonexistent/should-never-run"}
	tests := []struct {
		name   string
		verify ScopeVerifier
	}{
		{"unowned", scope("other.example.com")},
		{"nil verifier", nil},
	}
	for _, tc := range tests {
		_, err := New(cfg, tc.verify).Run(context.Background(), urlTarget())
		if err == nil || !strings.Contains(err.Error(), "not in scope") {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestApplies(t *testing.T) {
	c := New(cfgFor("echo", nil), nil)
	if !c.Applies(model.Asset{Kind: model.KindURL}) || c.Applies(model.Asset{Kind: model.KindIP}) {
		t.Error("kind filter")
	}
	cfg := cfgFor("echo", nil)
	cfg.Applies.Kind = ""
	if New(cfg, nil).Applies(model.Asset{Kind: model.KindURL}) {
		t.Error("empty kind must not match everything")
	}
}

func TestTierFromConfig(t *testing.T) {
	for tier, want := range map[string]model.Tier{"passive": model.TierPassive, "intrusive": model.TierIntrusive, "": model.TierIntrusive, "bogus": model.TierIntrusive} {
		cfg := cfgFor("echo", nil)
		cfg.Tier = tier
		if got := New(cfg, nil).Tier(); got != want {
			t.Errorf("%q: %s want %s", tier, got, want)
		}
	}
}

func TestChecksSkipsInvalid(t *testing.T) {
	good := cfgFor("echo", nil)
	cs := Checks([]config.PluginConfig{good, {Name: "noexec"}, {Exec: []string{"x"}}}, nil)
	if len(cs) != 1 || cs[0].Name() != "plugin.demo" {
		t.Fatalf("%v", cs)
	}
}

func TestAssetHost(t *testing.T) {
	tests := []struct {
		a    model.Asset
		want string
	}{
		{model.Asset{Kind: model.KindURL, Key: "https://a.example.com:8443/p"}, "a.example.com"},
		{model.Asset{Kind: model.KindService, Key: "192.0.2.1:443/tcp"}, "192.0.2.1"},
		{model.Asset{Kind: model.KindService, Key: "x", Attrs: map[string]any{"ip": "192.0.2.5"}}, "192.0.2.5"},
		{model.Asset{Kind: model.KindHostname, Key: "a.example.com"}, "a.example.com"},
		{model.Asset{Kind: model.KindZone, Key: "example.com"}, ""},
	}
	for _, tc := range tests {
		if got := assetHost(tc.a); got != tc.want {
			t.Errorf("%+v: %q", tc.a, got)
		}
	}
}

func TestVerboseStderrDoesNotFailRun(t *testing.T) {
	c := New(cfgFor("noisy", nil), scope("app.example.com"))
	res, err := c.Run(context.Background(), urlTarget())
	if err != nil {
		t.Fatalf("64 KiB of stderr failed the run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings %+v", res.Findings)
	}
}

// The plugin runs in a fresh temp directory, so a relative exec path such as
// "plugins/check.py" must be resolved against deckard's working directory,
// not the plugin's, or it can never be found.
func TestRelativeExecPathResolvedFromWorkingDir(t *testing.T) {
	t.Chdir(filepath.Dir(os.Args[0]))
	cfg := cfgFor("echo", nil)
	cfg.Exec = []string{"." + string(filepath.Separator) + filepath.Base(os.Args[0])}
	c := New(cfg, scope("app.example.com"))

	if _, err := c.Run(context.Background(), urlTarget()); err != nil {
		t.Fatalf("relative exec path: %v", err)
	}
}
