package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "deckard.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Format != "json" || cfg.Log.Level != "info" {
		t.Errorf("log defaults = %+v", cfg.Log)
	}
	if cfg.Sync.Interval != 10*time.Minute {
		t.Errorf("sync interval = %v", cfg.Sync.Interval)
	}
	if !cfg.Profiles.Passive.Enabled || cfg.Profiles.Passive.Interval != 5*time.Minute {
		t.Errorf("passive = %+v", cfg.Profiles.Passive)
	}
	if cfg.Profiles.Intrusive.Enabled {
		t.Error("intrusive must default to disabled")
	}
	if cfg.Findings.ResolveAfter != 2 || cfg.Learning.StableAfter != 3 {
		t.Errorf("findings/learning defaults: %+v %+v", cfg.Findings, cfg.Learning)
	}
	if cfg.Scope.MaxCIDRHosts != 1024 {
		t.Errorf("max cidr hosts = %d", cfg.Scope.MaxCIDRHosts)
	}
	if cfg.Expansion.Interval != 6*time.Hour || !cfg.Expansion.CTLogs {
		t.Errorf("expansion defaults = %+v", cfg.Expansion)
	}
	if r := cfg.Refdata; !r.Enabled || r.Interval != 24*time.Hour || r.Dir != "/var/lib/deckard/refdata" ||
		r.Timeout != 30*time.Second || !r.Datasets.TakeoverFingerprints || !r.Datasets.SharedRanges {
		t.Errorf("refdata defaults = %+v", r)
	}
	if !cfg.Profiles.Active.OnInventoryChange {
		t.Error("active.on_inventory_change must default to true")
	}
	if cfg.Profiles.Intrusive.OnInventoryChange {
		t.Error("intrusive.on_inventory_change must default to false")
	}
	if cfg.Notify.Alertmanager.MinSeverity != "info" {
		t.Errorf("notify.alertmanager.min_severity must default to info (notify everything), got %q", cfg.Notify.Alertmanager.MinSeverity)
	}
}

func TestHeartbeatConfig(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if h := cfg.Notify.Heartbeat; h.Enabled() || h.Interval != 5*time.Minute || h.Method != "GET" || h.Timeout != 10*time.Second {
		t.Fatalf("heartbeat defaults = %+v (want disabled, 5m, GET, 10s)", h)
	}
	// Invalid method/interval only matter once a URL turns the heartbeat on.
	if _, err := Load(writeCfg(t, "notify: {heartbeat: {method: PUT, interval: 0s}}"), nil); err != nil {
		t.Fatalf("disabled heartbeat must not be validated: %v", err)
	}
	secret := "https://user:pw@hc-ping.example/0b1c2d3e-uuid?token=SECRET"
	cfg, err = Load("", []string{"DECKARD_NOTIFY__HEARTBEAT__URL=" + secret, "DECKARD_NOTIFY__HEARTBEAT__METHOD=post"})
	if err != nil || !cfg.Notify.Heartbeat.Enabled() {
		t.Fatalf("env: %v", err)
	}
	_, err = Load("", []string{"DECKARD_NOTIFY__HEARTBEAT__URL=ftp://user:pw@hc-ping.example/0b1c2d3e-uuid?token=SECRET"})
	if err == nil {
		t.Fatal("ftp heartbeat url accepted")
	}
	for _, leak := range []string{"SECRET", "pw@", "0b1c2d3e", "hc-ping"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("validation error leaks %q: %v", leak, err)
		}
	}
}

func TestNotifyMinSeverityFromFileAndEnv(t *testing.T) {
	cfg, err := Load(writeCfg(t, "notify: {alertmanager: {min_severity: medium}}"), nil)
	if err != nil || cfg.Notify.Alertmanager.MinSeverity != "medium" {
		t.Fatalf("file: %v %q", err, cfg.Notify.Alertmanager.MinSeverity)
	}
	cfg, err = Load("", []string{"DECKARD_NOTIFY__ALERTMANAGER__MIN_SEVERITY=high"})
	if err != nil || cfg.Notify.Alertmanager.MinSeverity != "high" {
		t.Fatalf("env: %v", err)
	}
}

func TestCheckOptions(t *testing.T) {
	d, ok, err := CheckInterval(map[string]any{"interval": "30m"})
	if err != nil || !ok || d != 30*time.Minute {
		t.Fatalf("string interval: %v %v %v", d, ok, err)
	}
	if d, ok, err := CheckInterval(map[string]any{"interval": 2 * time.Hour}); err != nil || !ok || d != 2*time.Hour {
		t.Fatalf("duration interval: %v %v %v", d, ok, err)
	}
	if _, ok, err := CheckInterval(nil); ok || err != nil {
		t.Fatalf("absent interval: %v %v", ok, err)
	}
	if _, _, err := CheckInterval(map[string]any{"interval": 5}); err == nil {
		t.Fatal("bare integer interval must be rejected")
	}
	if v, ok, err := CheckOnNewAsset(map[string]any{"on_new_asset": false}); err != nil || !ok || v {
		t.Fatalf("on_new_asset false: %v %v %v", v, ok, err)
	}
	if _, ok, _ := CheckOnNewAsset(map[string]any{}); ok {
		t.Fatal("absent on_new_asset must report ok=false")
	}
	if cfg, err := Load(writeCfg(t, "checks: {unknown.plugin: {interval: 10m, on_new_asset: false}}"), nil); err != nil || cfg == nil {
		t.Fatalf("unknown check names must be allowed: %v", err)
	}
}

func TestLoadFileAndEnvOverride(t *testing.T) {
	p := writeCfg(t, `
database: { url: "postgres://file/db" }
sync: { interval: 30m }
sources:
  - { name: cf, type: cloudflare, token_env: CF_API_TOKEN }
`)
	env := []string{"DECKARD_DATABASE__URL=postgres://env/db", "DECKARD_LOG__LEVEL=debug"}
	cfg, err := Load(p, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.URL != "postgres://env/db" {
		t.Errorf("env should win, got %q", cfg.Database.URL)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("level = %q", cfg.Log.Level)
	}
	if cfg.Sync.Interval != 30*time.Minute {
		t.Errorf("interval = %v", cfg.Sync.Interval)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].TokenEnv != "CF_API_TOKEN" {
		t.Errorf("sources = %+v", cfg.Sources)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown source type", "sources: [{name: x, type: nope}]", "unknown type"},
		{"duplicate source name", "sources: [{name: a, type: static},{name: a, type: static}]", "duplicate"},
		{"missing source name", "sources: [{type: static}]", "name"},
		{"bad level", "log: {level: loud}", "log.level"},
		{"bad rate limit", "profiles: {active: {rate_limit: fast}}", "rate_limit"},
		{"zero interval", "profiles: {passive: {interval: 0s}}", "interval"},
		{"oversized cidr", "scope: {max_cidr_hosts: 256}\nsources: [{name: s, type: static, cidrs: [10.0.0.0/16]}]", "max_cidr_hosts"},
		{"bad cidr", "sources: [{name: s, type: static, cidrs: [nonsense]}]", "cidr"},
		{"bad plugin tier", "plugins: [{name: p, exec: [/bin/true], tier: wild}]", "tier"},
		{"plugin no exec", "plugins: [{name: p, tier: active}]", "exec"},
		{"unknown group profile tier", "asset_groups: [{name: g, profiles: {wild: {}}}]", "asset_groups"},
		{"oidc missing issuer", "auth: {mode: oidc}", "issuer"},
		{"empty ignore key", "learning: {ignore_keys: {tls.cert: [\"\"]}}", "learning.ignore_keys"},
		{"bad auth mode", "auth: {mode: magic}", "auth.mode"},
		{"zero expansion interval", "expansion: {interval: 0s}", "expansion.interval"},
		{"refdata interval too small", "refdata: {interval: 1m}", "refdata.interval"},
		{"refdata zero timeout", "refdata: {timeout: 0s}", "refdata.timeout"},
		{"refdata no datasets", "refdata: {datasets: {takeover_fingerprints: false, shared_ranges: false}}", "refdata.datasets"},
		{"bad check interval", "checks: {dns.records: {interval: soon}}", "checks.dns.records.interval"},
		{"negative check interval", "checks: {x: {interval: -5m}}", "checks.x.interval"},
		{"vulnintel zero interval", "vulnintel: {interval: 0s}", "vulnintel.interval"},
		{"vulnintel zero timeout", "vulnintel: {timeout: 0s}", "vulnintel.timeout"},
		{"vulnintel empty dir", "vulnintel: {dir: \"\"}", "vulnintel.dir"},
		{"vulnintel bad floor", "vulnintel: {kev_floor: urgent}", "vulnintel.kev_floor"},
		{"vulnintel epss out of range", "vulnintel: {epss_high: 1.5}", "vulnintel.epss_high"},
		{"vulnintel epss order", "vulnintel: {epss_high: 0.2, epss_medium: 0.5}", "vulnintel.epss_medium"},
		{"bad on_new_asset", "checks: {x: {on_new_asset: maybe}}", "on_new_asset"},
		{"bad notify floor", "notify: {alertmanager: {min_severity: urgent}}", "notify.alertmanager.min_severity \"urgent\": must be info|low|medium|high|critical"},
		{"heartbeat not http", "notify: {heartbeat: {url: \"ftp://hc.example/abc\"}}", "notify.heartbeat.url must be an absolute http(s) URL"},
		{"heartbeat relative", "notify: {heartbeat: {url: /ping}}", "notify.heartbeat.url"},
		{"heartbeat bad method", "notify: {heartbeat: {url: \"https://hc.example/x\", method: PUT}}", "notify.heartbeat.method \"PUT\": must be GET or POST"},
		{"heartbeat zero interval", "notify: {heartbeat: {url: \"https://hc.example/x\", interval: 0s}}", "notify.heartbeat.interval"},
		{"heartbeat zero timeout", "notify: {heartbeat: {url: \"https://hc.example/x\", timeout: 0s}}", "notify.heartbeat.timeout"},
		{"gcpdns without projects", "sources: [{name: g, type: gcpdns}]", "gcpdns needs projects"},
		{"gcpdns empty projects", "sources: [{name: g, type: gcpdns, projects: []}]", "gcpdns needs projects"},
		{"gcpdns bad project id", "sources: [{name: g, type: gcpdns, projects: [My_Project]}]", "invalid gcp project id \"My_Project\""},
		{"gcpdns short project id", "sources: [{name: g, type: gcpdns, projects: [abc]}]", "invalid gcp project id"},
		{"gcpdns project id with slash", "sources: [{name: g, type: gcpdns, projects: [\"projects/my-project-a\"]}]", "invalid gcp project id"},
		{"gcpdns duplicate project", "sources: [{name: g, type: gcpdns, projects: [my-project-a, my-project-a]}]", "duplicate project"},
		{"gcpdns empty zone entry", "sources: [{name: g, type: gcpdns, projects: [my-project-a], zones: [\"\"]}]", "zones must not contain empty"},
		{"gcpdns projects wrong type", "sources: [{name: g, type: gcpdns, projects: {a: b}}]", "projects"},
		{"gcpdns include_private wrong type", "sources: [{name: g, type: gcpdns, projects: [my-project-a], include_private: sometimes}]", "include_private"},
		{"reserved source prefix", "sources: [{name: \"ingest:prowler\", type: static}]", "reserved for assets created by the ingest API"},
		{"reserved plugin prefix", "plugins: [{name: ext.prowler, exec: [/bin/true], tier: passive}]", "reserved for findings posted to the ingest API"},
		{"empty notify floor", "notify: {alertmanager: {min_severity: \"\"}}", "notify.alertmanager.min_severity"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeCfg(t, tc.yaml), nil)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestGCPDNSSourceConfig(t *testing.T) {
	cfg, err := Load(writeCfg(t, `
sources:
  - name: gcp
    type: gcpdns
    projects: [my-project-a, "example.com:legacy-project"]
    include_private: true
    zones: [prod-zone, example.org.]
`), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	s := cfg.Sources[0]
	if !slices.Equal(s.Projects, []string{"my-project-a", "example.com:legacy-project"}) || !s.IncludePrivate ||
		!slices.Equal(s.Zones, []string{"prod-zone", "example.org."}) {
		t.Fatalf("gcpdns settings not decoded: %+v", s)
	}
}

func TestParseRate(t *testing.T) {
	tests := []struct {
		in      string
		perSec  float64
		wantErr bool
	}{
		{"50/s", 50, false},
		{"120/m", 2, false},
		{"3600/h", 1, false},
		{"", 0, false},
		{"fast", 0, true},
		{"0/s", 0, true},
		{"-1/s", 0, true},
	}
	for _, tc := range tests {
		got, err := ParseRate(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseRate(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if err == nil && got != tc.perSec {
			t.Errorf("ParseRate(%q) = %v, want %v", tc.in, got, tc.perSec)
		}
	}
}

func TestSecretResolution(t *testing.T) {
	s := SourceConfig{TokenEnv: "MY_TOKEN"}
	if got := s.ResolveToken(func(k string) string {
		if k == "MY_TOKEN" {
			return "abc"
		}
		return ""
	}); got != "abc" {
		t.Errorf("token = %q", got)
	}
	s2 := SourceConfig{Token: "inline"}
	if s2.ResolveToken(func(string) string { return "" }) != "inline" {
		t.Error("inline token should be returned when no env")
	}
}

func TestRefdataDisabledSkipsValidation(t *testing.T) {
	cfg, err := Load(writeCfg(t, "refdata: {enabled: false, interval: 1s}"), nil)
	if err != nil {
		t.Fatalf("air-gapped opt-out must validate: %v", err)
	}
	if cfg.Refdata.Enabled {
		t.Error("enabled should be false")
	}
	cfg, err = Load("", []string{"DECKARD_REFDATA__ENABLED=false", "DECKARD_REFDATA__DIR=/tmp/r"})
	if err != nil || cfg.Refdata.Enabled || cfg.Refdata.Dir != "/tmp/r" {
		t.Errorf("env override: %+v %v", cfg.Refdata, err)
	}
}

func TestVulnintelDefaultsAndOptOut(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	v := cfg.Vulnintel
	if !v.Enabled || v.Interval != 6*time.Hour || v.Dir != "/var/lib/deckard/vulnintel" || v.Timeout != 30*time.Second ||
		v.KEVFloor != "critical" || v.EPSSHigh != 0.7 || v.EPSSMedium != 0.3 {
		t.Fatalf("defaults = %+v", v)
	}
	cfg, err = Load(writeCfg(t, "vulnintel: {enabled: false, interval: 0s, kev_floor: nonsense}"), nil)
	if err != nil {
		t.Fatalf("disabled vulnintel must not be validated: %v", err)
	}
	if cfg.Vulnintel.Enabled {
		t.Fatal("opt-out ignored")
	}
}
