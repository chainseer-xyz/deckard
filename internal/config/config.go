// Package config loads deckard's YAML + environment configuration, applies
// defaults and validates it. Environment variables use the DECKARD_ prefix with
// "__" as the nesting separator (DECKARD_DATABASE__URL -> database.url) and
// always win over the file.
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const EnvPrefix = "DECKARD_"

// Config is the full operator configuration.
type Config struct {
	Server       ServerConfig              `koanf:"server"`
	Log          LogConfig                 `koanf:"log"`
	Database     DatabaseConfig            `koanf:"database"`
	Sync         SyncConfig                `koanf:"sync"`
	Scheduling   SchedulingConfig          `koanf:"scheduling"`
	Retention    RetentionConfig           `koanf:"retention"`
	Sources      []SourceConfig            `koanf:"sources"`
	Scope        ScopeConfig               `koanf:"scope"`
	Profiles     Profiles                  `koanf:"profiles"`
	Expansion    ExpansionConfig           `koanf:"expansion"`
	Refdata      RefdataConfig             `koanf:"refdata"`
	Learning     LearningConfig            `koanf:"learning"`
	Checks       map[string]map[string]any `koanf:"checks"`
	Nuclei       NucleiConfig              `koanf:"nuclei"`
	Plugins      []PluginConfig            `koanf:"plugins"`
	Findings     FindingsConfig            `koanf:"findings"`
	Notify       NotifyConfig              `koanf:"notify"`
	AssetGroups  []AssetGroup              `koanf:"asset_groups"`
	Suppressions []Suppression             `koanf:"suppressions"`
	Auth         AuthConfig                `koanf:"auth"`
	Vulnintel    VulnintelConfig           `koanf:"vulnintel"`
	Intel        IntelConfig               `koanf:"intel"`

	// intelKeyErrs are unknown keys found under intel.* at load (the block is
	// closed; see unknownIntelKeys). Validate reports them.
	intelKeyErrs []string
}

// VulnintelConfig configures exploit-intelligence enrichment (CISA KEV and
// FIRST EPSS). Feeds are fetched from cisa.gov and api.first.org; set
// enabled: false for air-gapped deployments.
type VulnintelConfig struct {
	Enabled  bool          `koanf:"enabled"`
	Interval time.Duration `koanf:"interval"` // feed refresh period
	Dir      string        `koanf:"dir"`      // last-good feed copies
	Timeout  time.Duration `koanf:"timeout"`  // per HTTP request
	// KEVFloor is the minimum severity of a finding for a KEV-listed CVE.
	KEVFloor string `koanf:"kev_floor"`
	// EPSSHigh / EPSSMedium: EPSS scores at or above these raise a finding to
	// at least high / medium.
	EPSSHigh   float64 `koanf:"epss_high"`
	EPSSMedium float64 `koanf:"epss_medium"`
}

type ServerConfig struct {
	HTTPAddr    string `koanf:"http_addr"`
	MetricsAddr string `koanf:"metrics_addr"`
	BaseURL     string `koanf:"base_url"`
	// MetricsTokenEnv names the env var holding a bearer token required on
	// /metrics. Empty (default) leaves the metrics listener open.
	MetricsTokenEnv string   `koanf:"metrics_token_env"`
	Roles           []string `koanf:"roles"` // api, scheduler, worker
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

type DatabaseConfig struct {
	URL      string `koanf:"url"`
	MaxConns int    `koanf:"max_conns"`
}

type SyncConfig struct {
	Interval time.Duration `koanf:"interval"`
}

// SchedulingConfig tunes the job scheduler.
type SchedulingConfig struct {
	// ErrorRetry is the soonest a (asset, check) whose latest attempt failed
	// is retried (capped at the check's own interval).
	ErrorRetry time.Duration `koanf:"error_retry"`
	// QueueWorkers is the max concurrent jobs per River queue: sync, passive,
	// active, intrusive, default, expand.
	QueueWorkers map[string]int `koanf:"queue_workers"`
}

// RetentionConfig bounds how long history is kept.
type RetentionConfig struct {
	Scans     time.Duration `koanf:"scans"`     // scan run history
	Relations time.Duration `koanf:"relations"` // relations touching removed assets
}

// QueueNames are the valid scheduling.queue_workers keys.
var QueueNames = []string{"sync", "passive", "active", "intrusive", "default", "expand", "maintenance"}

// SourceConfig is a union of every source type's settings; unused fields are
// ignored by the other types.
type SourceConfig struct {
	Name string `koanf:"name"`
	Type string `koanf:"type"`

	// cloudflare
	Token     string `koanf:"token"`
	TokenEnv  string `koanf:"token_env"`
	BaseURL   string `koanf:"base_url"`
	AccountID string `koanf:"account_id"`

	// route53
	Region   string `koanf:"region"`
	Profile  string `koanf:"profile"`
	RoleARN  string `koanf:"role_arn"`
	Endpoint string `koanf:"endpoint"`

	// aws (also uses region/profile/role_arn/endpoint above): regions to
	// inventory; when empty, region is used, else us-east-1.
	Regions []string `koanf:"regions"`

	// gcpdns (Application Default Credentials only): project ids to scan,
	// whether private zones are included, and an optional allow-list of managed
	// zone names or DNS names (empty = every eligible zone).
	Projects       []string `koanf:"projects"`
	IncludePrivate bool     `koanf:"include_private"`
	Zones          []string `koanf:"zones"`

	// kubernetes
	Kubeconfig string   `koanf:"kubeconfig"`
	Contexts   []string `koanf:"contexts"`
	InCluster  bool     `koanf:"in_cluster"`

	// static
	Hostnames []string `koanf:"hostnames"`
	IPs       []string `koanf:"ips"`
	CIDRs     []string `koanf:"cidrs"`
	URLs      []string `koanf:"urls"`
}

// ResolveToken returns the token from the named env var, else the inline one.
func (s SourceConfig) ResolveToken(getenv func(string) string) string {
	if s.TokenEnv != "" {
		if v := getenv(s.TokenEnv); v != "" {
			return v
		}
	}
	return s.Token
}

type ScopeConfig struct {
	Include      []string `koanf:"include"`
	Exclude      []string `koanf:"exclude"`
	MaxCIDRHosts int      `koanf:"max_cidr_hosts"`
	// Resolvers are the recursive DNS servers (IP or IP:port) every scan uses
	// instead of the system resolvers. Set public resolvers to see your names the
	// way an outside attacker does (no split-horizon answers).
	Resolvers []string `koanf:"resolvers"`
}

// Profile controls one tier. Pointer-free so group overrides can be merged by
// comparing against defaults at the engine layer.
type Profile struct {
	Enabled            bool          `koanf:"enabled"`
	Interval           time.Duration `koanf:"interval"`
	OnInventoryChange  bool          `koanf:"on_inventory_change"`
	RateLimit          string        `koanf:"rate_limit"`
	PerHostConcurrency int           `koanf:"per_host_concurrency"`
}

type Profiles struct {
	Passive   Profile `koanf:"passive"`
	Active    Profile `koanf:"active"`
	Intrusive Profile `koanf:"intrusive"`
}

type ExpansionConfig struct {
	CTLogs        bool          `koanf:"ct_logs"`
	DNSBruteforce bool          `koanf:"dns_bruteforce"`
	Wordlist      string        `koanf:"wordlist"`
	Interval      time.Duration `koanf:"interval"` // how often each owned zone is expanded
}

// RefdataConfig controls live refresh of the embedded reference datasets
// (takeover fingerprints, shared-infrastructure ranges). The embedded copy
// stays the fallback; disable for air-gapped deployments.
type RefdataConfig struct {
	Enabled  bool          `koanf:"enabled"`
	Interval time.Duration `koanf:"interval"` // how often the sources are re-fetched
	// Dir persists the last good copy (empty = memory only). Must be writable.
	Dir      string          `koanf:"dir"`
	Timeout  time.Duration   `koanf:"timeout"` // per HTTP request
	Datasets RefdataDatasets `koanf:"datasets"`
}

// RefdataDatasets selects which datasets are refreshed.
type RefdataDatasets struct {
	TakeoverFingerprints bool `koanf:"takeover_fingerprints"`
	SharedRanges         bool `koanf:"shared_ranges"`
}

// MinRefdataInterval keeps operators from hammering the public sources.
const MinRefdataInterval = time.Hour

type LearningConfig struct {
	StableAfter int `koanf:"stable_after"`
	// IgnoreKeys lists extra volatile observation keys per check name ("*" =
	// every check) that never count as drift.
	IgnoreKeys map[string][]string `koanf:"ignore_keys"`
}

type NucleiConfig struct {
	Enabled      bool     `koanf:"enabled"`
	Binary       string   `koanf:"binary"`
	TemplatesDir string   `koanf:"templates_dir"`
	SeverityMin  string   `koanf:"severity_min"`
	TagsExclude  []string `koanf:"tags_exclude"`
	ExtraTags    []string `koanf:"extra_tags"`
	// ScanMode is "tech" (default: templates selected by detected technology,
	// with a generic fallback) or "all" (every non-excluded template).
	ScanMode string             `koanf:"scan_mode"`
	Update   NucleiUpdateConfig `koanf:"update"`
}

// NucleiUpdateConfig drives the continuous template updater.
type NucleiUpdateConfig struct {
	Enabled bool `koanf:"enabled"`
	// Interval is how often the updater looks for a new template release.
	Interval time.Duration `koanf:"interval"`
	// Dir is the writable state root: releases, the current symlink, and the
	// HOME/XDG directories nuclei writes into.
	Dir string `koanf:"dir"`
	// Timeout bounds one update (download plus validation).
	Timeout time.Duration `koanf:"timeout"`
	// RunNewTemplates scans every owned web asset with the templates an update
	// added, right after the update.
	RunNewTemplates bool `koanf:"run_new_templates"`
	// MaxAgeWarn is the template age after which the staleness alert fires.
	MaxAgeWarn time.Duration `koanf:"max_age_warn"`
}

// UpdateCurrentDir is the updater's current-templates path (a symlink to the
// active release).
func (n NucleiConfig) UpdateCurrentDir() string {
	if n.Update.Dir == "" {
		return ""
	}
	return filepath.Join(n.Update.Dir, "current")
}

type PluginConfig struct {
	Name    string         `koanf:"name"`
	Exec    []string       `koanf:"exec"`
	Tier    string         `koanf:"tier"`
	Applies PluginApplies  `koanf:"applies"`
	Timeout time.Duration  `koanf:"timeout"`
	Config  map[string]any `koanf:"config"`
}

type PluginApplies struct {
	Kind string `koanf:"kind"`
}

type FindingsConfig struct {
	ResolveAfter int `koanf:"resolve_after"`
}

type NotifyConfig struct {
	Alertmanager AlertmanagerConfig `koanf:"alertmanager"`
	Heartbeat    HeartbeatConfig    `koanf:"heartbeat"`
}

// HeartbeatConfig is an external dead-man's switch: while deckard is healthy
// the scheduler requests URL every Interval. An empty URL disables it. The
// URL usually embeds a token, so it is treated as a secret: logs and errors
// show only its scheme and host.
type HeartbeatConfig struct {
	URL      string        `koanf:"url"`
	Interval time.Duration `koanf:"interval"`
	Method   string        `koanf:"method"` // GET or POST
	Timeout  time.Duration `koanf:"timeout"`
}

// Enabled reports whether a heartbeat URL is configured.
func (h HeartbeatConfig) Enabled() bool { return strings.TrimSpace(h.URL) != "" }

type AlertmanagerConfig struct {
	URLs    []string      `koanf:"urls"`
	Resend  time.Duration `koanf:"resend"`
	Timeout time.Duration `koanf:"timeout"`
	// MinSeverity is the lowest finding severity sent to Alertmanager
	// (info|low|medium|high|critical). Findings below it are still stored and
	// shown; they are only not notified.
	MinSeverity string `koanf:"min_severity"`
	// BasicAuth credentials, optional.
	Username    string `koanf:"username"`
	PasswordEnv string `koanf:"password_env"`
}

// AssetGroup overrides profiles for assets matching Match.
type AssetGroup struct {
	Name     string                     `koanf:"name"`
	Match    GroupMatch                 `koanf:"match"`
	Profiles map[string]ProfileOverride `koanf:"profiles"`
}

type GroupMatch struct {
	Zones     []string `koanf:"zones"`
	Sources   []string `koanf:"sources"`
	Hostnames []string `koanf:"hostnames"`
	CIDRs     []string `koanf:"cidrs"`
}

// ProfileOverride uses pointers so "unset" is distinguishable from zero.
type ProfileOverride struct {
	Enabled            *bool          `koanf:"enabled"`
	Interval           *time.Duration `koanf:"interval"`
	RateLimit          *string        `koanf:"rate_limit"`
	PerHostConcurrency *int           `koanf:"per_host_concurrency"`
}

type Suppression struct {
	Match  string     `koanf:"match"`
	Reason string     `koanf:"reason"`
	Until  *time.Time `koanf:"until"`
}

type AuthConfig struct {
	Mode     string     `koanf:"mode"` // none|token|oidc
	TokenEnv string     `koanf:"token_env"`
	OIDC     OIDCConfig `koanf:"oidc"`
}

type OIDCConfig struct {
	Issuer          string   `koanf:"issuer"`
	ClientID        string   `koanf:"client_id"`
	ClientSecretEnv string   `koanf:"client_secret_env"`
	RedirectURL     string   `koanf:"redirect_url"`
	AllowedGroups   []string `koanf:"allowed_groups"`
	GroupsClaim     string   `koanf:"groups_claim"`
	// AllowInsecureBaseURL permits a non-https redirect/base URL (local dev
	// only): cookies are then not Secure and HSTS is off.
	AllowInsecureBaseURL bool `koanf:"allow_insecure_base_url"`
}

// Defaults returns the baseline configuration.
func Defaults() map[string]any {
	return map[string]any{
		"server.http_addr":                        ":8080",
		"server.metrics_addr":                     ":9090",
		"server.roles":                            []string{"api", "scheduler", "worker"},
		"log.level":                               "info",
		"log.format":                              "json",
		"database.max_conns":                      10,
		"sync.interval":                           "10m",
		"scheduling.error_retry":                  "10m",
		"scheduling.queue_workers.sync":           2,
		"scheduling.queue_workers.passive":        10,
		"scheduling.queue_workers.active":         4,
		"scheduling.queue_workers.intrusive":      1,
		"scheduling.queue_workers.default":        2,
		"scheduling.queue_workers.expand":         1,
		"scheduling.queue_workers.maintenance":    1,
		"retention.scans":                         "168h",
		"retention.relations":                     "720h",
		"scope.max_cidr_hosts":                    1024,
		"profiles.passive.enabled":                true,
		"profiles.passive.interval":               "5m",
		"profiles.passive.on_inventory_change":    true,
		"profiles.passive.rate_limit":             "100/s",
		"profiles.passive.per_host_concurrency":   4,
		"profiles.active.enabled":                 true,
		"profiles.active.interval":                "6h",
		"profiles.active.on_inventory_change":     true,
		"profiles.active.rate_limit":              "50/s",
		"profiles.active.per_host_concurrency":    2,
		"profiles.intrusive.enabled":              false,
		"profiles.intrusive.interval":             "24h",
		"profiles.intrusive.rate_limit":           "10/s",
		"profiles.intrusive.per_host_concurrency": 1,
		"expansion.ct_logs":                       true,
		"expansion.interval":                      "6h",
		"refdata.enabled":                         true,
		"refdata.interval":                        "24h",
		"refdata.dir":                             "/var/lib/deckard/refdata",
		"refdata.timeout":                         "30s",
		"refdata.datasets.takeover_fingerprints":  true,
		"refdata.datasets.shared_ranges":          true,
		"learning.stable_after":                   3,
		"nuclei.enabled":                          true,
		"nuclei.binary":                           "nuclei",
		"nuclei.severity_min":                     "low",
		"nuclei.tags_exclude":                     []string{"dos", "fuzz"},
		"nuclei.scan_mode":                        "tech",
		"nuclei.update.enabled":                   true,
		"nuclei.update.interval":                  "6h",
		"nuclei.update.dir":                       "/var/lib/deckard/nuclei-templates",
		"nuclei.update.timeout":                   "10m",
		"nuclei.update.run_new_templates":         true,
		"nuclei.update.max_age_warn":              "72h",
		"findings.resolve_after":                  2,
		"notify.alertmanager.resend":              "4m",
		"notify.alertmanager.timeout":             "10s",
		"notify.alertmanager.min_severity":        "info",
		"notify.heartbeat.interval":               "5m",
		"notify.heartbeat.method":                 "GET",
		"notify.heartbeat.timeout":                "10s",
		"vulnintel.enabled":                       true,
		"vulnintel.interval":                      "6h",
		"vulnintel.dir":                           "/var/lib/deckard/vulnintel",
		"vulnintel.timeout":                       "30s",
		"vulnintel.kev_floor":                     "critical",
		"vulnintel.epss_high":                     0.7,
		"vulnintel.epss_medium":                   0.3,
		"intel.enabled":                           true,
		"auth.mode":                               "token",
		"auth.oidc.groups_claim":                  "groups",
	}
}

// Load reads path (may be empty), overlays env (a list of KEY=VALUE pairs,
// typically os.Environ()), applies defaults and validates.
func Load(path string, env []string) (*Config, error) {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(Defaults(), "."), nil); err != nil {
		return nil, fmt.Errorf("config: defaults: %w", err)
	}
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
	}
	envMap := envOverrides(env)
	if len(envMap) > 0 {
		if err := k.Load(confmap.Provider(envMap, "."), nil); err != nil {
			return nil, fmt.Errorf("config: env: %w", err)
		}
	}

	var cfg Config
	err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			Result:           &cfg,
			TagName:          "koanf",
			WeaklyTypedInput: true,
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
				stringToTimeHook,
			),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}
	cfg.intelKeyErrs = unknownIntelKeys(k.Keys())
	cfg.applyDerived()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyDerived fills values that depend on other settings. With the template
// updater on and no explicit nuclei.templates_dir, nuclei reads the updater's
// current release.
func (c *Config) applyDerived() {
	if c.Nuclei.Update.Enabled && strings.TrimSpace(c.Nuclei.TemplatesDir) == "" {
		c.Nuclei.TemplatesDir = c.Nuclei.UpdateCurrentDir()
	}
}

func envOverrides(env []string) map[string]any {
	out := map[string]any{}
	for _, kv := range env {
		key, val, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(key, EnvPrefix) {
			continue
		}
		path := strings.ToLower(strings.TrimPrefix(key, EnvPrefix))
		path = strings.ReplaceAll(path, "__", ".")
		if path == "" {
			continue
		}
		out[path] = val
	}
	return out
}

var timeType = reflect.TypeOf(time.Time{})

func stringToTimeHook(from reflect.Type, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.String || to != timeType {
		return data, nil
	}
	s := data.(string)
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return nil, fmt.Errorf("invalid time %q (want RFC3339 or YYYY-MM-DD)", s)
}

// ParseRate parses "N/s", "N/m" or "N/h" into events per second. The empty
// string means unlimited and returns 0.
func ParseRate(s string) (float64, error) {
	if s == "" {
		return 0, nil
	}
	num, unit, ok := strings.Cut(s, "/")
	if !ok {
		return 0, fmt.Errorf("rate %q: want N/s, N/m or N/h", s)
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("rate %q: count must be a positive number", s)
	}
	switch strings.TrimSpace(unit) {
	case "s":
		return n, nil
	case "m":
		return n / 60, nil
	case "h":
		return n / 3600, nil
	}
	return 0, fmt.Errorf("rate %q: unit must be s, m or h", s)
}

var (
	validSourceTypes = map[string]bool{"cloudflare": true, "route53": true, "aws": true, "gcpdns": true, "kubernetes": true, "static": true}
	validLevels      = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	validTiers       = map[string]bool{"passive": true, "active": true, "intrusive": true}
	validAuthModes   = map[string]bool{"none": true, "token": true, "oidc": true}
	validSeverities  = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
)

// Validate checks the configuration and returns all problems joined.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if !validLevels[c.Log.Level] {
		add("log.level %q: must be debug|info|warn|error", c.Log.Level)
	}
	if c.Log.Format != "json" && c.Log.Format != "text" {
		add("log.format %q: must be json|text", c.Log.Format)
	}
	if c.Sync.Interval <= 0 {
		add("sync.interval must be > 0")
	}
	if c.Expansion.Interval <= 0 {
		add("expansion.interval must be > 0")
	}
	if c.Refdata.Enabled {
		if c.Refdata.Interval < MinRefdataInterval {
			add("refdata.interval must be >= %s", MinRefdataInterval)
		}
		if c.Refdata.Timeout <= 0 {
			add("refdata.timeout must be > 0")
		}
		if !c.Refdata.Datasets.TakeoverFingerprints && !c.Refdata.Datasets.SharedRanges {
			add("refdata.enabled with no dataset selected (refdata.datasets.*); set refdata.enabled=false instead")
		}
	}
	c.validateVulnintel(add)
	c.validateIntel(add)
	if c.Scheduling.ErrorRetry <= 0 {
		add("scheduling.error_retry must be > 0")
	}
	if c.Retention.Scans <= 0 {
		add("retention.scans must be > 0")
	}
	if c.Retention.Relations <= 0 {
		add("retention.relations must be > 0")
	}
	for q, n := range c.Scheduling.QueueWorkers {
		if !slices.Contains(QueueNames, q) {
			add("scheduling.queue_workers: unknown queue %q (valid: %s)", q, strings.Join(QueueNames, ", "))
		} else if n < 1 {
			add("scheduling.queue_workers.%s must be >= 1", q)
		}
	}
	if c.Scope.MaxCIDRHosts <= 0 {
		add("scope.max_cidr_hosts must be > 0")
	}
	if c.Learning.StableAfter < 1 {
		add("learning.stable_after must be >= 1")
	}
	for chk, keys := range c.Learning.IgnoreKeys {
		if strings.TrimSpace(chk) == "" {
			add("learning.ignore_keys: empty check name")
		}
		for _, k := range keys {
			if strings.TrimSpace(k) == "" {
				add("learning.ignore_keys.%s: empty key", chk)
			}
		}
	}
	if c.Findings.ResolveAfter < 1 {
		add("findings.resolve_after must be >= 1")
	}
	for name, p := range map[string]Profile{"passive": c.Profiles.Passive, "active": c.Profiles.Active, "intrusive": c.Profiles.Intrusive} {
		if p.Interval <= 0 {
			add("profiles.%s.interval must be > 0", name)
		}
		if _, err := ParseRate(p.RateLimit); err != nil {
			add("profiles.%s.rate_limit: %v", name, err)
		}
	}
	for name, opts := range c.Checks {
		if _, _, err := CheckInterval(opts); err != nil {
			add("checks.%s.interval: %v", name, err)
		}
		if _, _, err := CheckOnNewAsset(opts); err != nil {
			add("checks.%s.on_new_asset: %v", name, err)
		}
	}
	if !validSeverities[c.Notify.Alertmanager.MinSeverity] {
		add("notify.alertmanager.min_severity %q: must be info|low|medium|high|critical", c.Notify.Alertmanager.MinSeverity)
	}
	c.validateHeartbeat(add)
	c.validateNuclei(add)
	c.validateSources(add)
	c.validatePlugins(add)
	for _, g := range c.AssetGroups {
		for tier, o := range g.Profiles {
			if !validTiers[tier] {
				add("asset_groups[%s].profiles: unknown tier %q", g.Name, tier)
			}
			if o.RateLimit != nil {
				if _, err := ParseRate(*o.RateLimit); err != nil {
					add("asset_groups[%s].profiles.%s.rate_limit: %v", g.Name, tier, err)
				}
			}
			if o.Interval != nil && *o.Interval <= 0 {
				add("asset_groups[%s].profiles.%s.interval must be > 0", g.Name, tier)
			}
		}
	}
	if !validAuthModes[c.Auth.Mode] {
		add("auth.mode %q: must be none|token|oidc", c.Auth.Mode)
	}
	if c.Auth.Mode == "oidc" {
		if c.Auth.OIDC.Issuer == "" {
			add("auth.oidc.issuer is required when auth.mode=oidc")
		}
		if c.Auth.OIDC.ClientID == "" {
			add("auth.oidc.client_id is required when auth.mode=oidc")
		}
		// Secure cookies and HSTS key off the URL scheme; never let them
		// silently turn off.
		if !c.Auth.OIDC.AllowInsecureBaseURL {
			switch {
			case c.Auth.OIDC.RedirectURL != "":
				if !strings.HasPrefix(c.Auth.OIDC.RedirectURL, "https://") {
					add("auth.oidc.redirect_url %q must be https (or set auth.oidc.allow_insecure_base_url: true for local dev)", c.Auth.OIDC.RedirectURL)
				}
			case !strings.HasPrefix(c.Server.BaseURL, "https://"):
				add("server.base_url %q must be https when auth.mode=oidc (or set auth.oidc.allow_insecure_base_url: true for local dev)", c.Server.BaseURL)
			}
		}
	}
	for _, role := range c.Server.Roles {
		if role != "api" && role != "scheduler" && role != "worker" {
			add("server.roles: unknown role %q", role)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// validateHeartbeat never echoes the URL: it usually carries a token.
func (c *Config) validateHeartbeat(add func(string, ...any)) {
	h := c.Notify.Heartbeat
	if !h.Enabled() {
		return
	}
	u, err := url.Parse(strings.TrimSpace(h.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		add("notify.heartbeat.url must be an absolute http(s) URL (value not shown: it is treated as a secret)")
	}
	switch strings.ToUpper(strings.TrimSpace(h.Method)) {
	case "GET", "POST":
	default:
		add("notify.heartbeat.method %q: must be GET or POST", h.Method)
	}
	if h.Interval <= 0 {
		add("notify.heartbeat.interval must be > 0")
	}
	if h.Timeout <= 0 {
		add("notify.heartbeat.timeout must be > 0")
	}
}

func (c *Config) validateNuclei(add func(string, ...any)) {
	n := c.Nuclei
	if n.ScanMode != "tech" && n.ScanMode != "all" {
		add("nuclei.scan_mode %q: must be tech|all", n.ScanMode)
	}
	u := n.Update
	if !u.Enabled {
		return
	}
	if u.Interval <= 0 {
		add("nuclei.update.interval must be > 0")
	}
	if u.Timeout <= 0 {
		add("nuclei.update.timeout must be > 0")
	}
	if u.MaxAgeWarn <= 0 {
		add("nuclei.update.max_age_warn must be > 0")
	}
	switch {
	case strings.TrimSpace(u.Dir) == "":
		add("nuclei.update.dir must not be empty (set nuclei.update.enabled: false to opt out)")
	case !filepath.IsAbs(u.Dir):
		add("nuclei.update.dir %q must be an absolute path", u.Dir)
	}
}

func (c *Config) validateSources(add func(string, ...any)) {
	seen := map[string]bool{}
	for i, s := range c.Sources {
		if s.Name == "" {
			add("sources[%d]: name is required", i)
			continue
		}
		if seen[s.Name] {
			add("sources[%d]: duplicate source name %q", i, s.Name)
		}
		seen[s.Name] = true
		if !validSourceTypes[s.Type] {
			add("sources[%s]: unknown type %q", s.Name, s.Type)
			continue
		}
		if s.Type == "aws" {
			dup := map[string]bool{}
			for _, r := range s.Regions {
				if strings.TrimSpace(r) == "" {
					add("sources[%s]: regions must not contain empty entries", s.Name)
				} else if dup[r] {
					add("sources[%s]: duplicate region %q", s.Name, r)
				}
				dup[r] = true
			}
		}
		if s.Type == "gcpdns" {
			validateGCPDNS(s, add)
		}
		if s.Type != "static" {
			continue
		}
		for _, cidr := range s.CIDRs {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				add("sources[%s]: invalid cidr %q", s.Name, cidr)
				continue
			}
			// #nosec G115 -- scope.max_cidr_hosts is validated > 0
			if n := prefixHosts(p); n > uint64(c.Scope.MaxCIDRHosts) {
				add("sources[%s]: cidr %s has %d hosts, exceeds scope.max_cidr_hosts=%d", s.Name, cidr, n, c.Scope.MaxCIDRHosts)
			}
		}
		for _, ip := range s.IPs {
			if _, err := netip.ParseAddr(ip); err != nil {
				add("sources[%s]: invalid ip %q", s.Name, ip)
			}
		}
	}
}

// gcpProjectID matches a Google Cloud project id (6-30 characters, lowercase
// letters, digits and hyphens, starting with a letter, not ending in a hyphen),
// optionally domain-scoped ("example.com:my-project").
var gcpProjectID = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

func validateGCPDNS(s SourceConfig, add func(string, ...any)) {
	if len(s.Projects) == 0 {
		add("sources[%s]: gcpdns needs projects (a list of Google Cloud project ids)", s.Name)
	}
	dup := map[string]bool{}
	for _, p := range s.Projects {
		switch {
		case !gcpProjectID.MatchString(p):
			add("sources[%s]: invalid gcp project id %q (6-30 lowercase letters, digits or hyphens, starting with a letter)", s.Name, p)
		case dup[p]:
			add("sources[%s]: duplicate project %q", s.Name, p)
		}
		dup[p] = true
	}
	for _, z := range s.Zones {
		if strings.TrimSpace(z) == "" {
			add("sources[%s]: zones must not contain empty entries", s.Name)
		}
	}
}

func (c *Config) validatePlugins(add func(string, ...any)) {
	for _, p := range c.Plugins {
		if p.Name == "" {
			add("plugins: name is required")
		}
		if len(p.Exec) == 0 {
			add("plugins[%s]: exec is required", p.Name)
		}
		if !validTiers[p.Tier] {
			add("plugins[%s]: invalid tier %q", p.Name, p.Tier)
		}
	}
}

// prefixHosts returns the number of addresses in p, saturating at MaxUint64.
func prefixHosts(p netip.Prefix) uint64 {
	bits := p.Addr().BitLen() - p.Bits()
	if bits >= 64 {
		return ^uint64(0)
	}
	return uint64(1) << bits
}

// PrefixHosts is exported for the scope and static-source packages.
func PrefixHosts(p netip.Prefix) uint64 { return prefixHosts(p) }

func (c *Config) validateVulnintel(add func(string, ...any)) {
	v := c.Vulnintel
	if !v.Enabled {
		return
	}
	if v.Interval <= 0 {
		add("vulnintel.interval must be > 0")
	}
	if v.Timeout <= 0 {
		add("vulnintel.timeout must be > 0")
	}
	if strings.TrimSpace(v.Dir) == "" {
		add("vulnintel.dir must not be empty")
	}
	switch v.KEVFloor {
	case "low", "medium", "high", "critical":
	default:
		add("vulnintel.kev_floor %q: must be low|medium|high|critical", v.KEVFloor)
	}
	if v.EPSSHigh <= 0 || v.EPSSHigh > 1 {
		add("vulnintel.epss_high %v: must be in (0,1]", v.EPSSHigh)
	}
	if v.EPSSMedium <= 0 || v.EPSSMedium > 1 {
		add("vulnintel.epss_medium %v: must be in (0,1]", v.EPSSMedium)
	}
	if v.EPSSMedium > v.EPSSHigh {
		add("vulnintel.epss_medium must be <= vulnintel.epss_high")
	}
}
