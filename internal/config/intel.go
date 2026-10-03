package config

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/intel"
)

// IntelConfig configures the restricted client checks use to ask third-party
// metadata services (RDAP registries, Shodan InternetDB, the Wayback Machine)
// about the operator's own domains and IPs. The hosts it may reach are fixed
// in code (internal/intel); there is deliberately no setting that adds one.
type IntelConfig struct {
	// Enabled false (air-gapped) makes every consumer skip with an
	// observation instead of a finding.
	Enabled bool `koanf:"enabled"`
	// UserAgentContact (an e-mail address or URL) is appended to the
	// User-Agent so service operators can reach you.
	UserAgentContact string                        `koanf:"user_agent_contact"`
	Services         map[string]IntelServiceConfig `koanf:"services"`
}

// IntelServiceConfig tunes one service. Zero values keep the built-in default.
type IntelServiceConfig struct {
	Enabled          *bool         `koanf:"enabled"`
	RatePerSecond    float64       `koanf:"rate_per_second"`
	Timeout          time.Duration `koanf:"timeout"`
	CacheTTL         time.Duration `koanf:"cache_ttl"`
	NegativeCacheTTL time.Duration `koanf:"negative_cache_ttl"`
	MaxBytes         int64         `koanf:"max_bytes"`
}

// ServiceOptions converts the configuration into the client's per-service
// overrides.
func (c IntelConfig) ServiceOptions() map[string]intel.ServiceConfig {
	out := make(map[string]intel.ServiceConfig, len(c.Services))
	for name, s := range c.Services {
		out[name] = intel.ServiceConfig{
			Disabled:         s.Enabled != nil && !*s.Enabled,
			RatePerSecond:    s.RatePerSecond,
			Timeout:          s.Timeout,
			CacheTTL:         s.CacheTTL,
			NegativeCacheTTL: s.NegativeCacheTTL,
			MaxBytes:         s.MaxBytes,
		}
	}
	return out
}

var intelServiceKeys = []string{"enabled", "rate_per_second", "timeout", "cache_ttl", "negative_cache_ttl", "max_bytes"}

// unknownIntelKeys reports keys under intel.* that deckard does not read. The
// block is closed (unlike checks.*): a typo or an attempt to widen the client's
// reach must fail loudly rather than be ignored.
func unknownIntelKeys(keys []string) []string {
	var out []string
	for _, k := range keys {
		rest, ok := strings.CutPrefix(k, "intel.")
		if !ok {
			continue
		}
		switch {
		case rest == "enabled", rest == "user_agent_contact", rest == "services":
			continue
		case rest == "extra_allowed_hosts" || strings.HasPrefix(rest, "extra_allowed_hosts."):
			out = append(out, "intel.extra_allowed_hosts is not supported: the metadata hosts are fixed in code (see docs/operations.md, Network egress)")
			continue
		}
		svc, field, _ := strings.Cut(strings.TrimPrefix(rest, "services."), ".")
		if !strings.HasPrefix(rest, "services.") {
			out = append(out, fmt.Sprintf("%s: unknown key", k))
			continue
		}
		if !slices.Contains(intel.ServiceNames(), svc) {
			out = append(out, fmt.Sprintf("intel.services.%s: unknown service (known: %s)", svc, strings.Join(intel.ServiceNames(), ", ")))
			continue
		}
		if field != "" && !slices.Contains(intelServiceKeys, field) {
			out = append(out, fmt.Sprintf("%s: unknown key (known: %s)", k, strings.Join(intelServiceKeys, ", ")))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (c *Config) validateIntel(add func(string, ...any)) {
	for _, e := range c.intelKeyErrs {
		add("%s", e)
	}
	ic := c.Intel
	if n := len(ic.UserAgentContact); n > 128 {
		add("intel.user_agent_contact is %d characters (max 128)", n)
	}
	for _, r := range ic.UserAgentContact {
		if r < 0x20 || r > 0x7e || strings.ContainsRune("();\\\"", r) {
			add("intel.user_agent_contact must be printable ASCII without ( ) ; \\ or quotes (an e-mail address or URL)")
			break
		}
	}
	for name, s := range ic.Services {
		if !slices.Contains(intel.ServiceNames(), name) {
			add("intel.services.%s: unknown service (known: %s)", name, strings.Join(intel.ServiceNames(), ", "))
			continue
		}
		p := "intel.services." + name
		if s.RatePerSecond < 0 || s.RatePerSecond > 50 {
			add("%s.rate_per_second %v: must be in (0, 50] (0 or unset = default %v)", p, s.RatePerSecond, intel.DefaultRate(name))
		}
		checkRange(add, p+".timeout", s.Timeout, time.Second, 2*time.Minute)
		checkRange(add, p+".cache_ttl", s.CacheTTL, time.Minute, 7*24*time.Hour)
		checkRange(add, p+".negative_cache_ttl", s.NegativeCacheTTL, time.Minute, 24*time.Hour)
		if s.MaxBytes != 0 && (s.MaxBytes < 4<<10 || s.MaxBytes > 32<<20) {
			add("%s.max_bytes %d: must be between 4096 and 33554432 (0 or unset = default %d)", p, s.MaxBytes, intel.DefaultMaxBytes)
		}
	}
}

// checkRange accepts 0 (use the default) or a value in [lo, hi].
func checkRange(add func(string, ...any), key string, d, lo, hi time.Duration) {
	if d != 0 && (d < lo || d > hi) {
		add("%s %s: must be between %s and %s (0 or unset = default)", key, d, lo, hi)
	}
}
