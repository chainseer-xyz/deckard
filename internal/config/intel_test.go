package config

import (
	"strings"
	"testing"
	"time"
)

func TestIntelDefaultsAndOverrides(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Intel.Enabled || len(cfg.Intel.Services) != 0 {
		t.Fatalf("defaults: %+v", cfg.Intel)
	}
	cfg, err = Load(writeCfg(t, `
intel:
  user_agent_contact: security@example.com
  services:
    rdap: {rate_per_second: 0.5, timeout: 10s, cache_ttl: 12h, negative_cache_ttl: 30m, max_bytes: 1048576}
    wayback: {enabled: false}
`), []string{"DECKARD_INTEL__ENABLED=false"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intel.Enabled {
		t.Error("env override ignored")
	}
	opts := cfg.Intel.ServiceOptions()
	r := opts["rdap"]
	if r.RatePerSecond != 0.5 || r.Timeout != 10*time.Second || r.CacheTTL != 12*time.Hour ||
		r.NegativeCacheTTL != 30*time.Minute || r.MaxBytes != 1<<20 || r.Disabled {
		t.Errorf("rdap = %+v", r)
	}
	if !opts["wayback"].Disabled {
		t.Errorf("wayback = %+v", opts["wayback"])
	}
}

func TestIntelValidation(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{"escape hatch", "intel: {extra_allowed_hosts: [evil.example.com]}", "intel.extra_allowed_hosts is not supported"},
		{"unknown top key", "intel: {proxy: http://proxy.example.com}", "intel.proxy: unknown key"},
		{"unknown service", "intel: {services: {pastebin: {rate_per_second: 1}}}", "intel.services.pastebin: unknown service"},
		{"unknown service key", "intel: {services: {rdap: {hosts: [evil.example.com]}}}", "intel.services.rdap.hosts: unknown key"},
		{"negative rate", "intel: {services: {rdap: {rate_per_second: -1}}}", "intel.services.rdap.rate_per_second"},
		{"huge rate", "intel: {services: {internetdb: {rate_per_second: 500}}}", "intel.services.internetdb.rate_per_second"},
		{"short timeout", "intel: {services: {rdap: {timeout: 10ms}}}", "intel.services.rdap.timeout"},
		{"long timeout", "intel: {services: {rdap: {timeout: 1h}}}", "intel.services.rdap.timeout"},
		{"long cache", "intel: {services: {rdap: {cache_ttl: 720h}}}", "intel.services.rdap.cache_ttl"},
		{"short negative cache", "intel: {services: {rdap: {negative_cache_ttl: 1s}}}", "intel.services.rdap.negative_cache_ttl"},
		{"tiny cap", "intel: {services: {rdap: {max_bytes: 10}}}", "intel.services.rdap.max_bytes"},
		{"huge cap", "intel: {services: {rdap: {max_bytes: 1073741824}}}", "intel.services.rdap.max_bytes"},
		{"contact injection", "intel: {user_agent_contact: \"a@example.com)\\r\\nX-Evil: 1\"}", "intel.user_agent_contact"},
		{"contact too long", "intel: {user_agent_contact: " + strings.Repeat("a", 129) + "}", "intel.user_agent_contact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeCfg(t, tc.yaml), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	if _, err := Load("", []string{"DECKARD_INTEL__EXTRA_ALLOWED_HOSTS=evil.example.com"}); err == nil {
		t.Error("escape hatch accepted from the environment")
	}
}
