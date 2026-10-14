package config

import (
	"regexp"
	"strings"
	"time"
	"unicode"
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (s SourceConfig) ExpectedInterval(syncInterval time.Duration) time.Duration {
	if s.RemoteOnly {
		if s.ReportInterval > 0 {
			return s.ReportInterval
		}
		return 6 * time.Hour
	}
	return syncInterval
}

func (c *Config) validateCollectorCredentials(add func(string, ...any)) {
	if len(c.Ingest.Credentials) > 64 {
		add("ingest.credentials: at most 64 credentials are allowed")
	}
	remote := map[string]bool{}
	for _, src := range c.Sources {
		if src.Type == "bbot" && src.RemoteOnly {
			remote[src.Name] = true
		}
	}
	for name, cred := range c.Ingest.Credentials {
		bad := func() {
			add("ingest.credentials.%s: require a distinct token_env and bounded exact tool/scope or remote discovery grants", name)
		}
		if !validIngestTool(name) || !envName.MatchString(cred.TokenEnv) || cred.TokenEnv == c.Auth.TokenEnv || len(cred.Tools) > 64 || len(cred.Scopes) > 64 || len(cred.DiscoverySources) > 64 {
			bad()
			continue
		}
		if (len(cred.Tools) == 0) != (len(cred.Scopes) == 0) || len(cred.Tools)+len(cred.DiscoverySources) == 0 {
			bad()
		}
		for _, tool := range cred.Tools {
			if !validIngestTool(tool) {
				bad()
			}
		}
		for _, value := range cred.Scopes {
			if len(value) == 0 || len(value) > 200 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "*?") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
				bad()
			}
		}
		for _, source := range cred.DiscoverySources {
			if !remote[source] {
				bad()
			}
		}
	}
}
