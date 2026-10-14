package config

import "testing"

func TestRemoteBBOTSource(t *testing.T) {
	if _, err := Load(writeCfg(t, "sources:\n  - {name: external-discovery, type: bbot, remote_only: true}\n"), nil); err != nil {
		t.Fatalf("configured remote producer requires no local file: %v", err)
	}
	for _, source := range []string{
		"{name: bad, type: bbot, remote_only: true, discovery_file: /tmp/report}",
		"{name: bad, type: cloudflare, remote_only: true}",
	} {
		if _, err := Load(writeCfg(t, "sources:\n  - "+source+"\n"), nil); err == nil {
			t.Fatalf("ambiguous remote source accepted: %s", source)
		}
	}
}

func TestCollectorCredentialValidation(t *testing.T) {
	for _, credential := range []string{
		"{token_env: COLLECTOR, tools: [trivy]}",
		"{token_env: COLLECTOR, scopes: ['image:one']}",
		"{token_env: COLLECTOR, tools: [trivy], scopes: ['*']}",
		"{token_env: COLLECTOR, discovery_sources: [cloudflare]}",
		"{token_env: ADMIN, tools: [trivy], scopes: ['image:one']}",
	} {
		yaml := "auth: {mode: token, token_env: ADMIN}\ningest:\n  credentials:\n    collector: " + credential + "\n"
		if _, err := Load(writeCfg(t, yaml), nil); err == nil {
			t.Fatalf("unbounded or authority-impersonating credential accepted: %s", credential)
		}
	}
}

func TestNegativeReportIntervalIsRejected(t *testing.T) {
	if _, err := Load(writeCfg(t, "ingest:\n  tools:\n    tetragon: {expected_report_interval: -1m}\n"), nil); err == nil {
		t.Fatal("negative report interval accepted")
	}
}
