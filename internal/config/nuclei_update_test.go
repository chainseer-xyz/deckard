package config

import (
	"strings"
	"testing"
	"time"
)

func TestNucleiUpdateDefaults(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.Nuclei.Update
	if !u.Enabled || u.Interval != 6*time.Hour || u.Dir != "/var/lib/deckard/nuclei-templates" ||
		u.Timeout != 10*time.Minute || !u.RunNewTemplates || u.MaxAgeWarn != 72*time.Hour {
		t.Fatalf("update defaults = %+v", u)
	}
	if cfg.Nuclei.TemplatesDir != "/var/lib/deckard/nuclei-templates/current" {
		t.Errorf("templates_dir default = %q, want the updater's current path", cfg.Nuclei.TemplatesDir)
	}
	if cfg.Nuclei.ScanMode != "tech" {
		t.Errorf("scan_mode default = %q, want tech", cfg.Nuclei.ScanMode)
	}
	if cfg.Nuclei.ProcessConcurrency != 1 || cfg.Nuclei.ProcessMemoryLimit != "768MiB" {
		t.Errorf("process defaults = %d/%q", cfg.Nuclei.ProcessConcurrency, cfg.Nuclei.ProcessMemoryLimit)
	}
	if cfg.Nuclei.UpdateCurrentDir() != cfg.Nuclei.TemplatesDir {
		t.Errorf("UpdateCurrentDir = %q", cfg.Nuclei.UpdateCurrentDir())
	}
}

func TestNucleiUpdateOptOutAndOverrides(t *testing.T) {
	// Air-gapped: updater off, operator-mounted templates.
	cfg, err := Load(writeCfg(t, "nuclei: {update: {enabled: false}, templates_dir: /mnt/templates}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Nuclei.Update.Enabled || cfg.Nuclei.TemplatesDir != "/mnt/templates" {
		t.Fatalf("opt-out = %+v", cfg.Nuclei)
	}
	// Disabled updater with no templates_dir leaves it empty (nuclei defaults).
	cfg, err = Load(writeCfg(t, "nuclei: {update: {enabled: false}}"), nil)
	if err != nil || cfg.Nuclei.TemplatesDir != "" {
		t.Fatalf("disabled: %v templates_dir=%q", err, cfg.Nuclei.TemplatesDir)
	}
	// An explicit templates_dir always wins over the updater default.
	cfg, err = Load(writeCfg(t, "nuclei: {templates_dir: /mnt/t}"), nil)
	if err != nil || cfg.Nuclei.TemplatesDir != "/mnt/t" {
		t.Fatalf("explicit: %v %q", err, cfg.Nuclei.TemplatesDir)
	}
	// Custom dir moves the current path.
	cfg, err = Load(writeCfg(t, "nuclei: {update: {dir: /data/nt, interval: 1h}}"), nil)
	if err != nil || cfg.Nuclei.TemplatesDir != "/data/nt/current" || cfg.Nuclei.Update.Interval != time.Hour {
		t.Fatalf("custom dir: %v %q", err, cfg.Nuclei.TemplatesDir)
	}
}

func TestNucleiUpdateValidation(t *testing.T) {
	for name, body := range map[string]string{
		"interval":            "nuclei: {update: {interval: 0s}}",
		"neg interval":        "nuclei: {update: {interval: -1h}}",
		"timeout":             "nuclei: {update: {timeout: 0s}}",
		"max_age_warn":        "nuclei: {update: {max_age_warn: 0s}}",
		"empty dir":           "nuclei: {update: {dir: ''}}",
		"relative dir":        "nuclei: {update: {dir: relative/dir}}",
		"scan_mode":           "nuclei: {scan_mode: everything}",
		"leading dash":        "nuclei: {update: {dir: -x}}",
		"process concurrency": "nuclei: {process_concurrency: 0}",
		"process memory":      "nuclei: {process_memory_limit: 12MB}",
		"relative custom":     "nuclei: {extra_templates_dirs: [templates/custom]}",
		"empty custom":        "nuclei: {extra_templates_dirs: ['']}",
		"dash custom":         "nuclei: {extra_templates_dirs: [/tmp/-templates]}",
	} {
		_, err := Load(writeCfg(t, body), nil)
		if err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	// Disabled updater does not validate its (unused) tunables.
	if _, err := Load(writeCfg(t, "nuclei: {update: {enabled: false, interval: 0s}}"), nil); err != nil {
		t.Errorf("disabled updater should not validate interval: %v", err)
	}
	if _, err := Load(writeCfg(t, "nuclei: {scan_mode: all}"), nil); err != nil {
		t.Errorf("scan_mode all: %v", err)
	}
	_, err := Load(writeCfg(t, "nuclei: {update: {interval: 0s}}"), nil)
	if err == nil || !strings.Contains(err.Error(), "nuclei.update.interval") {
		t.Errorf("error should name the key: %v", err)
	}
}

func TestMaintenanceQueueWorkers(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scheduling.QueueWorkers["maintenance"] != 1 {
		t.Errorf("maintenance workers = %d, want 1", cfg.Scheduling.QueueWorkers["maintenance"])
	}
}
