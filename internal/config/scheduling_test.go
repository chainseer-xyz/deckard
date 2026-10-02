package config

import (
	"testing"
	"time"
)

func TestSchedulingAndRetentionDefaultsAndValidation(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scheduling.ErrorRetry != 10*time.Minute {
		t.Errorf("error_retry = %v", cfg.Scheduling.ErrorRetry)
	}
	if cfg.Retention.Scans != 168*time.Hour || cfg.Retention.Relations != 720*time.Hour {
		t.Errorf("retention = %+v", cfg.Retention)
	}
	want := map[string]int{"sync": 2, "passive": 10, "active": 4, "intrusive": 1, "default": 2, "expand": 1}
	for q, n := range want {
		if cfg.Scheduling.QueueWorkers[q] != n {
			t.Errorf("queue_workers[%s] = %d want %d", q, cfg.Scheduling.QueueWorkers[q], n)
		}
	}
	for name, body := range map[string]string{
		"error_retry":  "scheduling: {error_retry: 0s}",
		"scans":        "retention: {scans: 0s}",
		"relations":    "retention: {relations: -1h}",
		"zero workers": "scheduling: {queue_workers: {active: 0}}",
		"unknown":      "scheduling: {queue_workers: {bogus: 2}}",
	} {
		if _, err := Load(writeCfg(t, body), nil); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	c, err := Load(writeCfg(t, "scheduling: {queue_workers: {active: 7}}"), nil)
	if err != nil || c.Scheduling.QueueWorkers["active"] != 7 || c.Scheduling.QueueWorkers["passive"] != 10 {
		t.Fatalf("override: %v %+v", err, c.Scheduling)
	}
}
