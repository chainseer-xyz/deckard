package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
)

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	log := New(config.LogConfig{Level: "info", Format: "json"}, &buf)
	log.Info("hello", "asset", "a.example.com", "count", 3)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not JSON: %v: %q", err, buf.String())
	}
	if rec["msg"] != "hello" || rec["level"] != "INFO" || rec["asset"] != "a.example.com" {
		t.Errorf("unexpected record: %v", rec)
	}
	if _, ok := rec["time"]; !ok {
		t.Error("missing time")
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(config.LogConfig{Level: "warn", Format: "json"}, &buf)
	log.Info("quiet")
	log.Warn("loud")
	out := buf.String()
	if strings.Contains(out, "quiet") || !strings.Contains(out, "loud") {
		t.Errorf("level filter wrong: %q", out)
	}
}

func TestRedactsSecretKeys(t *testing.T) {
	var buf bytes.Buffer
	log := New(config.LogConfig{Level: "info", Format: "json"}, &buf)
	log.Info("auth", "token", "s3cr3t", "password", "hunter2", "api_key", "k", "ok", "visible")
	out := buf.String()
	for _, secret := range []string{"s3cr3t", "hunter2"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q leaked: %s", secret, out)
		}
	}
	if !strings.Contains(out, "visible") || !strings.Contains(out, "[REDACTED]") {
		t.Errorf("unexpected: %s", out)
	}
}

func TestTextFormat(t *testing.T) {
	var buf bytes.Buffer
	log := New(config.LogConfig{Level: "info", Format: "text"}, &buf)
	log.Info("x")
	if json.Valid(buf.Bytes()) {
		t.Error("text format should not be JSON")
	}
}
