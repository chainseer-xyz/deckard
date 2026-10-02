package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "deckard ") {
		t.Errorf("out = %q", out.String())
	}
}

func TestScanAcceptsNoUpdateFlag(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(bad, []byte("log: {level: loud}\n"), 0o600)
	var out, errb bytes.Buffer
	// A recognised flag reaches config loading (exit 1); an unknown one stops at
	// flag parsing (exit 2).
	if code := run([]string{"scan", "--no-update", "--config", bad}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "log.level") {
		t.Fatalf("--no-update: exit %d: %s", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"scan", "--bogus"}, &out, &errb); code != 2 {
		t.Fatalf("--bogus: exit %d", code)
	}
	if !strings.Contains(usage, "--no-update") {
		t.Error("usage must mention --no-update")
	}
}

func TestNoArgsAndUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if run(nil, &out, &errb) != 2 {
		t.Error("no args should exit 2")
	}
	errb.Reset()
	if run([]string{"bogus"}, &out, &errb) != 2 || !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("unknown command: %q", errb.String())
	}
}

func TestConfigValidate(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(good, []byte("log: {level: debug}\n"), 0o600)
	_ = os.WriteFile(bad, []byte("log: {level: loud}\n"), 0o600)

	var out, errb bytes.Buffer
	if code := run([]string{"config", "validate", "--config", good}, &out, &errb); code != 0 {
		t.Fatalf("good config exit %d: %s", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"config", "validate", "--config", bad}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "log.level") {
		t.Fatalf("bad config exit %d: %s", code, errb.String())
	}
}
