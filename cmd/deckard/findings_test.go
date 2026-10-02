package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// seedFindings writes findings through the store the way a scan would.
func seedFindings(t *testing.T) (cfgPath string) {
	t.Helper()
	url := pgtest.NewURL(t)
	ctx := context.Background()
	s, err := postgres.New(ctx, url, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	if _, err := s.ApplySnapshot(ctx, "lab", []store.AssetUpsert{
		{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "a.example.com", Source: "lab"}, Scope: model.ScopeOwned},
		{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "b.example.com", Source: "lab"}, Scope: model.ScopeOwned},
	}, nil, now); err != nil {
		t.Fatal(err)
	}
	rec := func(host, check, key string, sev model.Severity, title string, at time.Time) {
		a, err := s.GetAssetByKey(ctx, model.KindHostname, host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReconcileFindings(ctx, store.ReconcileInput{AssetID: a.ID, Check: check, ResolveAfter: 1, Now: at,
			Findings: []model.FindingInput{{Check: check, Key: key, Severity: sev, Title: title}}}); err != nil {
			t.Fatal(err)
		}
	}
	rec("a.example.com", "tls.cert", "k1", model.SeverityLow, "low old", now.Add(-48*time.Hour))
	rec("a.example.com", "dns.takeover", "k2", model.SeverityCritical, "critical new", now.Add(-time.Hour))
	rec("b.example.com", "http.headers", "k3", model.SeverityCritical, "critical older", now.Add(-24*time.Hour))
	rec("b.example.com", "dns.hygiene", "k4", model.SeverityMedium, "medium resolved", now.Add(-72*time.Hour))
	// Resolve k4 by a clean run.
	b, _ := s.GetAssetByKey(ctx, model.KindHostname, "b.example.com")
	if _, err := s.ReconcileFindings(ctx, store.ReconcileInput{AssetID: b.ID, Check: "dns.hygiene", ResolveAfter: 1, Now: now}); err != nil {
		t.Fatal(err)
	}

	cfgPath = filepath.Join(t.TempDir(), "deckard.yaml")
	if err := os.WriteFile(cfgPath, []byte("database:\n  url: \""+url+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestFindingsTableSortedBySeverityThenAge(t *testing.T) {
	cfg := seedFindings(t)
	var out, errb bytes.Buffer
	if code := run([]string{"findings", "--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 { // header + 3 open findings (resolved one hidden by default)
		t.Fatalf("lines:\n%s", out.String())
	}
	for i, want := range []string{"SEVERITY", "critical older", "critical new", "low old"} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d = %q, want it to contain %q", i, lines[i], want)
		}
	}
	for _, col := range []string{"CHECK", "ASSET", "TITLE", "FIRST_SEEN"} {
		if !strings.Contains(lines[0], col) {
			t.Errorf("header missing %s: %q", col, lines[0])
		}
	}
}

func TestFindingsFilters(t *testing.T) {
	cfg := seedFindings(t)
	var out, errb bytes.Buffer
	if code := run([]string{"findings", "--config", cfg, "--min-severity", "high", "--format", "json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if len(got) != 2 || got[0]["severity"] != "critical" {
		t.Errorf("min-severity=high: %v", got)
	}

	out.Reset()
	if code := run([]string{"findings", "--config", cfg, "--status", "resolved", "--format", "json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got = nil
	_ = json.Unmarshal(out.Bytes(), &got)
	if len(got) != 1 || got[0]["title"] != "medium resolved" {
		t.Errorf("status=resolved: %v", got)
	}
}

func TestFindingsBadFlags(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{
		{"findings", "--min-severity", "bogus"},
		{"findings", "--format", "xml"},
		{"findings", "--status", "nope"},
	} {
		errb.Reset()
		if code := run(args, &out, &errb); code != 2 || errb.Len() == 0 {
			t.Errorf("%v: exit %d stderr %q", args, code, errb.String())
		}
	}
}
