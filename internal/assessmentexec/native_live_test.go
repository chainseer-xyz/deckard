//go:build live

package assessmentexec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

// This checks the genuine pinned ZAP Automation Framework parser offline. It
// does not claim a scan, sandbox or network-containment proof.
func TestNativeZAPAcceptsGeneratedAutomationPlan(t *testing.T) {
	if os.Getenv("DECKARD_ASSESSMENT_NATIVE") != "1" {
		t.Skip("set DECKARD_ASSESSMENT_NATIVE=1 with pinned local images")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fixture := t.TempDir()
	if err := os.Chmod(fixture, 0755); err != nil {
		t.Fatal(err)
	}
	r := assessmentjob.ExecutionRequest{Targets: []string{"https://app.example.com"}, TimeoutSeconds: 60}
	cfg := zapSettings{proxyURL: "http://10.20.30.40:9092", token: strings.Repeat("p", 43), auth: []zapAuthOrigin{{Origin: "https://app.example.com", Header: "Authorization", Value: "Bearer fixture-only", VerificationPath: "/private", ExpectedStatus: 200}}}
	plan, err := zapPlan(r, "/tmp", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "automation.yaml"), plan, 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "--user", "65532:65532", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--mount", "type=bind,src="+fixture+",dst=/fixture,readonly", "--entrypoint", "/zap/zap.sh", "ghcr.io/zaproxy/zaproxy@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2", "-cmd", "-silent", "-notel", "-autocheck", "/fixture/automation.yaml", "-dir", "/tmp/zap")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official ZAP rejected generated plan: %v\n%s", err, output)
	}
}

// Run the freshly compiled real CLI against the actual isolated Strix image,
// with no model credentials and no network. Imports must succeed far enough to
// emit the adapter's structured failure, not an empty/missing report.
func TestNativeStrixWrapperEmitsModelUnavailableAndFailedDone(t *testing.T) {
	if os.Getenv("DECKARD_ASSESSMENT_NATIVE") != "1" {
		t.Skip("set DECKARD_ASSESSMENT_NATIVE=1 with pinned local images")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fixture := t.TempDir()
	if err := os.Chmod(fixture, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(fixture, "deckard")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/deckard")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native CLI fixture: %v\n%s", err, output)
	}
	r := assessmentjob.ExecutionRequest{SchemaVersion: 1, SessionID: "fixture-1", Tool: assessmentjob.ToolStrix, Targets: []string{"https://app.example.com"}, MaxTurns: 30, TimeoutSeconds: 30, MaxRequests: 50, MaxOutputBytes: 4 << 20}
	path := filepath.Join(fixture, "request.json")
	writeRequest(t, path, r)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	script := `/fixture/deckard assessment execute --tool strix --request /fixture/request.json --report /tmp/report.json --done /tmp/done >/tmp/wrapper-out 2>/tmp/wrapper-err
status=$?
if [ "$status" -ne 1 ]; then exit 20; fi
/opt/venv/bin/python -c 'import json; r=json.load(open("/tmp/report.json")); d=json.load(open("/tmp/done")); assert r["error"]=="model_unavailable"; assert r["schema_version"]==1 and r["session_id"]=="fixture-1" and r["tool"]=="strix"; assert r["upstream_source_sha"]=="55bc07991aacb1c26a81b43e7ca53148730d2019"; assert not r["completed"] and not r["complete"]; assert d=={"status":"failed"}'`
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "--user", "65532:65532", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--mount", "type=bind,src="+fixture+",dst=/fixture,readonly", "--entrypoint", "/bin/sh", "deckard:strix-candidate", "-c", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Strix wrapper did not emit its fail-closed report: %v\n%s", err, output)
	}
}
