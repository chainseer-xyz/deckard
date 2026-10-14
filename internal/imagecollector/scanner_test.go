package imagecollector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/trivy"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestCommandScannerKeepsFixedRegistryFlagsAndExcludesCredentials(t *testing.T) {
	t.Setenv("DECKARD_TOKEN", "must-not-inherit")
	t.Setenv("AWS_ACCESS_KEY_ID", "must-not-inherit")
	t.Setenv("TRIVY_USERNAME", "must-not-inherit")
	scanner, err := NewCommandScanner("/dedicated-registry")
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	// This helper verifies process arguments/environment, not actual Trivy output.
	helper := filepath.Join(t.TempDir(), "helper")
	script := `#!/bin/sh
arguments="$*"
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then shift; output="$1"; fi
  shift
done
printf '%s\n' "$arguments" > "$output"
env >> "$output"
`
	if err = os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	scanner.binary = helper
	raw, err := scanner.Scan(context.Background(), Target{Reference: reference(1), Digest: digest(1), Platform: "linux/arm64"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, expected := range []string{"image --image-src remote --platform linux/arm64 --scanners vuln --format json", "--exit-code 0 --timeout 2m " + reference(1), "DOCKER_CONFIG=/dedicated-registry", "AWS_EC2_METADATA_DISABLED=true"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing fixed scanner constraint %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "must-not-inherit") || strings.Contains(text, "--ignore-unfixed") || strings.Contains(text, "--severity") {
		t.Fatal("scanner credentials or filtered output")
	}
}

func TestCommandScannerFailureAndCancellationCannotUseReport(t *testing.T) {
	scanner, err := NewCommandScanner("")
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	helper := filepath.Join(t.TempDir(), "helper")
	if err = os.WriteFile(helper, []byte("#!/bin/sh\nexit 9\n"), 0700); err != nil {
		t.Fatal(err)
	}
	scanner.binary = helper
	if raw, err := scanner.Scan(context.Background(), Target{}); err == nil || raw != nil {
		t.Fatal("failed scanner exported output")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if raw, err := scanner.Scan(ctx, Target{}); err == nil || raw != nil || time.Since(started) > time.Second {
		t.Fatal("cancellation did not fail closed")
	}
}

// Opt-in integration test. Run in the official pinned Trivy 0.76.0 container
// with harmless registry target and writable disk scratch. Not a mock or local
// daemon scan; it runs the same real binary and registry-only arguments as jobs.
func TestNativePinnedTrivyFixture(t *testing.T) {
	ref := os.Getenv("TRIVY_COLLECTOR_FIXTURE_TARGET")
	if ref == "" {
		t.Skip("set TRIVY_COLLECTOR_FIXTURE_TARGET in the pinned scanner image")
	}
	scanner, err := NewCommandScanner("")
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), ScanDuration)
	defer cancel()
	raw, err := scanner.Scan(ctx, Target{Reference: ref, Platform: "linux/arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("native scanner emitted empty output")
	}
	report, err := trivy.ParseReport(raw, ingest.ParseOptions{Scope: testScope})
	if err != nil {
		t.Fatal(err)
	}
	want, ok := model.ContainerImageKey(ref)
	if !ok {
		t.Fatal("invalid harmless native fixture reference")
	}
	if len(report.Artifacts) == 0 || report.Artifacts[0].Key != want {
		t.Fatalf("native fixture did not preserve exact requested digest: %+v", report.Artifacts)
	}
	t.Logf("native pinned Trivy: %d artifacts, %d findings, exact manifest %s", len(report.Artifacts), len(report.Findings), want)
}
