package imagecollector

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest/trivy"
)

// CommandScanner shares only a fresh per-run DB cache across serialized scans.
// Its subprocess environment excludes service, cloud and ingest credentials.
type CommandScanner struct{ root, binary, registryAuthDir string }

func NewCommandScanner(registryAuthDir string) (*CommandScanner, error) {
	if registryAuthDir != "" && !filepath.IsAbs(registryAuthDir) {
		return nil, fmt.Errorf("registry authentication directory must be absolute")
	}
	root, err := os.MkdirTemp("", "deckard-runtime-images-")
	if err != nil {
		return nil, fmt.Errorf("create scanner scratch: %w", err)
	}
	return &CommandScanner{root: root, binary: "/usr/local/bin/trivy", registryAuthDir: registryAuthDir}, nil
}

func (s *CommandScanner) Close() { _ = os.RemoveAll(s.root) }

func (s *CommandScanner) Scan(ctx context.Context, target Target) ([]byte, error) {
	dir, err := os.MkdirTemp(s.root, "report-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	output := filepath.Join(dir, "result.json")
	args := []string{"image", "--image-src", "remote", "--platform", target.Platform, "--scanners", "vuln", "--format", "json", "--output", output, "--cache-dir", filepath.Join(s.root, "cache"), "--exit-code", "0", "--timeout", "2m", target.Reference}
	command := exec.CommandContext(ctx, s.binary, args...) // #nosec G204 -- fixed pinned scanner binary and validated immutable runtime reference, no shell
	command.Dir = s.root                                   // no operator/current-directory Trivy configuration
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + s.root, "TMPDIR=" + s.root, "AWS_EC2_METADATA_DISABLED=true"}
	if s.registryAuthDir != "" {
		command.Env = append(command.Env, "DOCKER_CONFIG="+s.registryAuthDir)
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("native Trivy scan failed")
	}
	file, err := os.Open(output) // #nosec G304 -- fixed result filename inside our private per-run temporary directory
	if err != nil {
		return nil, fmt.Errorf("native scanner produced no report")
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, trivy.MaxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > trivy.MaxInputBytes {
		return nil, fmt.Errorf("native scanner report is empty or exceeds 64 MiB")
	}
	return raw, nil
}
