//go:build linux || darwin

package assessmentexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNonRegularInputCannotBlockAssessmentWrapper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := readRegular(path, 64<<10, true); err == nil {
		t.Fatal("FIFO admitted as regular input")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("FIFO blocked trusted wrapper")
	}
}

func TestProjectedRequestSymlinksRemainReadableButReportSymlinksAreRejected(t *testing.T) {
	dir := t.TempDir()
	realPath, projected := filepath.Join(dir, "real"), filepath.Join(dir, "projected")
	if err := os.WriteFile(realPath, []byte("projection"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, projected); err != nil {
		t.Fatal(err)
	}
	raw, err := readRegular(projected, 64<<10, true)
	if err != nil || string(raw) != "projection" {
		t.Fatal("Kubernetes projected input rejected")
	}
	if _, err := readRegular(projected, 64<<10, false); err == nil {
		t.Fatal("report symlink accepted")
	}
}

func TestNativeTimeoutKillsDescendantsWithoutWaitingForTheirOutputPipes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	cmd := nativeCommand(ctx, t.TempDir(), "/bin/sh", "-c", "sleep 10 & wait")
	start := time.Now()
	if err := cmd.Run(); err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("native command ignored deadline")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("native descendants kept process/output pipes alive")
	}
}
