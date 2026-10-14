package assessmentexec

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

type ExecuteOptions struct {
	Tool                              assessmentjob.Tool
	RequestFile, ReportFile, DoneFile string
}

func Execute(ctx context.Context, options ExecuteOptions) error {
	return execute(ctx, options, (*exec.Cmd).Run, os.Getenv)
}

func execute(ctx context.Context, o ExecuteOptions, run func(*exec.Cmd) error, getenv func(string) string) error {
	if o.RequestFile == "" || o.ReportFile == "" || o.DoneFile == "" || filepath.Clean(o.ReportFile) == filepath.Clean(o.DoneFile) {
		return ErrInvalid
	}
	if _, err := os.Lstat(o.DoneFile); !os.IsNotExist(err) {
		return ErrInvalid
	}
	report, err := os.OpenFile(o.ReportFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrInvalid
	}
	defer func() { _ = report.Close() }()
	r, result := loadRequest(o)
	if result == nil {
		result = runExecution(ctx, o, r, run, getenv, report)
	}
	status := "succeeded"
	if result != nil {
		status = "failed"
	}
	if publishDone(o.DoneFile, status) != nil || result != nil {
		return ErrInvalid
	}
	return nil
}

func runExecution(ctx context.Context, o ExecuteOptions, r assessmentjob.ExecutionRequest, run func(*exec.Cmd) error, getenv func(string) string, report *os.File) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.TimeoutSeconds)*time.Second)
	defer cancel()
	work, err := os.MkdirTemp("", "deckard-assessment-")
	if err != nil {
		return ErrInvalid
	}
	defer func() { _ = os.RemoveAll(work) }()
	var raw []byte
	switch r.Tool {
	case assessmentjob.ToolZGrab2:
		raw, err = runZGrab(ctx, r, work, run)
	case assessmentjob.ToolStrix:
		raw, err = runStrix(ctx, r, work, run, getenv)
	case assessmentjob.ToolZAP:
		raw, err = runZAP(ctx, r, work, run, getenv)
	default:
		err = ErrInvalid
	}
	if int64(len(raw)) > r.MaxOutputBytes || !validReport(raw, o.Tool) {
		return ErrInvalid
	}
	if _, writeErr := report.Write(raw); writeErr != nil {
		return ErrInvalid
	}
	if report.Sync() != nil || ctx.Err() != nil || err != nil {
		return ErrInvalid
	}
	return nil
}

func nativeCommand(ctx context.Context, work, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- private callers select fixed binaries and argv; no shell or caller-supplied command.
	cmd.Dir = work
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + work, "TMPDIR=" + work, "LANG=C.UTF-8"}
	cmd.Stderr = io.Discard
	cmd.Stdout = io.Discard
	cmd.WaitDelay = time.Second
	containProcess(cmd)
	return cmd
}

func runStrix(ctx context.Context, r assessmentjob.ExecutionRequest, work string, run func(*exec.Cmd) error, getenv func(string) string) ([]byte, error) {
	request, output := filepath.Join(work, "request.json"), filepath.Join(work, "native.json")
	raw, _ := json.Marshal(r)
	if err := os.WriteFile(request, raw, 0600); err != nil {
		return nil, ErrInvalid
	}
	cmd := nativeCommand(ctx, work, "/opt/venv/bin/python", "/opt/deckard/strix_adapter.py", "run", "--request", request, "--output", output)
	if err := strixEnvironment(cmd, getenv); err != nil {
		return nil, err
	}
	runErr := run(cmd)
	result, err := readRegular(output, r.MaxOutputBytes, false)
	if err != nil {
		return nil, ErrInvalid
	}
	return result, runErr
}
