package nuclei

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	maxStdout = 32 << 20
	maxStderr = 8 << 10
)

// Runner executes the nuclei binary and returns its stdout (JSONL). Tests
// substitute a fake that replays fixtures.
type Runner interface {
	Run(ctx context.Context, binary string, args []string) ([]byte, error)
}

// ExecRunner runs the real binary with exec.CommandContext and an argv slice;
// no shell is involved.
type ExecRunner struct {
	// Env, when set, is called before every run for extra environment
	// variables (they override the minimal inherited set) and a cleanup to run
	// afterwards. An error fails the run before the binary starts.
	Env  func() ([]string, func(), error)
	Gate *ProcessGate
}

type capBuffer struct {
	buf    bytes.Buffer
	max    int
	cancel context.CancelFunc
	over   bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		c.over = true
		if c.cancel != nil {
			c.cancel()
		}
		return 0, errors.New("output limit exceeded")
	}
	return c.buf.Write(p)
}

// truncBuffer keeps the first max bytes and silently drops the rest. A write
// error would make os/exec stop draining the pipe and nuclei die of SIGPIPE,
// so warning volume alone would fail the run.
type truncBuffer struct {
	buf bytes.Buffer
	max int
}

func (t *truncBuffer) Write(p []byte) (int, error) {
	if room := t.max - t.buf.Len(); room > 0 {
		t.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// Run implements Runner. When nuclei exits non-zero the captured stdout is
// still returned alongside the error so callers can salvage matches.
func (r ExecRunner) Run(ctx context.Context, binary string, args []string) ([]byte, error) {
	release, err := r.Gate.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("nuclei: waiting for process slot: %w", err)
	}
	defer release()
	env := minimalEnv()
	if r.Env != nil {
		extra, cleanup, err := r.Env()
		if err != nil {
			return nil, fmt.Errorf("nuclei: preparing environment: %w", err)
		}
		defer cleanup()
		env = mergeEnv(env, extra)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- operator-configured binary, argv only, never a shell
	out := &capBuffer{max: maxStdout, cancel: cancel}
	errBuf := &truncBuffer{max: maxStderr}
	cmd.Stdout, cmd.Stderr = out, errBuf
	cmd.Env = env
	setProcessGroup(cmd)
	cmd.WaitDelay = 3 * time.Second
	err = cmd.Run()
	if out.over {
		return out.buf.Bytes(), fmt.Errorf("nuclei output exceeded %d bytes", maxStdout)
	}
	if err != nil {
		if ctx.Err() != nil {
			return out.buf.Bytes(), fmt.Errorf("nuclei: %w", ctx.Err())
		}
		return out.buf.Bytes(), fmt.Errorf("nuclei: %w: %s", err, bytes.TrimSpace(errBuf.buf.Bytes()))
	}
	return out.buf.Bytes(), nil
}

// mergeEnv returns base with every KEY=VALUE of extra replacing or adding.
func mergeEnv(base, extra []string) []string {
	over := map[string]bool{}
	for _, kv := range extra {
		k, _, _ := strings.Cut(kv, "=")
		over[k] = true
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		if k, _, _ := strings.Cut(kv, "="); !over[k] {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}

func minimalEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}
