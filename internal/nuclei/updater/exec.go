package updater

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

const maxOutput = 1 << 20

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil // never fail the child on log volume
}

// execCommand runs binary with an argv slice (no shell) and exactly env. It
// captures stdout and stderr together, bounded.
func execCommand(ctx context.Context, binary string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- operator-configured binary, fixed argv, never a shell
	out := &limitedBuffer{max: maxOutput}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = env
	setProcessGroup(cmd)
	cmd.WaitDelay = 3 * time.Second
	err := cmd.Run()
	if err != nil && ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	return out.buf.Bytes(), err
}
