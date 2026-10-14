package assessmentexec

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/url"
	"os/exec"
	"strconv"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

type boundedOutput struct {
	data   bytes.Buffer
	max    int64
	failed bool
	cancel context.CancelFunc
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	if b.failed || int64(len(raw)) > b.max-int64(b.data.Len()) {
		b.failed = true
		b.cancel()
		return 0, ErrInvalid
	}
	return b.data.Write(raw)
}

func runZGrab(ctx context.Context, r assessmentjob.ExecutionRequest, work string, run func(*exec.Cmd) error) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &boundedOutput{max: r.MaxOutputBytes, cancel: cancel}
	for _, target := range r.FixedTargets {
		u, _ := url.Parse(target.Origin)
		var input bytes.Buffer
		writer := csv.NewWriter(&input)
		for _, ip := range target.Addresses {
			_ = writer.Write([]string{ip.Unmap().String(), u.Hostname(), "", strconv.Itoa(int(target.Port))})
		}
		writer.Flush()
		timeout := (min(time.Duration(r.TimeoutSeconds)*time.Second, 30*time.Second)).String()
		args := []string{"--senders=1", "--connections-per-host=1", "--blocklist-file=", "--read-limit-per-host=256", "http", "--no-http2", "--max-redirects=0", "--method=GET", "--endpoint=/", "--port=" + strconv.Itoa(int(target.Port)), "--connect-timeout=" + timeout, "--target-timeout=" + timeout, "--max-size=64"}
		if u.Scheme == "https" {
			args = append(args, "--use-https", "--verify-server-certificate", "--server-name="+u.Hostname())
		}
		cmd := nativeCommand(ctx, work, "/usr/local/bin/zgrab2", args...)
		cmd.Stdin = &input
		cmd.Stdout = output
		if err := run(cmd); err != nil {
			return output.data.Bytes(), ErrInvalid
		}
		if output.failed || ctx.Err() != nil {
			return nil, ErrInvalid
		}
	}
	return output.data.Bytes(), nil
}
