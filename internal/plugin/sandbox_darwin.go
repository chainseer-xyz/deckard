//go:build darwin

package plugin

import (
	"context"
	"fmt"
	"os/exec"
)

func platformSandboxCommand(ctx context.Context, argv []string) (*exec.Cmd, error) {
	// Seatbelt applies to descendants and blocks direct TCP, UDP, DNS and Unix
	// socket traffic. Guarded I/O travels only over inherited anonymous pipes.
	args := append([]string{"-p", "(version 1)(allow default)(deny network*)"}, argv...)
	return exec.CommandContext(ctx, "/usr/bin/sandbox-exec", args...), nil // #nosec G204 -- fixed sandbox, operator-configured argv without a shell
}

func runSandboxHelper([]string) error {
	return fmt.Errorf("plugin sandbox: Linux helper is unavailable on macOS")
}
