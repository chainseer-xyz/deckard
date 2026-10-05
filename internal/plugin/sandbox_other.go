//go:build !darwin && !(linux && (amd64 || arm64))

package plugin

import (
	"context"
	"fmt"
	"os/exec"
)

func platformSandboxCommand(context.Context, []string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("plugin sandbox: unsupported platform; execution refused")
}

func runSandboxHelper([]string) error {
	return fmt.Errorf("plugin sandbox: unsupported platform; execution refused")
}
