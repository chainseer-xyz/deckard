package plugin

import (
	"context"
	"fmt"
	"os/exec"
)

const sandboxHelper = "_deckard-plugin-sandbox"

// RunSandboxHelper handles Deckard's private Linux re-exec entry point. It
// installs the network syscall filter before replacing itself with the plugin.
// Call it before command dispatch, also in test binaries that execute plugins.
func RunSandboxHelper(args []string) (bool, error) {
	if len(args) == 0 || args[0] != sandboxHelper {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("plugin sandbox: missing executable")
	}
	return true, runSandboxHelper(args[1:])
}

func sandboxCommand(ctx context.Context, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("plugin sandbox: missing executable")
	}
	binary, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, err
	}
	return platformSandboxCommand(ctx, append([]string{binary}, argv[1:]...))
}
