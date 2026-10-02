//go:build unix

package plugin

import (
	"os/exec"
	"syscall"
)

// setProcessGroup runs the plugin in its own process group and kills the
// whole group on timeout, so children it spawned die with it.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
