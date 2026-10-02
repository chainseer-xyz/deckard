//go:build unix

package updater

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the child in its own group and kills the whole group on
// cancellation, so the installer cannot outlive the update timeout.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
