//go:build unix

package nuclei

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the child in its own group and kills the whole group
// on cancellation so nuclei helpers cannot outlive the timeout.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
