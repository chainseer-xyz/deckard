//go:build !linux && !darwin

package assessmentexec

import "os/exec"

func containProcess(*exec.Cmd) {}
