//go:build !unix

package updater

import "os/exec"

func setProcessGroup(*exec.Cmd) {}
