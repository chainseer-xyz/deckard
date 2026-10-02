//go:build !unix

package plugin

import "os/exec"

func setProcessGroup(*exec.Cmd) {}
