//go:build !unix

package nuclei

import "os/exec"

func setProcessGroup(*exec.Cmd) {}
