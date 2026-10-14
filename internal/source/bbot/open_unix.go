//go:build unix

package bbot

import (
	"os"

	"golang.org/x/sys/unix"
)

// Open nonblocking before inspecting the descriptor. A producer may replace a
// regular report with a FIFO between any pathname check and the actual open.
// Discover rejects non-regular descriptors before attempting to read them.
func openReport(path string) (*os.File, error) {
	// #nosec G304 -- The operator explicitly configures this local input path.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
