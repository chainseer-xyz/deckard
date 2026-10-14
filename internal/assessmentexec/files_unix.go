//go:build linux || darwin

package assessmentexec

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ConfigMap and Secret projection paths use symlinks; report and done files do
// not. NONBLOCK prevents a FIFO from hanging before its type can be checked.
func readRegular(path string, limit int64, follow bool) ([]byte, error) {
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC
	if !follow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > limit {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}
