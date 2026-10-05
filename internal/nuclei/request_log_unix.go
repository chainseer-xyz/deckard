//go:build linux || darwin

package nuclei

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

func createRequestLog(path string) error {
	return unix.Mkfifo(path, 0o600)
}

// startRequestLog opens the FIFO read/write before Nuclei opens its writer.
// NONBLOCK avoids writer-open deadlock and makes final draining deterministic.
// Only a failure bit is retained; URLs and template secrets never enter errors.
func startRequestLog(path string) (func() error, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var failed bool
	var readErr error
	go func() {
		defer close(done)
		var buffer [16 << 10]byte
		poll := [1]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		read := func() (int, error) {
			n, err := unix.Read(fd, buffer[:])
			failed = failed || n > 0
			if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
				readErr = err
			}
			return n, err
		}
		for {
			select {
			case <-stop:
				// The child has exited. One final nonblocking read detects any
				// buffered error before closing, without waiting on stray writers.
				_, _ = read()
				return
			default:
			}
			n, err := read()
			if readErr != nil {
				return
			}
			if n > 0 || errors.Is(err, unix.EINTR) {
				continue
			}
			// Wake as soon as bytes arrive. A short bounded poll also lets
			// finish stop an idle reader without closing an in-use descriptor.
			if _, err := unix.Poll(poll[:], 10); err != nil && !errors.Is(err, unix.EINTR) {
				readErr = err
				return
			}
		}
	}()
	return func() error {
		once.Do(func() {
			close(stop)
			<-done
			readErr = errors.Join(readErr, unix.Close(fd))
		})
		if readErr != nil {
			return fmt.Errorf("checking request completeness: %w", readErr)
		}
		if failed {
			return fmt.Errorf("nuclei: incomplete scan: requests failed or were refused")
		}
		return nil
	}, nil
}
