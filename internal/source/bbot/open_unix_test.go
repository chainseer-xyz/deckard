//go:build unix

package bbot

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/source"
)

func TestDiscoverRejectsFIFOReplacementAtOpenBoundary(t *testing.T) {
	path := reportFile(t, `{"type":"DNS_NAME","data":"valid.example"}`)
	s, err := New(config.SourceConfig{Name: "recon", DiscoveryFile: path})
	if err != nil {
		t.Fatal(err)
	}
	openFile := s.openFile
	var reached, nonblocking, readonly, closeOnExec bool
	s.openFile = func(path string) (*os.File, error) {
		reached = true
		cleanup := replaceReportWithFIFO(t, path)
		defer cleanup()
		f, err := openFile(path)
		if err != nil {
			return nil, err
		}
		raw, err := f.SyscallConn()
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := raw.Control(func(fd uintptr) {
			flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
			if err != nil {
				t.Error(err)
				return
			}
			nonblocking, readonly = flags&unix.O_NONBLOCK != 0, flags&unix.O_ACCMODE == unix.O_RDONLY
			flags, err = unix.FcntlInt(fd, unix.F_GETFD, 0)
			if err != nil {
				t.Error(err)
				return
			}
			closeOnExec = flags&unix.FD_CLOEXEC != 0
		}); err != nil {
			_ = f.Close()
			return nil, err
		}
		return f, nil
	}
	d, err := s.Discover(context.Background())
	if !reached || !nonblocking || !readonly || !closeOnExec {
		t.Fatalf("unsafe report open: reached=%v nonblocking=%v readonly=%v close-on-exec=%v", reached, nonblocking, readonly, closeOnExec)
	}
	if err == nil || d != nil {
		t.Fatal("accepted the replacement FIFO as a report")
	}
}

func replaceReportWithFIFO(t *testing.T, path string) func() {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("report was not regular before the open-boundary replacement")
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// A keeper makes even the old blocking opener return. We can inspect the
	// descriptor flags deterministically, without leaving a stuck goroutine or
	// using elapsed time as evidence that the production open is nonblocking.
	keeper, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := unix.Close(keeper); err != nil {
			t.Error(err)
		}
	}
}

func TestFIFOReplacementDoesNotWaitForPeer(t *testing.T) {
	path := reportFile(t, `{"type":"DNS_NAME","data":"valid.example"}`)
	s, err := New(config.SourceConfig{Name: "recon", DiscoveryFile: path})
	if err != nil {
		t.Fatal(err)
	}
	openFile := s.openFile
	s.openFile = func(path string) (*os.File, error) {
		if err := os.Rename(path, path+".original"); err != nil {
			return nil, err
		}
		if err := unix.Mkfifo(path, 0o600); err != nil {
			return nil, err
		}
		return openFile(path) // No FIFO writer exists at this boundary.
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		d   *source.Discovery
		err error
	}
	done := make(chan result, 1)
	go func() {
		d, err := s.Discover(ctx)
		done <- result{d: d, err: err}
	}()
	select {
	case got := <-done:
		if got.err == nil || got.d != nil {
			t.Fatal("replacement FIFO was accepted")
		}
	case <-ctx.Done():
		// Rescue a regressed blocking opener before failing, so this regression
		// cannot leave a stuck goroutine behind. The descriptor-flags regression
		// independently verifies O_NONBLOCK without relying on a timer.
		keeper, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(keeper) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("FIFO reader did not stop after rescue")
		}
		t.Fatal("report open waited for a FIFO peer instead of refusing the descriptor")
	}
}
