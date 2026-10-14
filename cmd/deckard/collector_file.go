//go:build linux || darwin

package main

import (
	"errors"
	"io"
	"os"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"golang.org/x/sys/unix"
)

func readCollectorEnvelope(path string) ([]byte, string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, path, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > ingest.MaxBodyBytes {
		return nil, path, errors.New("collector report must be a bounded regular file, not a symlink or FIFO")
	}
	raw, err := io.ReadAll(io.LimitReader(file, ingest.MaxBodyBytes+1))
	if err != nil || len(raw) > ingest.MaxBodyBytes {
		return nil, path, errors.New("cannot read bounded collector report")
	}
	return raw, path, nil
}
