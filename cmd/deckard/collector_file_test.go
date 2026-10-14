//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRuntimeUploadRefusesFIFOWithoutWaitingForWriter(t *testing.T) {
	t.Setenv("RUNTIME_TEST_TOKEN", testIngestToken)
	path := filepath.Join(t.TempDir(), "report.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		var out, errw bytes.Buffer
		done <- runRuntime([]string{"upload", "--file", path, "--url", "http://127.0.0.1:1", "--token-env", "RUNTIME_TEST_TOKEN", "--cluster-scope", "k8s:uid:cluster-a"}, &out, &errw)
	}()
	select {
	case code := <-done:
		if code == 0 {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("runtime uploader waited for FIFO writer")
	}
	regular := filepath.Join(filepath.Dir(path), "regular.json")
	if err := os.WriteFile(regular, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCollectorEnvelope(link); err == nil {
		t.Fatal("report symlink accepted")
	}
}
