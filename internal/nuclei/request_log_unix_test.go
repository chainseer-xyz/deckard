//go:build linux || darwin

package nuclei

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestLogDrainsLargeVolumeWithoutDiskWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "errors.fifo")
	if err := createRequestLog(path); err != nil {
		t.Fatal(err)
	}
	finish, err := startRequestLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = finish() }()
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	chunk := bytes.Repeat([]byte("e"), 16<<10)
	for range 512 { // 8 MiB, with a fixed 16 KiB reader buffer.
		if _, err := writer.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := finish(); err == nil || !strings.Contains(err.Error(), "incomplete scan") {
		t.Fatalf("large request error stream became complete: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 || info.Size() != 0 {
		t.Fatalf("error stream used a disk file: info=%v error=%v", info, err)
	}
}

func TestRequestLogFinalReadAndIdempotentClose(t *testing.T) {
	for _, data := range []string{"", "request refused\n"} {
		for range 25 {
			path := filepath.Join(t.TempDir(), "errors.fifo")
			if err := createRequestLog(path); err != nil {
				t.Fatal(err)
			}
			finish, err := startRequestLog(path)
			if err != nil {
				t.Fatal(err)
			}
			if data != "" {
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					_ = finish()
					t.Fatal(err)
				}
			}
			err = finish()
			if (err != nil) != (data != "") {
				t.Fatalf("final buffered bytes %q: error=%v", data, err)
			}
			if again := finish(); (again != nil) != (err != nil) {
				t.Fatalf("second close changed completeness: first=%v second=%v", err, again)
			}
		}
	}
}
