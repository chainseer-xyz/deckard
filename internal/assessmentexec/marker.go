package assessmentexec

import (
	"io"
	"os"
	"path/filepath"
)

// Publish a fully written status atomically without ever replacing an existing
// marker. CreateTemp uses O_EXCL; Link exclusively creates the final path.
func publishDone(path, status string) error {
	if status != "succeeded" && status != "failed" {
		return ErrInvalid
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".deckard-done-")
	if err != nil {
		return ErrInvalid
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	if _, err := io.WriteString(file, `{"status":"`+status+`"}`); err != nil {
		return ErrInvalid
	}
	if file.Sync() != nil || file.Close() != nil {
		return ErrInvalid
	}
	if os.Link(file.Name(), path) != nil {
		return ErrInvalid
	}
	return nil
}
