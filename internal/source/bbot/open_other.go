//go:build !unix

package bbot

import (
	"errors"
	"os"
)

// Non-Unix platforms do not expose Unix filesystem FIFOs. Keep pathname and
// descriptor regular-file checks around the ordinary read-only open.
func openReport(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("bbot: discovery_file must be a regular file")
	}
	// #nosec G304 -- The operator explicitly configures this local input path.
	return os.Open(path)
}
