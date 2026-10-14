//go:build !linux && !darwin

package main

import "errors"

func readCollectorEnvelope(path string) ([]byte, string, error) {
	return nil, path, errors.New("collector report files require Linux or macOS")
}
