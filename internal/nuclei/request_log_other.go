//go:build !linux && !darwin

package nuclei

import "fmt"

func createRequestLog(string) error {
	return fmt.Errorf("nuclei: destination-policy request logging requires Linux or macOS")
}

func startRequestLog(string) (func() error, error) {
	return nil, fmt.Errorf("nuclei: destination-policy request logging requires Linux or macOS")
}
