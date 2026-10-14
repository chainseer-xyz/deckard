//go:build !linux && !darwin

package assessmentexec

func readRegular(string, int64, bool) ([]byte, error) { return nil, ErrInvalid }
