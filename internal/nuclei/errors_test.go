package nuclei

import (
	"context"
	"errors"
	"testing"
)

func TestErrorReason(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"no templates", ErrNoTemplates, "no-templates"},
		{"timeout", context.DeadlineExceeded, "timeout"},
		{"oom", errors.New("signal: killed (out of memory)"), "oom"},
		{"parse", errors.New("yaml parse failed"), "parse"},
		{"other", errors.New("exit status 2"), "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ErrorReason(tc.err); got != tc.want {
				t.Fatalf("ErrorReason() = %q, want %q", got, tc.want)
			}
		})
	}
}
