package nuclei

import (
	"context"
	"errors"
	"strings"
)

// ErrorReason reduces process and validation failures to bounded metric labels.
func ErrorReason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrOutOfScope) {
		return "scope-refused"
	}
	if strings.Contains(err.Error(), "incomplete scan") {
		return "incomplete"
	}
	if errors.Is(err, ErrNoTemplates) || strings.Contains(strings.ToLower(err.Error()), "no templates") {
		return "no-templates"
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "deadline exceeded") {
		return "timeout"
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom") || strings.Contains(lower, "signal: killed") {
		return "oom"
	}
	if strings.Contains(lower, "parse") || strings.Contains(lower, "json") || strings.Contains(lower, "yaml") {
		return "parse"
	}
	return "other"
}
