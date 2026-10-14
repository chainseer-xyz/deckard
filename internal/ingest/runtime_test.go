package ingest

import (
	"strings"
	"testing"
)

func TestRuntimeEventsCannotAssertCompleteCoverage(t *testing.T) {
	for _, tool := range []string{"falco", "tetragon"} {
		t.Run(tool, func(t *testing.T) {
			r := valid()
			r.Tool = tool
			problems := Validate(r, Options{Now: now})
			if len(problems) != 1 || !strings.Contains(problems[0].Reason, "runtime events cannot assert complete coverage") {
				t.Fatalf("complete runtime stream accepted: %v", problems)
			}
			r.Complete = false
			if problems := Validate(r, Options{Now: now}); len(problems) != 0 {
				t.Fatalf("event-only report rejected: %v", problems)
			}
		})
	}
}

func TestRuntimeEventsRejectFutureEvidence(t *testing.T) {
	r := valid()
	r.Tool, r.Complete = "tetragon", false
	r.Findings[0].Evidence = map[string]any{"runtime_last_seen": "2099-01-01T00:00:00Z"}
	problems := Validate(r, Options{Now: now})
	if len(problems) != 1 || !strings.Contains(problems[0].Reason, "runtime event time") {
		t.Fatalf("future event could prevent later incident updates: %v", problems)
	}
}
