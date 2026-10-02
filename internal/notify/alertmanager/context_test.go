package alertmanager

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestContextAnnotations(t *testing.T) {
	f := finding(func(f *model.Finding) {
		f.Context = map[string]any{
			"lineage":        "a --proxied_by--> b",
			"previous_state": "[22]",
			"current_state":  "[22,8080]",
			"owner":          "kubernetes cluster=prod",
			"last_changed":   "2026-10-02T08:00:00Z",
		}
	})
	a := buildPayload([]model.Finding{f}, nil, t0, time.Minute, "")[0].Annotations
	for k, want := range map[string]string{
		"lineage": "a --proxied_by--> b", "previous_state": "[22]", "current_state": "[22,8080]",
		"owner": "kubernetes cluster=prod", "last_changed": "2026-10-02T08:00:00Z",
		"first_seen": f.FirstSeen.UTC().Format(time.RFC3339),
	} {
		if a[k] != want {
			t.Errorf("%s = %q want %q", k, a[k], want)
		}
	}
}

func TestContextAnnotationsAbsentAndTruncated(t *testing.T) {
	a := buildPayload([]model.Finding{finding(nil)}, nil, t0, time.Minute, "")[0].Annotations
	for _, k := range []string{"lineage", "previous_state", "current_state", "owner", "last_changed"} {
		if _, ok := a[k]; ok {
			t.Errorf("%s should be absent without context", k)
		}
	}
	long := strings.Repeat("é", 5000) // multi-byte: must not split a rune
	f := finding(func(f *model.Finding) { f.Context = map[string]any{"lineage": long, "owner": 42} })
	a = buildPayload([]model.Finding{f}, nil, t0, time.Minute, "")[0].Annotations
	if !utf8.ValidString(a["lineage"]) || len(a["lineage"]) > maxContext+len(truncMarker) || !strings.HasSuffix(a["lineage"], truncMarker) {
		t.Errorf("lineage not safely truncated: %d bytes", len(a["lineage"]))
	}
	if _, ok := a["owner"]; ok {
		t.Error("non-string context value must be ignored")
	}
}
