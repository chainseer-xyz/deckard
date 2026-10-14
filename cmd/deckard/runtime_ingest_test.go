package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

func TestRuntimeCLIAlwaysUsesEventOnlyLifecycle(t *testing.T) {
	reports := map[string]string{
		"falco":    `{"time":"2026-10-14T01:00:00Z","rule":"Write below etc","priority":"Warning","source":"syscall","output_fields":{"k8s.pod.uid":"11111111-1111-4111-8111-111111111111","k8s.ns.name":"default","container.id":"container-a"}}`,
		"tetragon": `{"time":"2026-10-14T01:00:00Z","node_name":"node-a","process_kprobe":{"policy_name":"sensitive-files","action":"KPROBE_ACTION_POST","process":{"pod":{"uid":"11111111-1111-4111-8111-111111111111","namespace":"default","name":"api"}}}}`,
	}
	for tool, data := range reports {
		t.Run(tool, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "events.json")
			if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errs := runI(t, "--tool", tool, "--scope", "k8s:uid:22222222-2222-4222-8222-222222222222", "--file", file, "--dry-run")
			if code != ingestExitOK {
				t.Fatalf("native runtime report exit %d: %s", code, errs)
			}
			r, err := ingest.Decode([]byte(out))
			if err != nil || r.Complete || len(r.Findings) != 1 {
				t.Fatalf("runtime report lost event-only semantics: %+v, %v", r, err)
			}
			code, _, errs = runI(t, "--tool", "prowler", "--format", tool, "--scope", "cluster", "--file", file, "--dry-run")
			if code != ingestExitUsage || !strings.Contains(errs, "must match --tool") {
				t.Fatalf("event report impersonated snapshot producer: exit=%d %s", code, errs)
			}
		})
	}
}
