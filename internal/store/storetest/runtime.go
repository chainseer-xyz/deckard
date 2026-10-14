package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// RunRuntime verifies that event silence is never a clean observation, even
// for direct store callers that bypass the wire validator.
func RunRuntime(t *testing.T, factory Factory) {
	for _, tool := range []string{"falco", "tetragon"} {
		t.Run(tool+" silence preserves incidents", func(t *testing.T) {
			ctx := context.Background()
			s := factory(t)
			now := time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC)
			in := store.IngestInput{Tool: tool, Scope: "k8s:uid:cluster-a", Check: model.IngestCheck(tool), Source: model.IngestSource(tool),
				AssetScope: model.ScopeExternal, ObservedAt: now, Now: now, Complete: true, ResolveAfter: 1, Digest: "detection",
				Items: []store.IngestItem{{Index: 0, AssetKind: model.KindCloudResource, AssetKey: "runtime:cluster-a:pod-a",
					Finding: model.FindingInput{Key: "policy:pod-a", Title: "Runtime policy detection", Severity: model.SeverityHigh}}}}
			result, err := s.IngestFindings(ctx, in)
			if err != nil || len(result.Opened) != 1 || result.Complete {
				t.Fatalf("event import: %+v, %v", result, err)
			}
			in.Items, in.Digest = nil, "quiet"
			in.Now, in.ObservedAt = now.Add(time.Minute), now.Add(time.Minute)
			result, err = s.IngestFindings(ctx, in)
			if err != nil || result.Complete || result.Pending != 0 || len(result.Resolved) != 0 {
				t.Fatalf("event silence became clean: %+v, %v", result, err)
			}
			findings, _, err := s.ListFindings(ctx, store.FindingFilter{Check: model.IngestCheck(tool)})
			if err != nil || len(findings) != 1 || findings[0].Status != model.StatusOpen || findings[0].MissedRuns != 0 {
				t.Fatalf("runtime incident lost: %+v, %v", findings, err)
			}
		})
		t.Run(tool+" delayed events cannot overwrite or reopen", func(t *testing.T) {
			ctx := context.Background()
			s := factory(t)
			now := time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC)
			latest := now.Format(time.RFC3339Nano)
			in := store.IngestInput{Tool: tool, Scope: "k8s:uid:cluster-a", Check: model.IngestCheck(tool), Source: model.IngestSource(tool),
				AssetScope: model.ScopeExternal, ObservedAt: now, Now: now, ResolveAfter: 1, Digest: "latest",
				Items: []store.IngestItem{{Index: 0, AssetKind: model.KindCloudResource, AssetKey: "runtime:cluster-a:pod-a",
					Finding: model.FindingInput{Key: "policy:pod-a", Title: "Runtime policy detection", Severity: model.SeverityHigh,
						Evidence: map[string]any{"runtime_last_seen": latest}}}}}
			result, err := s.IngestFindings(ctx, in)
			if err != nil || len(result.Opened) != 1 {
				t.Fatalf("event import: %+v, %v", result, err)
			}
			id := result.Opened[0].ID
			for _, eventTime := range []time.Time{now.Add(-10 * time.Minute), now} {
				in.Now, in.ObservedAt = now.Add(20*time.Minute), now.Add(20*time.Minute)
				in.Digest = eventTime.String()
				in.Items[0].Finding.Evidence = map[string]any{"runtime_last_seen": eventTime.Format(time.RFC3339Nano)}
				if _, err := s.IngestFindings(ctx, in); err != nil {
					t.Fatal(err)
				}
				f, err := s.GetFinding(ctx, id)
				if err != nil || f.Evidence["runtime_last_seen"] != latest || !f.LastSeen.Equal(now) {
					t.Fatalf("late or duplicate event changed evidence: %+v, %v", f, err)
				}
			}
			if err := s.ChangeFindingStatus(ctx, id, store.StatusChange{Status: model.StatusResolved, Actor: "operator", Note: "Investigated and contained"}, now.Add(21*time.Minute)); err != nil {
				t.Fatal(err)
			}
			audited, err := s.GetFinding(ctx, id)
			if err != nil || audited.ResolvedAt == nil || audited.SuppressionNote != "Investigated and contained" {
				t.Fatalf("manual resolution audit lost: %+v %v", audited, err)
			}
			in.Digest = "redelivery-after-resolution"
			if _, err := s.IngestFindings(ctx, in); err != nil {
				t.Fatal(err)
			}
			f, err := s.GetFinding(ctx, id)
			if err != nil || f.Status != model.StatusResolved {
				t.Fatalf("duplicate event reopened resolved incident: %+v, %v", f, err)
			}
			in.Digest = "new-detection"
			in.Items[0].Finding.Evidence = map[string]any{"runtime_last_seen": now.Add(time.Minute).Format(time.RFC3339Nano)}
			result, err = s.IngestFindings(ctx, in)
			if err != nil || len(result.Reopened) != 1 {
				t.Fatalf("genuinely new detection did not reopen incident: %+v, %v", result, err)
			}
		})
	}
}
