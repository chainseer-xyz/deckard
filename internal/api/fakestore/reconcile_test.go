package fakestore

import (
	"context"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestReconcilePartialNeverResolves(t *testing.T) {
	s := New()
	s.Assets[1] = model.Asset{ID: 1, Key: "a.example.com", Kind: model.KindHostname}
	ctx := context.Background()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	rec := func(partial bool, keys ...string) store.ReconcileResult {
		var fs []model.FindingInput
		for _, k := range keys {
			fs = append(fs, model.FindingInput{Key: k, Severity: model.SeverityHigh, Title: k})
		}
		now = now.Add(time.Minute)
		r, err := s.ReconcileFindings(ctx, store.ReconcileInput{AssetID: 1, Check: "cve.nuclei", Findings: fs, ResolveAfter: 1, Now: now, PartialRun: partial})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := rec(false, "old"); len(r.Opened) != 1 {
		t.Fatalf("open: %+v", r)
	}
	if r := rec(true); len(r.Resolved) != 0 {
		t.Fatalf("partial resolved: %+v", r)
	}
	if r := rec(true, "new"); len(r.Opened) != 1 || len(r.Resolved) != 0 {
		t.Fatalf("partial open: %+v", r)
	}
	if r := rec(false, "new"); len(r.Resolved) != 1 || r.Resolved[0].Title != "old" {
		t.Fatalf("full run must resolve old: %+v", r)
	}
	if _, err := s.ReconcileFindings(ctx, store.ReconcileInput{AssetID: 9}); err != store.ErrNotFound {
		t.Fatalf("unknown asset err = %v", err)
	}
}
