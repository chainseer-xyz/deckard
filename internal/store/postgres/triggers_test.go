package postgres_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestScanTriggerOutboxRetainsAcknowledgedDeltas(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t).(store.ScanTriggerStore)
	trigger := store.NewScanTrigger(store.ScanTriggerTemplates, "v2", []string{"http/b.yaml", "http/a.yaml"}, nil)
	for i := 0; i < 2; i++ {
		if err := s.PutScanTrigger(ctx, trigger); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.ListPendingScanTriggers(ctx, store.ScanTriggerTemplates)
	if err != nil || len(pending) != 1 || !reflect.DeepEqual(pending[0].Templates, trigger.Templates) {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	if other, err := s.ListPendingScanTriggers(ctx, store.ScanTriggerKEV); err != nil || len(other) != 0 {
		t.Fatalf("wrong kind returned: %v err=%v", other, err)
	}
	if err := s.AckScanTrigger(ctx, trigger.Key); err != nil {
		t.Fatal(err)
	}
	if err := s.PutScanTrigger(ctx, store.NewScanTrigger(store.ScanTriggerTemplates, "v2", []string{"http/a.yaml", "http/b.yaml"}, nil)); err != nil {
		t.Fatal(err)
	}
	pending, err = s.ListPendingScanTriggers(ctx, store.ScanTriggerTemplates)
	if err != nil || len(pending) != 0 {
		t.Fatalf("acknowledged delta was reactivated: %v err=%v", pending, err)
	}
	if err := s.AckScanTrigger(ctx, trigger.Key); err != nil {
		t.Fatalf("repeated acknowledgment failed: %v", err)
	}
}

func TestKEVScanTriggerOutboxSeparatesCatalogRevisions(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t).(store.ScanTriggerStore)
	cves := []string{"CVE-2025-00002", "CVE-2024-00001"}
	first := store.NewScanTrigger(store.ScanTriggerKEV, `catalog:["v2","2026-10-02"]`, nil, cves)
	if err := s.PutScanTrigger(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.AckScanTrigger(ctx, first.Key); err != nil {
		t.Fatal(err)
	}
	second := store.NewScanTrigger(store.ScanTriggerKEV, `catalog:["v4","2026-10-04"]`, nil, cves)
	if first.Key == second.Key {
		t.Fatal("different catalog revisions reused the same trigger key")
	}
	for _, trigger := range []store.ScanTrigger{first, second, second} {
		if err := s.PutScanTrigger(ctx, trigger); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.ListPendingScanTriggers(ctx, store.ScanTriggerKEV)
	if err != nil || len(pending) != 1 || pending[0].Key != second.Key || pending[0].Release != second.Release {
		t.Fatalf("new revision lost or old revision reactivated: %+v err=%v", pending, err)
	}
	if err := s.AckScanTrigger(ctx, second.Key); err != nil {
		t.Fatal(err)
	}
	if err := s.PutScanTrigger(ctx, second); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.ListPendingScanTriggers(ctx, store.ScanTriggerKEV); err != nil || len(pending) != 0 {
		t.Fatalf("same revision replay was not idempotent: %+v err=%v", pending, err)
	}
}
