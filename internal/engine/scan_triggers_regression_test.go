package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

func TestDeltaWaitsForThePublishingRelease(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("some_paths_present=%v", partial), func(t *testing.T) {
			th := newTmplHarness(t, nil, []model.Asset{urlAsset(1, "https://a.example.com/")})
			th.tpl.status.Version = "v10.9.0"
			th.dl.missing = map[string]bool{"http/new.yaml": true}
			paths := []string{"http/new.yaml"}
			if partial {
				paths = append(paths, "http/present.yaml")
			}
			job := deltaJob{Kind: KindScanNewTemplates, Release: "v10.10.0", Templates: paths, AssetIDs: []int64{1}}
			if err := th.r.runDelta(context.Background(), job); !errors.Is(err, errTemplatesNotReady) || len(th.dl.requests()) != 0 {
				t.Fatalf("older tree must wait without partially running: scans=%v err=%v", th.dl.requests(), err)
			}
			th.tpl.status.Version = "v10.11.0"
			if err := th.r.runDelta(context.Background(), job); err != nil {
				t.Fatalf("a later release may retire missing paths: %v", err)
			}
			want := 0
			if partial {
				want = 1
			}
			if len(th.dl.requests()) != want {
				t.Fatalf("later release scans=%d, want %d", len(th.dl.requests()), want)
			}
		})
	}
	for _, tc := range []struct {
		current, requested string
		reached            bool
	}{
		{"v10.9.0", "v10.10.0", false}, {"v10.10.0", "v10.10.0", true}, {"v10.11.0", "v10.10.0", true},
		{"v10.10.0-beta.1", "v10.10.0", false}, {"", "v10.10.0", false}, {"unknown", "v10.10.0", false},
	} {
		if got := templateReleaseReached(tc.current, tc.requested); got != tc.reached {
			t.Errorf("release %q reaches %q: %v, want %v", tc.current, tc.requested, got, tc.reached)
		}
	}
}

func TestIntegrationRunOnceExecutesAndAcknowledgesKEVScansLocally(t *testing.T) {
	ctx := context.Background()
	feed := &fakeFeed{delta: vulnintel.Delta{NewKEV: []string{"CVE-2025-55182"}}}
	originalTrigger := &fakeTrigger{err: errors.New("original engine queue must not be used")}
	e, pool, tpl, dl, proc, st := templateEngineCfg(t, []string{RoleAPI}, func(c *config.Config) {
		c.Vulnintel.Enabled = true
	}, WithVulnIntel(feed), WithCVEScanTrigger(originalTrigger))
	tpl.up = updater.Update{Version: "v10.5.0"}
	dl.res = nuclei.ScanResult{Findings: map[int64][]model.FindingInput{1: {sev("CVE-2025-55182")}}}
	if err := e.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(dl.requests()) != 1 || len(proc.calls) != 1 || !proc.calls[0].res.Partial {
		t.Fatalf("one-shot must execute a partial KEV scan: requests=%v calls=%v", dl.requests(), proc.calls)
	}
	if len(originalTrigger.calls) != 0 {
		t.Fatalf("original queue trigger was called: %v", originalTrigger.calls)
	}
	if _, n := riverJobs(t, pool, KindScanCVEs); n != 0 {
		t.Fatalf("one-shot leaked %d jobs into River", n)
	}
	triggers := st.(store.ScanTriggerStore)
	pendingTriggerCount(t, triggers, store.ScanTriggerKEV, 0)
}

func TestIntegrationRunOnceRetainsKEVAfterDeltaFailure(t *testing.T) {
	ctx := context.Background()
	feed := &fakeFeed{delta: vulnintel.Delta{NewKEV: []string{"CVE-2025-55182"}}}
	e, pool, tpl, dl, _, st := templateEngineCfg(t, []string{RoleAPI}, func(c *config.Config) {
		c.Vulnintel.Enabled = true
	}, WithVulnIntel(feed))
	tpl.up = updater.Update{Version: "v10.5.0"}
	dl.scanErr = errors.New("nuclei interrupted")
	if err := e.RunOnce(ctx); err == nil {
		t.Fatal("expected the one-shot delta failure")
	}
	triggers := st.(store.ScanTriggerStore)
	pendingTriggerCount(t, triggers, store.ScanTriggerKEV, 1)
	dl.scanErr = nil
	if err := e.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(dl.requests()) != 2 {
		t.Fatalf("unchanged feed did not replay pending scan: requests=%v", dl.requests())
	}
	pendingTriggerCount(t, triggers, store.ScanTriggerKEV, 0)
	if _, n := riverJobs(t, pool, KindScanCVEs); n != 0 {
		t.Fatalf("one-shot retry leaked %d jobs into River", n)
	}
}

type failingObservationStore struct {
	store.Store
	err error
}

func (s failingObservationStore) LatestObservations(context.Context, int64) ([]model.Observation, error) {
	return nil, s.err
}

type failingObservationTriggerStore struct {
	failingObservationStore
	store.ScanTriggerStore
}

func TestIntegrationObservationReadFailureKeepsTemplateTriggerPending(t *testing.T) {
	ctx := context.Background()
	e, _, tpl, _, _, st := templateEngine(t, []string{RoleAPI})
	diff, err := st.AddDiscovered(ctx, []store.AssetUpsert{{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "observed.example.com", Source: "static"}, Scope: model.ScopeOwned}}, nil, time.Now())
	if err != nil || len(diff.Added) != 1 {
		t.Fatalf("seed hostname: %+v %v", diff, err)
	}
	hostID := diff.Added[0].ID
	triggerStore := st.(store.ScanTriggerStore)
	trigger := store.NewScanTrigger(store.ScanTriggerTemplates, "v10.5.0", []string{"http/new.yaml"}, nil)
	if err := triggerStore.PutScanTrigger(ctx, trigger); err != nil {
		t.Fatal(err)
	}
	tpl.up = updater.Update{Version: "v10.5.0"}
	readErr := errors.New("database observations temporarily unavailable")
	e.r.Store = failingObservationTriggerStore{failingObservationStore{st, readErr}, triggerStore}
	if err := e.r.updateAndScan(ctx, 0); !errors.Is(err, readErr) {
		t.Fatalf("fanout swallowed observation read failure: %v", err)
	}
	pendingTriggerCount(t, triggerStore, store.ScanTriggerTemplates, 1)
	job := deltaJob{Kind: KindScanNewTemplates, Templates: []string{"http/new.yaml"}, AssetIDs: []int64{hostID}, Release: "v10.5.0"}
	if err := e.r.runDelta(ctx, job); !errors.Is(err, readErr) {
		t.Fatalf("worker must retry observation read failure: %v", err)
	}
	e.r.Store = st
	if err := st.SaveObservation(ctx, hostID, model.ObservationInput{Check: "http.probe", Data: map[string]any{"status": 200, "url": "https://observed.example.com/"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.r.updateAndScan(ctx, 0); err != nil {
		t.Fatal(err)
	}
	pendingTriggerCount(t, triggerStore, store.ScanTriggerTemplates, 0)
}
