package engine

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type stubLookup struct{}

func (stubLookup) Query(context.Context, string, uint16) (*dnsx.Response, error) {
	return nil, errors.New("stub")
}

func TestTargetCarriesLookup(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	for _, tc := range []struct {
		name string
		in   check.Lookup
	}{{"configured", stubLookup{}}, {"not available", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			chk := passiveCheck("c.lookup")
			h := newHarness(nil, []model.Asset{a}, chk)
			h.g.classes[a.Key] = model.ScopeOwned
			h.r.Lookup = tc.in
			if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
				t.Fatal(err)
			}
			if len(chk.targets) != 1 || chk.targets[0].Lookup != tc.in {
				t.Fatalf("targets = %+v", chk.targets)
			}
		})
	}
}

// zonesCheck is a fakeCheck that asks for Target.OwnedZones.
type zonesCheck struct{ *fakeCheck }

func (zonesCheck) WantsOwnedZones() bool { return true }

func TestOwnedZonesAreFilledOnlyForChecksThatWantThem(t *testing.T) {
	a := zoneAsset(1, "example.com")
	zones := []model.Asset{
		a, zoneAsset(2, "Example.NET."), zoneAsset(3, "corp.example.com"), zoneAsset(4, "example.net"),
		{ID: 5, Kind: model.KindZone, Key: "partner.example.org", Scope: model.ScopeExternal},
		hostAsset(6, "www.example.com"),
	}
	gone := zoneAsset(7, "removed.example.com")
	now := time.Now()
	gone.RemovedAt = &now

	wants := zonesCheck{passiveCheck("c.wants")}
	plain := passiveCheck("c.plain")
	h := newHarness(nil, append(zones, gone), wants, plain)
	h.g.classes[a.Key] = model.ScopeOwned
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if len(wants.targets) != 1 || len(plain.targets) != 1 {
		t.Fatalf("targets: wants=%d plain=%d", len(wants.targets), len(plain.targets))
	}
	want := []string{"corp.example.com", "example.com", "example.net"}
	if got := wants.targets[0].OwnedZones; !slices.Equal(got, want) {
		t.Errorf("OwnedZones = %v, want %v (owned, live, normalised, de-duplicated zones only)", got, want)
	}
	if plain.targets[0].OwnedZones != nil {
		t.Errorf("a check that did not ask got %v", plain.targets[0].OwnedZones)
	}
}

type failingListStore struct {
	*fakeStore
}

func (failingListStore) ListAssets(context.Context, store.AssetFilter) ([]model.Asset, int, error) {
	return nil, 0, errors.New("db down")
}

func TestOwnedZonesListFailureFailsTheRunInsteadOfRunningBlind(t *testing.T) {
	a := zoneAsset(1, "example.com")
	wants := zonesCheck{passiveCheck("c.wants")}
	h := newHarness(nil, []model.Asset{a}, wants)
	h.g.classes[a.Key] = model.ScopeOwned
	h.r.Store = &failingListStore{h.st}
	_ = h.r.runCheck(context.Background(), wants, a, nil, model.ScopeOwned, nil)
	if len(wants.targets) != 0 {
		t.Fatal("the check ran without the owned zones: it would report the estate's own names as lookalikes")
	}
	h.proc.mu.Lock()
	processed := len(h.proc.calls)
	h.proc.mu.Unlock()
	if processed != 0 {
		t.Error("a failed run was processed")
	}
	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	if len(h.rec.scans) != 1 || h.rec.scans[0].err == nil {
		t.Errorf("the failure was not recorded: %+v", h.rec.scans)
	}
}

// timeoutCheck declares its own deadline (check.DefaultTimeouter).
type timeoutCheck struct {
	*fakeCheck
	d time.Duration
}

func (c timeoutCheck) DefaultTimeout() time.Duration { return c.d }

func TestCheckDefaultTimeout(t *testing.T) {
	r := newRunner(Deps{})
	slow := timeoutCheck{passiveCheck("p.slow"), 30 * time.Minute}
	plain := passiveCheck("p.plain")
	bad := timeoutCheck{passiveCheck("p.bad"), -time.Second}
	if got := r.timeoutFor(slow); got != 30*time.Minute {
		t.Errorf("own default: %v", got)
	}
	if got := r.timeoutFor(plain); got != defaultCheckTimeout {
		t.Errorf("no default: %v", got)
	}
	if got := r.timeoutFor(bad); got != defaultCheckTimeout {
		t.Errorf("non-positive default: %v", got)
	}
	// checks.<name>.timeout still wins.
	r.Config.Checks = map[string]map[string]any{"p.slow": {"timeout": "5m"}}
	if got := r.timeoutFor(slow); got != 5*time.Minute {
		t.Errorf("override: %v", got)
	}
	if got := r.checkTimeout("p.slow"); got != 5*time.Minute {
		t.Errorf("checkTimeout: %v", got)
	}
}
