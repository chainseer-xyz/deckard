package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type stubIntel struct{}

func (stubIntel) Get(context.Context, string, string) (intel.Response, error) {
	return intel.Response{}, intel.ErrDisabled
}
func (stubIntel) RDAPBase(context.Context, string) (string, error) { return "", intel.ErrDisabled }

func TestTargetCarriesIntel(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	for _, tc := range []struct {
		name string
		in   check.Intel
	}{{"configured", stubIntel{}}, {"not available", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			chk := passiveCheck("c.intel")
			h := newHarness(nil, []model.Asset{a}, chk)
			h.g.classes[a.Key] = model.ScopeOwned
			h.r.Intel = tc.in
			if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
				t.Fatal(err)
			}
			if len(chk.targets) != 1 || chk.targets[0].Intel != tc.in {
				t.Fatalf("targets = %+v", chk.targets)
			}
		})
	}
}

// slowCheck declares its own cadence (check.DefaultIntervaler).
type slowCheck struct {
	*fakeCheck
	iv time.Duration
}

func (c slowCheck) DefaultInterval() time.Duration { return c.iv }

func TestCheckDefaultInterval(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	slow := slowCheck{passiveCheck("p.slow"), 12 * time.Hour}
	plain := passiveCheck("p.plain")
	schedule := func(checks map[string]map[string]any, ago time.Duration) string {
		h := newHarness(func(c *testCfg) { c.Checks = checks }, []model.Asset{a}, slow, plain)
		for _, n := range []string{"p.slow", "p.plain"} {
			h.st.scans = append(h.st.scans, store.ScanRun{AssetID: 1, Check: n, StartedAt: h.now.Add(-ago)})
		}
		if _, err := h.r.scheduleTier(context.Background(), model.TierPassive); err != nil {
			t.Fatal(err)
		}
		return strings.Join(h.q.keys(), ",")
	}
	// The passive tier runs every 5m; the check's own 12h wins.
	if got := schedule(nil, time.Hour); got != "1|passive|p.plain" {
		t.Errorf("1h ago: queued %q", got)
	}
	if got := schedule(nil, 13*time.Hour); got != "1|passive|p.plain,1|passive|p.slow" && got != "1|passive|p.slow,1|passive|p.plain" {
		t.Errorf("13h ago: queued %q", got)
	}
	// checks.<name>.interval still overrides the check's default.
	if got := schedule(map[string]map[string]any{"p.slow": {"interval": "30m"}}, time.Hour); !strings.Contains(got, "p.slow") {
		t.Errorf("override ignored: queued %q", got)
	}
	cfg := baseCfg()
	if r := resolveFor(cfg, a, model.TierPassive, slow); r.Interval != 12*time.Hour || !r.OnInventoryChange {
		t.Errorf("resolveFor = %+v", r)
	}
}
