package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestScheduleTierPerCheckInterval(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	fast := &fakeCheck{name: "net.fast", tier: model.TierActive}
	slow := &fakeCheck{name: "net.slow", tier: model.TierActive}
	plain := &fakeCheck{name: "net.plain", tier: model.TierActive}
	h := newHarness(func(c *testCfg) {
		c.Checks = map[string]map[string]any{
			"net.fast": {"interval": "10m"}, // shorter than the 6h tier
			"net.slow": {"interval": "48h"}, // longer than the 6h tier
		}
	}, []model.Asset{a}, fast, slow, plain)
	// every check last ran 1h ago: only the 10m override is due.
	for _, n := range []string{"net.fast", "net.slow", "net.plain"} {
		h.st.scans = append(h.st.scans, store.ScanRun{AssetID: 1, Check: n, StartedAt: h.now.Add(-time.Hour)})
	}
	if _, err := h.r.scheduleTier(context.Background(), model.TierActive); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.q.keys(), ","); got != "1|active|net.fast" {
		t.Fatalf("queued %q, want only net.fast", got)
	}
	// 7h ago: plain (6h) is due; slow (48h) is not.
	h2 := newHarness(func(c *testCfg) { c.Checks = map[string]map[string]any{"net.slow": {"interval": "48h"}} },
		[]model.Asset{a}, slow, plain)
	for _, n := range []string{"net.slow", "net.plain"} {
		h2.st.scans = append(h2.st.scans, store.ScanRun{AssetID: 1, Check: n, StartedAt: h2.now.Add(-7 * time.Hour)})
	}
	_, _ = h2.r.scheduleTier(context.Background(), model.TierActive)
	if got := strings.Join(h2.q.keys(), ","); got != "1|active|net.plain" {
		t.Fatalf("queued %q, want only net.plain", got)
	}
}

func TestPerCheckOverrideNeverEnablesDisabledTier(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	intr := &fakeCheck{name: "i.x", tier: model.TierIntrusive}
	h := newHarness(func(c *testCfg) {
		c.Checks = map[string]map[string]any{"i.x": {"interval": "1m", "on_new_asset": true}}
		c.Profiles.Intrusive.OnInventoryChange = true
	}, []model.Asset{a}, intr)
	if n, _ := h.r.scheduleTier(context.Background(), model.TierIntrusive); n != 0 {
		t.Fatal("interval override enabled a disabled tier")
	}
	h.r.enqueueImmediate(context.Background(), []model.Asset{a})
	if len(h.q.keys()) != 0 {
		t.Fatalf("inventory change queued %v for disabled intrusive tier", h.q.keys())
	}
	// Even an explicitly enabled intrusive tier is never triggered by inventory change.
	h.r.Config.Profiles.Intrusive.Enabled = true
	h.r.enqueueImmediate(context.Background(), []model.Asset{a})
	if len(h.q.keys()) != 0 {
		t.Fatalf("intrusive scan queued on inventory change: %v", h.q.keys())
	}
}

func TestEnqueueImmediateActiveTier(t *testing.T) {
	newHost := hostAsset(10, "new.example.com")
	shared := model.Asset{ID: 11, Kind: model.KindHostname, Key: "shared.example.com", Zone: "example.com"}
	act := &fakeCheck{name: "net.x", tier: model.TierActive}
	act2 := &fakeCheck{name: "net.quiet", tier: model.TierActive}
	pas := passiveCheck("dns.x")
	for _, tc := range []struct {
		name string
		cfg  func(*testCfg)
		want string
	}{
		{"active and passive on new asset", func(c *testCfg) { c.Profiles.Active.OnInventoryChange = true },
			"10|active|net.quiet,10|active|net.x,10|passive|dns.x"},
		{"tier flag off", nil, "10|passive|dns.x"},
		{"check opt-out", func(c *testCfg) {
			c.Profiles.Active.OnInventoryChange = true
			c.Checks = map[string]map[string]any{"net.quiet": {"on_new_asset": false}, "dns.x": {"on_new_asset": false}}
		}, "10|active|net.x"},
		{"active tier disabled", func(c *testCfg) {
			c.Profiles.Active.OnInventoryChange = true
			c.Profiles.Active.Enabled = false
		}, "10|passive|dns.x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(tc.cfg, []model.Asset{newHost, shared}, act, act2, pas)
			h.g.classes[shared.Key] = model.ScopeExcluded
			h.r.enqueueImmediate(context.Background(), []model.Asset{newHost, shared})
			if got := strings.Join(h.q.keys(), ","); got != tc.want {
				t.Fatalf("queued %q want %q", got, tc.want)
			}
		})
	}
}
