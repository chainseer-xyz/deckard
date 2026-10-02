package engine

import (
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestResolveCheck(t *testing.T) {
	host := model.Asset{Kind: model.KindHostname, Key: "app.home.example.com", Zone: "home.example.com", Source: "cf"}
	disableActive := []config.AssetGroup{{Name: "quiet", Match: config.GroupMatch{Zones: []string{"home.example.com"}},
		Profiles: map[string]config.ProfileOverride{"active": {Enabled: ptr(false)}}}}
	groupInterval := []config.AssetGroup{{Name: "g", Match: config.GroupMatch{Zones: []string{"home.example.com"}},
		Profiles: map[string]config.ProfileOverride{"active": {Interval: ptr(time.Hour)}}}}

	tests := []struct {
		name        string
		groups      []config.AssetGroup
		checks      map[string]map[string]any
		tier        model.Tier
		intrOnInv   bool // set intrusive.on_inventory_change in config
		chk         string
		wantEnabled bool
		wantIv      time.Duration
		wantOnNew   bool
	}{
		{"no override follows tier (active now scans on new)", nil, nil, model.TierActive, false, "c.a", true, 6 * time.Hour, true},
		{"interval shortens", nil, map[string]map[string]any{"c.a": {"interval": "10m"}}, model.TierActive, false, "c.a", true, 10 * time.Minute, true},
		{"interval lengthens", nil, map[string]map[string]any{"c.a": {"interval": "72h"}}, model.TierActive, false, "c.a", true, 72 * time.Hour, true},
		{"override is per check", nil, map[string]map[string]any{"c.other": {"interval": "1m"}}, model.TierActive, false, "c.a", true, 6 * time.Hour, true},
		{"override beats group interval", groupInterval, map[string]map[string]any{"c.a": {"interval": "15m"}}, model.TierActive, false, "c.a", true, 15 * time.Minute, true},
		{"group interval used without override", groupInterval, nil, model.TierActive, false, "c.a", true, time.Hour, true},
		{"on_new_asset false narrows", nil, map[string]map[string]any{"c.a": {"on_new_asset": false}}, model.TierActive, false, "c.a", true, 6 * time.Hour, false},
		{"duration typed value", nil, map[string]map[string]any{"c.a": {"interval": 20 * time.Minute}}, model.TierPassive, false, "c.a", true, 20 * time.Minute, true},
		{"invalid interval ignored", nil, map[string]map[string]any{"c.a": {"interval": "soon"}}, model.TierActive, false, "c.a", true, 6 * time.Hour, true},
		{"interval never enables group-disabled tier", disableActive, map[string]map[string]any{"c.a": {"interval": "1m", "on_new_asset": true}}, model.TierActive, false, "c.a", false, time.Minute, true},
		{"interval never enables intrusive", nil, map[string]map[string]any{"c.a": {"interval": "1m"}}, model.TierIntrusive, false, "c.a", false, time.Minute, false},
		{"intrusive never on inventory change even if configured", nil, map[string]map[string]any{"c.a": {"on_new_asset": true}}, model.TierIntrusive, true, "c.a", false, 24 * time.Hour, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg()
			cfg.Profiles.Active.OnInventoryChange = true
			cfg.Profiles.Intrusive.OnInventoryChange = tc.intrOnInv
			cfg.AssetGroups = tc.groups
			cfg.Checks = tc.checks
			got := ResolveCheck(cfg, host, tc.tier, tc.chk)
			if got.Enabled != tc.wantEnabled || got.Interval != tc.wantIv || got.OnInventoryChange != tc.wantOnNew {
				t.Fatalf("got enabled=%v iv=%v onNew=%v; want %v %v %v", got.Enabled, got.Interval, got.OnInventoryChange,
					tc.wantEnabled, tc.wantIv, tc.wantOnNew)
			}
		})
	}
}

func TestResolveCheckOnNewAssetCannotWidenTier(t *testing.T) {
	cfg := baseCfg() // active.on_inventory_change = false
	cfg.Checks = map[string]map[string]any{"c.a": {"on_new_asset": true}}
	got := ResolveCheck(cfg, model.Asset{Kind: model.KindHostname, Key: "a.b"}, model.TierActive, "c.a")
	if got.OnInventoryChange {
		t.Fatal("check on_new_asset=true must not override tier on_inventory_change=false")
	}
}
