package engine

import (
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func ptr[T any](v T) *T { return &v }

func baseCfg() config.Config {
	return config.Config{Profiles: config.Profiles{
		Passive:   config.Profile{Enabled: true, Interval: 5 * time.Minute, OnInventoryChange: true, RateLimit: "100/s", PerHostConcurrency: 4},
		Active:    config.Profile{Enabled: true, Interval: 6 * time.Hour, RateLimit: "50/s", PerHostConcurrency: 2},
		Intrusive: config.Profile{Enabled: false, Interval: 24 * time.Hour, RateLimit: "10/s", PerHostConcurrency: 1},
	}}
}

func TestResolveProfile(t *testing.T) {
	host := model.Asset{Kind: model.KindHostname, Key: "app.home.example.com", Zone: "home.example.com", Source: "cf"}
	ip := model.Asset{Kind: model.KindIP, Key: "203.0.113.7", Source: "static"}
	svc := model.Asset{Kind: model.KindService, Key: "203.0.113.7:443/tcp", Source: "static"}
	url := model.Asset{Kind: model.KindURL, Key: "https://app.example.com/x", Source: "cf", Zone: "example.com"}

	grp := func(name string, m config.GroupMatch, p map[string]config.ProfileOverride) config.AssetGroup {
		return config.AssetGroup{Name: name, Match: m, Profiles: p}
	}
	tests := []struct {
		name   string
		groups []config.AssetGroup
		asset  model.Asset
		tier   model.Tier
		want   Resolved
	}{
		{"global passive", nil, host, model.TierPassive,
			Resolved{true, 5 * time.Minute, 100, 4, true}},
		{"global active", nil, host, model.TierActive,
			Resolved{true, 6 * time.Hour, 50, 2, false}},
		{"intrusive off by default", nil, host, model.TierIntrusive,
			Resolved{false, 24 * time.Hour, 10, 1, false}},
		{"unknown tier disabled", nil, host, model.Tier("bogus"), Resolved{Enabled: false}},
		{"group enables intrusive for its zone only",
			[]config.AssetGroup{grp("lab", config.GroupMatch{Zones: []string{"home.example.com"}},
				map[string]config.ProfileOverride{"intrusive": {Enabled: ptr(true)}})},
			host, model.TierIntrusive, Resolved{true, 24 * time.Hour, 10, 1, false}},
		{"group does not leak to other zone",
			[]config.AssetGroup{grp("lab", config.GroupMatch{Zones: []string{"home.example.com"}},
				map[string]config.ProfileOverride{"intrusive": {Enabled: ptr(true)}})},
			url, model.TierIntrusive, Resolved{false, 24 * time.Hour, 10, 1, false}},
		{"group interval override without enabled does not enable intrusive",
			[]config.AssetGroup{grp("lab", config.GroupMatch{Zones: []string{"home.example.com"}},
				map[string]config.ProfileOverride{"intrusive": {Interval: ptr(time.Hour)}})},
			host, model.TierIntrusive, Resolved{false, time.Hour, 10, 1, false}},
		{"later group wins on conflicting field",
			[]config.AssetGroup{
				grp("a", config.GroupMatch{Zones: []string{"home.example.com"}}, map[string]config.ProfileOverride{"active": {Interval: ptr(time.Hour), RateLimit: ptr("5/s")}}),
				grp("b", config.GroupMatch{Sources: []string{"cf"}}, map[string]config.ProfileOverride{"active": {Interval: ptr(2 * time.Hour)}}),
			}, host, model.TierActive, Resolved{true, 2 * time.Hour, 5, 2, false}},
		{"later group can disable what earlier enabled",
			[]config.AssetGroup{
				grp("a", config.GroupMatch{Zones: []string{"home.example.com"}}, map[string]config.ProfileOverride{"intrusive": {Enabled: ptr(true)}}),
				grp("b", config.GroupMatch{Hostnames: []string{"app.*"}}, map[string]config.ProfileOverride{"intrusive": {Enabled: ptr(false)}}),
			}, host, model.TierIntrusive, Resolved{false, 24 * time.Hour, 10, 1, false}},
		{"AND across criteria: zone matches, source does not",
			[]config.AssetGroup{grp("x", config.GroupMatch{Zones: []string{"home.example.com"}, Sources: []string{"r53"}},
				map[string]config.ProfileOverride{"active": {Interval: ptr(time.Minute)}})},
			host, model.TierActive, Resolved{true, 6 * time.Hour, 50, 2, false}},
		{"OR within criterion",
			[]config.AssetGroup{grp("x", config.GroupMatch{Sources: []string{"r53", "cf"}},
				map[string]config.ProfileOverride{"active": {PerHostConcurrency: ptr(9)}})},
			host, model.TierActive, Resolved{true, 6 * time.Hour, 50, 9, false}},
		{"empty match matches nothing",
			[]config.AssetGroup{grp("x", config.GroupMatch{},
				map[string]config.ProfileOverride{"intrusive": {Enabled: ptr(true)}})},
			host, model.TierIntrusive, Resolved{false, 24 * time.Hour, 10, 1, false}},
		{"cidr matches ip",
			[]config.AssetGroup{grp("net", config.GroupMatch{CIDRs: []string{"203.0.113.0/24"}},
				map[string]config.ProfileOverride{"active": {Interval: ptr(time.Hour)}})},
			ip, model.TierActive, Resolved{true, time.Hour, 50, 2, false}},
		{"cidr matches service ip:port",
			[]config.AssetGroup{grp("net", config.GroupMatch{CIDRs: []string{"203.0.113.0/24"}},
				map[string]config.ProfileOverride{"active": {Interval: ptr(time.Hour)}})},
			svc, model.TierActive, Resolved{true, time.Hour, 50, 2, false}},
		{"cidr does not match hostname",
			[]config.AssetGroup{grp("net", config.GroupMatch{CIDRs: []string{"203.0.113.0/24"}},
				map[string]config.ProfileOverride{"active": {Interval: ptr(time.Hour)}})},
			host, model.TierActive, Resolved{true, 6 * time.Hour, 50, 2, false}},
		{"hostname glob matches url host",
			[]config.AssetGroup{grp("g", config.GroupMatch{Hostnames: []string{"*.example.com"}},
				map[string]config.ProfileOverride{"passive": {Interval: ptr(time.Minute)}})},
			url, model.TierPassive, Resolved{true, time.Minute, 100, 4, true}},
		{"override for other tier ignored",
			[]config.AssetGroup{grp("g", config.GroupMatch{Zones: []string{"home.example.com"}},
				map[string]config.ProfileOverride{"active": {Interval: ptr(time.Minute)}})},
			host, model.TierPassive, Resolved{true, 5 * time.Minute, 100, 4, true}},
		{"bad rate string keeps previous rate",
			[]config.AssetGroup{grp("g", config.GroupMatch{Zones: []string{"home.example.com"}},
				map[string]config.ProfileOverride{"active": {RateLimit: ptr("garbage")}})},
			host, model.TierActive, Resolved{true, 6 * time.Hour, 50, 2, false}},
		{"concurrency floor of one",
			[]config.AssetGroup{grp("g", config.GroupMatch{Zones: []string{"home.example.com"}},
				map[string]config.ProfileOverride{"active": {PerHostConcurrency: ptr(0)}})},
			host, model.TierActive, Resolved{true, 6 * time.Hour, 50, 1, false}},
		{"empty rate means unlimited",
			[]config.AssetGroup{grp("g", config.GroupMatch{Zones: []string{"home.example.com"}},
				map[string]config.ProfileOverride{"active": {RateLimit: ptr("")}})},
			host, model.TierActive, Resolved{true, 6 * time.Hour, 0, 2, false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg()
			cfg.AssetGroups = tc.groups
			got := ResolveProfile(cfg, tc.asset, tc.tier)
			if got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestResolveProfileZeroConfigDisablesEverything(t *testing.T) {
	for _, tier := range []model.Tier{model.TierPassive, model.TierActive, model.TierIntrusive} {
		if r := ResolveProfile(config.Config{}, model.Asset{Kind: model.KindHostname, Key: "a.b"}, tier); r.Enabled {
			t.Fatalf("%s enabled with zero config", tier)
		}
	}
}

func TestZoneMatchFallsBackToSuffix(t *testing.T) {
	cfg := baseCfg()
	cfg.AssetGroups = []config.AssetGroup{{Name: "g", Match: config.GroupMatch{Zones: []string{"Example.COM."}},
		Profiles: map[string]config.ProfileOverride{"active": {Interval: ptr(time.Minute)}}}}
	for key, want := range map[string]time.Duration{
		"a.example.com": time.Minute, "example.com": time.Minute, "notexample.com": 6 * time.Hour,
	} {
		got := ResolveProfile(cfg, model.Asset{Kind: model.KindHostname, Key: key}, model.TierActive)
		if got.Interval != want {
			t.Errorf("%s: interval %v want %v", key, got.Interval, want)
		}
	}
}
