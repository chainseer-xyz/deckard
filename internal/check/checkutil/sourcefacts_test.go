package checkutil_test

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestBoolAttributeUsesAttributedFacts(t *testing.T) {
	a := model.Asset{Source: "cluster", Reporters: []string{"cluster", "cf"},
		SourceFacts: map[string]model.SourceFact{
			"cluster": {Attrs: map[string]any{"namespace": "web"}},
			"cf":      {Zone: "example.com", Attrs: map[string]any{"proxied": true}},
			"retired": {Attrs: map[string]any{"proxied": false}},
		}}
	if value, source, ok, conflict := checkutil.BoolAttribute(a, "proxied"); !ok || !value || source != "cf" || conflict {
		t.Fatalf("secondary source lost: value=%v source=%q ok=%v", value, source, ok)
	}
	a.SourceFacts["cluster"] = model.SourceFact{Attrs: map[string]any{"proxied": false}}
	if _, _, ok, conflict := checkutil.BoolAttribute(a, "proxied"); ok || !conflict {
		t.Fatal("conflicting source facts must remain unknown")
	}
	if !checkutil.AnyAttributeTrue(a, "proxied") {
		t.Fatal("positive evidence should remain available without overwriting conflicts")
	}
	a.Reporters = []string{"cluster"}
	if checkutil.AnyAttributeTrue(a, "proxied") {
		t.Fatal("withdrawn reporters must not contribute facts")
	}
}

func TestBoolAttributeCanonicalFallback(t *testing.T) {
	a := model.Asset{Source: "cf", Attrs: map[string]any{"proxied": true}, Reporters: []string{"cf", "legacy"}}
	if value, source, ok, conflict := checkutil.BoolAttribute(a, "proxied"); !ok || !value || source != "cf" || conflict {
		t.Fatalf("legacy canonical facts lost: %v %q %v", value, source, ok)
	}
	a.SourceFacts = map[string]model.SourceFact{"cf": {Attrs: map[string]any{}}}
	if _, _, ok, conflict := checkutil.BoolAttribute(a, "proxied"); ok || conflict {
		t.Fatal("known empty facts must not revive obsolete canonical attributes")
	}
	a.SourceFacts = nil
	a.Reporters = []string{"cluster"}
	if _, _, ok, conflict := checkutil.BoolAttribute(a, "proxied"); ok || conflict {
		t.Fatal("a nonmember canonical source must not revive withdrawn facts")
	}
}

func TestAssetZoneIncludesSecondaryFacts(t *testing.T) {
	a := model.Asset{Kind: model.KindHostname, Key: "api.dev.example.com", Source: "cluster",
		Reporters: []string{"cluster", "cf", "route53"}, SourceFacts: map[string]model.SourceFact{
			"cf":      {Zone: "example.com"},
			"route53": {Zone: "dev.example.com"},
			"retired": {Zone: "api.dev.example.com"},
		}}
	if zone := checkutil.AssetZone(a); zone != "dev.example.com" {
		t.Fatalf("zone=%q", zone)
	}
	a.Key = "notexample.com"
	if zone := checkutil.AssetZone(a); zone != "" {
		t.Fatalf("unrelated source zone accepted: %q", zone)
	}
}
