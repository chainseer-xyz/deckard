package registry

import (
	"context"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

type stub struct {
	name string
	tier model.Tier
}

func (s stub) Name() string             { return s.name }
func (s stub) Tier() model.Tier         { return s.tier }
func (s stub) Applies(model.Asset) bool { return true }
func (s stub) Run(context.Context, check.Target) (*check.Result, error) {
	return &check.Result{}, nil
}

func TestRegistry(t *testing.T) {
	r := New()
	for _, c := range []stub{{"b", model.TierPassive}, {"a", model.TierActive}, {"c", model.TierPassive}} {
		if err := r.Register(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Register(stub{"a", model.TierActive}); err == nil {
		t.Error("duplicate must fail")
	}
	if err := r.Register(stub{"", model.TierActive}); err == nil {
		t.Error("empty name must fail")
	}
	if err := r.Register(stub{"x", "bogus"}); err == nil {
		t.Error("bad tier must fail")
	}
	all := r.All()
	if len(all) != 3 || all[0].Name() != "a" || all[2].Name() != "c" {
		t.Errorf("All not sorted: %v", all)
	}
	if _, ok := r.ByName("b"); !ok {
		t.Error("ByName b")
	}
	if _, ok := r.ByName("zz"); ok {
		t.Error("ByName zz")
	}
	if p := r.ForTier(model.TierPassive); len(p) != 2 || p[0].Name() != "b" {
		t.Errorf("ForTier: %v", p)
	}
}
