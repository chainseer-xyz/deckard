package storetest

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func testRelationReporters(t *testing.T, f Factory) {
	assets := func(source string) []store.AssetUpsert {
		return []store.AssetUpsert{host("a.x.io", source), host("b.x.io", source), host("c.x.io", source)}
	}
	rel := func(to string) model.RelationInput {
		return model.RelationInput{FromKind: model.KindHostname, FromKey: "a.x.io", ToKind: model.KindHostname, ToKey: to, Type: model.RelCNAMETo}
	}
	t.Run("complete snapshots replace relationships between live assets", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", assets("cf"), []model.RelationInput{rel("b.x.io")}, at(0))
		e.snapshot("cf", assets("cf"), []model.RelationInput{rel("c.x.io")}, at(1))
		a := e.asset(model.KindHostname, "a.x.io")
		if got := edgeKeys(e, a.ID); !equalStrings(got, []string{"c.x.io"}) {
			t.Fatalf("stale live relationship: %v", got)
		}
		e.snapshot("cf", assets("cf"), nil, at(2))
		if got := edgeKeys(e, a.ID); len(got) != 0 {
			t.Errorf("empty complete relationship set: %v", got)
		}
	})
	t.Run("partial snapshots retain old relationships", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", assets("cf"), []model.RelationInput{rel("b.x.io")}, at(0))
		if _, err := e.s.UpsertSnapshot(e.ctx, "cf", assets("cf"), []model.RelationInput{rel("c.x.io")}, at(1)); err != nil {
			t.Fatal(err)
		}
		a := e.asset(model.KindHostname, "a.x.io")
		if got := edgeKeys(e, a.ID); !equalStrings(got, sorted("b.x.io", "c.x.io")) {
			t.Errorf("partial snapshot discarded relationships: %v", got)
		}
		e.snapshot("cf", assets("cf"), []model.RelationInput{rel("c.x.io")}, at(2))
		if got := edgeKeys(e, a.ID); !equalStrings(got, []string{"c.x.io"}) {
			t.Errorf("complete snapshot did not retire partial-era relationship: %v", got)
		}
	})
	t.Run("one reporter cannot delete another reporter's relationship", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", assets("cf"), []model.RelationInput{rel("b.x.io")}, at(0))
		e.snapshot("aws", assets("aws"), []model.RelationInput{rel("b.x.io")}, at(1))
		e.snapshot("cf", assets("cf"), nil, at(2))
		a := e.asset(model.KindHostname, "a.x.io")
		if got := edgeKeys(e, a.ID); !equalStrings(got, []string{"b.x.io"}) {
			t.Fatalf("foreign relationship deleted: %v", got)
		}
		e.snapshot("aws", assets("aws"), nil, at(3))
		if got := edgeKeys(e, a.ID); len(got) != 0 {
			t.Errorf("last relationship reporter stopped: %v", got)
		}
	})
	t.Run("derived relationships retire even when children stay live", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", assets("cf"), nil, at(0))
		a, b := e.asset(model.KindHostname, "a.x.io"), e.asset(model.KindHostname, "b.x.io")
		child := []store.AssetUpsert{host("b.x.io", "cf")}
		e.replace(a.ID, "dns.dangling", child, []model.RelationInput{rel("b.x.io")}, at(1))
		e.replace(a.ID, "dns.dangling", nil, nil, at(2))
		if got := edgeKeys(e, a.ID); len(got) != 0 {
			t.Errorf("stale derived relationship on source-owned child: %v", got)
		}
		if got := e.asset(model.KindHostname, b.Key); got.RemovedAt != nil {
			t.Error("source-owned child removed")
		}
	})
	t.Run("removed endpoints never appear in current edges", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", assets("cf"), nil, at(0))
		e.discover(nil, []model.RelationInput{rel("b.x.io")}, at(0))
		a, b := e.asset(model.KindHostname, "a.x.io"), e.asset(model.KindHostname, "b.x.io")
		e.snapshot("cf", assets("cf")[:1], nil, at(1))
		for _, id := range []int64{a.ID, b.ID} {
			if got := edgeKeys(e, id); len(got) != 0 {
				t.Errorf("edges include removed endpoint for %d: %v", id, got)
			}
		}
	})
	t.Run("reviving a parent does not revive stale check relationships", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", assets("cf"), nil, at(0))
		a := e.asset(model.KindHostname, "a.x.io")
		e.replace(a.ID, "dns.dangling", []store.AssetUpsert{host("b.x.io", "cf")}, []model.RelationInput{rel("b.x.io")}, at(1))
		e.snapshot("cf", assets("cf")[1:], nil, at(2))
		e.snapshot("cf", assets("cf"), nil, at(3))
		if got := edgeKeys(e, a.ID); len(got) != 0 {
			t.Errorf("stale check relationships revived with parent: %v", got)
		}
	})
}
