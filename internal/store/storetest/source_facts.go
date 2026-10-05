package storetest

import (
	"reflect"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func reportedHost(source, zone string, attrs map[string]any) store.AssetUpsert {
	a := au(model.KindHostname, "overlap.example.com", source, model.ScopeOwned, attrs)
	a.Zone = zone
	return a
}

func testSourceFacts(t *testing.T, f Factory) {
	t.Run("overlap retains each authority without merging canonical metadata", func(t *testing.T) {
		e := newEnv(t, f)
		for i, src := range []string{"cf", "k8s", "aws"} {
			d := e.snapshot(src, []store.AssetUpsert{reportedHost(src, src+".example.com", map[string]any{"provider": src})}, nil, at(i))
			if i > 0 && len(d.Changed) != 1 {
				t.Fatalf("new reporter must change provenance: %+v", d)
			}
		}
		a := e.asset(model.KindHostname, "overlap.example.com")
		if a.Source != "cf" || a.Zone != "cf.example.com" || a.Attrs["provider"] != "cf" || !equalStrings(a.Reporters, []string{"aws", "cf", "k8s"}) {
			t.Fatalf("canonical asset/reporters = %+v", a)
		}
		for _, src := range a.Reporters {
			fact, ok := a.SourceFacts[src]
			if !ok || fact.Zone != src+".example.com" || fact.Attrs["provider"] != src {
				t.Errorf("%s fact = %+v, known=%v", src, fact, ok)
			}
			as, total, err := e.s.ListAssets(e.ctx, store.AssetFilter{Source: src})
			if err != nil || total != 1 || len(as) != 1 || as[0].ID != a.ID || !reflect.DeepEqual(as[0].SourceFacts, a.SourceFacts) {
				t.Errorf("source %s list = %+v total=%d err=%v", src, as, total, err)
			}
		}
		st, err := e.s.Stats(e.ctx)
		if err != nil || !reflect.DeepEqual(st.AssetsBySource, map[string]int{"cf": 1}) {
			t.Errorf("canonical source counts = %v err=%v", st.AssetsBySource, err)
		}
	})
	t.Run("secondary facts replace only their writer and identical snapshots are quiet", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{reportedHost("cf", "cf.example.com", map[string]any{"canonical": true})}, nil, at(0))
		e.snapshot("aws", []store.AssetUpsert{reportedHost("aws", "aws.example.com", map[string]any{"a": "1", "b": "2"})}, nil, at(1))
		aws := reportedHost("aws", "new.example.com", map[string]any{"a": "3"})
		if d := e.snapshot("aws", []store.AssetUpsert{aws}, nil, at(2)); len(d.Changed) != 1 {
			t.Fatalf("secondary metadata change = %+v", d)
		}
		a := e.asset(model.KindHostname, aws.Key)
		if a.Attrs["canonical"] != true || !reflect.DeepEqual(a.SourceFacts["aws"], model.SourceFact{Zone: aws.Zone, Attrs: aws.Attrs}) {
			t.Fatalf("secondary replace = %+v", a)
		}
		if d := e.snapshot("aws", []store.AssetUpsert{aws}, nil, at(3)); !d.Empty() {
			t.Errorf("identical secondary snapshot = %+v", d)
		}
		aws.Zone, aws.Attrs = "", nil
		e.snapshot("aws", []store.AssetUpsert{aws}, nil, at(4))
		aws.Attrs = map[string]any{}
		if d := e.snapshot("aws", []store.AssetUpsert{aws}, nil, at(5)); !d.Empty() {
			t.Errorf("nil and empty facts differ: %+v", d)
		}
		if fact, ok := e.asset(model.KindHostname, aws.Key).SourceFacts["aws"]; !ok || fact.Zone != "" || len(fact.Attrs) != 0 {
			t.Errorf("known empty fact = %+v known=%v", fact, ok)
		}
	})
	t.Run("partial omissions retain facts and complete removal projects remaining authority", func(t *testing.T) {
		e := newEnv(t, f)
		for i, src := range []string{"cf", "k8s", "aws"} {
			e.snapshot(src, []store.AssetUpsert{reportedHost(src, src+".example.com", map[string]any{"provider": src})}, nil, at(i))
		}
		if d, err := e.s.UpsertSnapshot(e.ctx, "cf", nil, nil, at(3)); err != nil || !d.Empty() {
			t.Fatalf("partial omission = %+v err=%v", d, err)
		}
		if a := e.asset(model.KindHostname, "overlap.example.com"); len(a.SourceFacts) != 3 || len(a.Reporters) != 3 {
			t.Fatalf("partial omission dropped facts: %+v", a)
		}
		d := e.snapshot("cf", nil, nil, at(4))
		if len(d.Changed) != 1 || len(d.Removed) != 0 {
			t.Fatalf("promotion diff = %+v", d)
		}
		a := e.asset(model.KindHostname, "overlap.example.com")
		if a.Source != "aws" || a.Zone != "aws.example.com" || a.Attrs["provider"] != "aws" || len(a.SourceFacts) != 2 || !equalStrings(a.Reporters, []string{"aws", "k8s"}) {
			t.Fatalf("promotion did not project actual aws facts: %+v", a)
		}
		if d := e.snapshot("k8s", nil, nil, at(5)); len(d.Changed) != 1 || len(d.Removed) != 0 {
			t.Fatalf("secondary reporter removal = %+v", d)
		}
		d = e.snapshot("aws", nil, nil, at(6))
		if len(d.Removed) != 1 || len(d.Removed[0].Reporters) != 0 || len(d.Removed[0].SourceFacts) != 0 {
			t.Fatalf("last removal retains active facts: %+v", d)
		}
	})
	t.Run("derived writers do not modify authority facts", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{reportedHost("cf", "cf.example.com", map[string]any{"authority": "cf"})}, nil, at(0))
		e.discover([]store.AssetUpsert{reportedHost("check:dns", "derived.example.com", map[string]any{"authority": "check"})}, nil, at(1))
		a := e.asset(model.KindHostname, "overlap.example.com")
		if !reflect.DeepEqual(a.SourceFacts, map[string]model.SourceFact{"cf": {Zone: "cf.example.com", Attrs: map[string]any{"authority": "cf"}}}) || !equalStrings(a.Reporters, []string{"cf"}) {
			t.Fatalf("derived writer changed authority facts: %+v", a)
		}
		e.discover([]store.AssetUpsert{svc("overlap.example.com:443", "net.ports", map[string]any{"port": "443"})}, nil, at(2))
		if a := e.asset(model.KindService, "overlap.example.com:443"); len(a.Reporters) != 0 || len(a.SourceFacts) != 0 {
			t.Errorf("derived asset invented source facts: %+v", a)
		}
	})
	t.Run("shared addresses do not collapse different asset identities", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{au(model.KindHostname, "api.example.com", "cf", model.ScopeOwned, map[string]any{"value": "192.0.2.5"})}, nil, at(0))
		e.snapshot("aws", []store.AssetUpsert{
			au(model.KindIP, "192.0.2.5", "aws", model.ScopeOwned, map[string]any{"owned": true}),
			au(model.KindCloudResource, "arn:aws:ec2:us-east-1:123456789012:instance/i-1", "aws", model.ScopeOwned, map[string]any{"public_ip": "192.0.2.5"}),
		}, nil, at(1))
		e.snapshot("k8s", []store.AssetUpsert{au(model.KindIP, "192.0.2.5", "k8s", model.ScopeOwned, map[string]any{"service": "api"})}, nil, at(2))
		assets, total, err := e.s.ListAssets(e.ctx, store.AssetFilter{})
		if err != nil || total != 3 || len(assets) != 3 {
			t.Fatalf("different identities collapsed: %+v total=%d err=%v", assets, total, err)
		}
		ip := e.asset(model.KindIP, "192.0.2.5")
		if !equalStrings(ip.Reporters, []string{"aws", "k8s"}) || len(ip.SourceFacts) != 2 {
			t.Fatalf("same IP identity did not converge: %+v", ip)
		}
	})
	t.Run("retirement and revival discard former reporting facts", func(t *testing.T) {
		e := newEnv(t, f)
		cf := reportedHost("cf", "cf.example.com", map[string]any{"former": true})
		e.snapshot("cf", []store.AssetUpsert{cf}, nil, at(0))
		e.snapshot("aws", []store.AssetUpsert{reportedHost("aws", "aws.example.com", map[string]any{"former_aws": true})}, nil, at(1))
		e.snapshot("cf", nil, nil, at(2))
		e.snapshot("aws", nil, nil, at(3))
		d := e.snapshot("k8s", []store.AssetUpsert{reportedHost("k8s", "k8s.example.com", map[string]any{"service": "api"})}, nil, at(4))
		if len(d.Revived) != 1 || len(d.Revived[0].SourceFacts) != 1 || !equalStrings(d.Revived[0].Reporters, []string{"k8s"}) || d.Revived[0].Source != "k8s" || d.Revived[0].Attrs["service"] != "api" {
			t.Fatalf("revival retained withdrawn metadata: %+v", d)
		}
	})
	t.Run("repeated partial withdrawals update scope and facts without resolving findings", func(t *testing.T) {
		e := newEnv(t, f)
		owned := au(model.KindIP, "198.51.100.7", "aws", model.ScopeOwned, map[string]any{"owned": true})
		e.snapshot("aws", []store.AssetUpsert{owned}, nil, at(0))
		a := e.asset(owned.Kind, owned.Key)
		e.reconcile(a.ID, "intel.internetdb", []model.FindingInput{fi("intel.internetdb", "tag:malware", model.SeverityCritical)}, 1, at(1))
		withdrawn := au(owned.Kind, owned.Key, "aws", model.ScopeShared, map[string]any{"owned": false})
		for i := 2; i < 5; i++ {
			if _, err := e.s.UpsertSnapshot(e.ctx, "aws", []store.AssetUpsert{withdrawn}, nil, at(i)); err != nil {
				t.Fatal(err)
			}
			a = e.asset(owned.Kind, owned.Key)
			if a.Scope != model.ScopeShared || a.SourceFacts["aws"].Attrs["owned"] != false {
				t.Fatalf("partial withdrawal kept unsafe ownership: %+v", a)
			}
			fs, _, err := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: a.ID})
			if err != nil || len(fs) != 1 || fs[0].Status != model.StatusOpen {
				t.Fatalf("partial sync #%d resolved findings: %+v err=%v", i-1, fs, err)
			}
		}
		e.snapshot("aws", []store.AssetUpsert{withdrawn}, nil, at(5))
		fs, _, err := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: a.ID})
		if err != nil || len(fs) != 1 || fs[0].Status != model.StatusResolved {
			t.Fatalf("complete nonowned confirmation did not heal findings: %+v err=%v", fs, err)
		}
	})
	t.Run("secondary fact changes refuse stale finding retirement", func(t *testing.T) {
		e := newEnv(t, f)
		cf := reportedHost("cf", "example.com", map[string]any{"provider": "cf"})
		e.snapshot("cf", []store.AssetUpsert{cf}, nil, at(0))
		a := e.asset(cf.Kind, cf.Key)
		e.reconcile(a.ID, "retired", []model.FindingInput{fi("retired", "k", model.SeverityHigh)}, 1, at(1))
		e.snapshot("aws", []store.AssetUpsert{reportedHost("aws", "example.com", map[string]any{"origin": true})}, nil, at(2))
		if n, err := e.s.ResolveInapplicableFindings(e.ctx, *a, "retired", at(3)); err != nil || n != 0 {
			t.Fatalf("secondary changes permitted stale retirement: n=%d err=%v", n, err)
		}
		a = e.asset(cf.Kind, cf.Key)
		e.snapshot("aws", []store.AssetUpsert{reportedHost("aws", "example.com", map[string]any{"origin": false})}, nil, at(4))
		if n, err := e.s.ResolveInapplicableFindings(e.ctx, *a, "retired", at(5)); err != nil || n != 0 {
			t.Fatalf("changed secondary metadata permitted stale retirement: n=%d err=%v", n, err)
		}
		a = e.asset(cf.Kind, cf.Key)
		e.snapshot("aws", nil, nil, at(6))
		if n, err := e.s.ResolveInapplicableFindings(e.ctx, *a, "retired", at(7)); err != nil || n != 0 {
			t.Fatalf("removed secondary provenance permitted stale retirement: n=%d err=%v", n, err)
		}
		if n, err := e.s.ResolveInapplicableFindings(e.ctx, *e.asset(cf.Kind, cf.Key), "retired", at(8)); err != nil || n != 1 {
			t.Fatalf("fresh provenance refused valid retirement: n=%d err=%v", n, err)
		}
	})
	t.Run("provenance changes emit events without duplicating identical reports", func(t *testing.T) {
		e := newEnv(t, f)
		cf := reportedHost("cf", "cf.example.com", map[string]any{"provider": "cf"})
		aws := reportedHost("aws", "aws.example.com", map[string]any{"provider": "aws"})
		e.snapshot("cf", []store.AssetUpsert{cf}, nil, at(0))
		e.snapshot("aws", []store.AssetUpsert{aws}, nil, at(1))
		aws.Attrs["updated"] = true
		e.snapshot("aws", []store.AssetUpsert{aws}, nil, at(2))
		e.snapshot("aws", []store.AssetUpsert{aws}, nil, at(3))
		e.snapshot("cf", nil, nil, at(4))
		e.snapshot("aws", nil, nil, at(5))
		events, err := e.s.ListEvents(e.ctx, at(0), 0)
		if err != nil || !reflect.DeepEqual(countTypes(events), map[string]int{"asset_added": 1, "asset_changed": 3, "asset_removed": 1}) {
			t.Fatalf("provenance event counts=%v err=%v", countTypes(events), err)
		}
	})
	t.Run("facts survive graph reads without aliasing canonical metadata", func(t *testing.T) {
		e := newEnv(t, f)
		attrs := map[string]any{"nested": map[string]any{"value": "original"}, "list": []any{map[string]any{"value": "original"}}}
		child := reportedHost("cf", "example.com", attrs)
		parent := host("parent.example.com", "cf")
		d := e.snapshot("cf", []store.AssetUpsert{parent, child}, []model.RelationInput{{FromKind: parent.Kind, FromKey: parent.Key, ToKind: child.Kind, ToKey: child.Key, Type: model.RelCNAMETo}}, at(0))
		attrs["nested"].(map[string]any)["value"] = "input mutation"
		a := e.asset(child.Kind, child.Key)
		a.Attrs["nested"].(map[string]any)["value"] = "canonical mutation"
		if got := a.SourceFacts["cf"].Attrs["nested"].(map[string]any)["value"]; got != "original" {
			t.Fatalf("canonical/facts alias: %v", got)
		}
		a.SourceFacts["cf"].Attrs["list"].([]any)[0].(map[string]any)["value"] = "read mutation"
		for _, changed := range d.Added {
			if changed.Key == child.Key {
				changed.SourceFacts["cf"].Attrs["nested"].(map[string]any)["value"] = "diff mutation"
			}
		}
		edges, err := e.s.Edges(e.ctx, e.asset(parent.Kind, parent.Key).ID)
		if err != nil || len(edges) != 1 {
			t.Fatalf("edges=%+v err=%v", edges, err)
		}
		fact := edges[0].Other.SourceFacts["cf"]
		if fact.Attrs["nested"].(map[string]any)["value"] != "original" || fact.Attrs["list"].([]any)[0].(map[string]any)["value"] != "original" {
			t.Fatalf("mutations escaped reads: %+v", fact)
		}
		fact.Attrs["nested"].(map[string]any)["value"] = "edge mutation"
		if a := e.asset(child.Kind, child.Key); a.SourceFacts["cf"].Attrs["nested"].(map[string]any)["value"] != "original" {
			t.Errorf("edge mutation persisted: %+v", a)
		}
	})
}
