package storetest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Seeder writes one source's complete inventory snapshot into a store under
// test: the given assets are upserted and the source's other assets are
// marked removed. The full suite seeds through ApplySnapshot; RunIngest takes
// a Seeder so stores that do not implement the inventory (the API fakestore)
// can run the ingest contract too.
type Seeder func(t *testing.T, s store.Store, source string, assets []store.AssetUpsert, now time.Time)

// SnapshotSeeder seeds through Store.ApplySnapshot.
func SnapshotSeeder(t *testing.T, s store.Store, source string, assets []store.AssetUpsert, now time.Time) {
	t.Helper()
	if _, err := s.ApplySnapshot(context.Background(), source, assets, nil, now); err != nil {
		t.Fatalf("ApplySnapshot(%s): %v", source, err)
	}
}

// RunIngest runs the ingest contract (IngestFindings, ListIngestScopes)
// against stores built by newStore, seeding inventory with seed.
func RunIngest(t *testing.T, newStore Factory, seed Seeder) {
	testIngest(t, newStore, seed)
}

const (
	ingTool  = "prowler"
	ingScope = "aws:123456789012:us-west-2"
	ingRA    = 2
)

var ingCheck = model.IngestCheck(ingTool)

type ingestEnv struct {
	*env
	seed Seeder
}

func newIngestEnv(t *testing.T, f Factory, seed Seeder) *ingestEnv {
	t.Helper()
	return &ingestEnv{env: newEnv(t, f), seed: seed}
}

// cr is an item on a cloud_resource asset named after its key.
func cr(i int, key string, sev model.Severity) store.IngestItem {
	return store.IngestItem{Index: i, AssetKind: model.KindCloudResource, AssetKey: "arn:aws:s3:::" + key,
		Finding: model.FindingInput{Key: key, Severity: sev, Title: key, Description: "desc " + key}}
}

func ref(i int, kind model.AssetKind, assetKey, key string) store.IngestItem {
	return store.IngestItem{Index: i, AssetKind: kind, AssetKey: assetKey, Ref: true,
		Finding: model.FindingInput{Key: key, Severity: model.SeverityMedium, Title: key}}
}

type ingOpt func(*store.IngestInput)

func incomplete(in *store.IngestInput) { in.Complete = false }
func owned(in *store.IngestInput)      { in.AssetScope = model.ScopeOwned }
func scope(s string) ingOpt            { return func(in *store.IngestInput) { in.Scope = s } }
func digest(d string) ingOpt           { return func(in *store.IngestInput) { in.Digest = d } }
func observed(o time.Time) ingOpt      { return func(in *store.IngestInput) { in.ObservedAt = o } }
func tool(name string) ingOpt          { return func(in *store.IngestInput) { setTool(in, name) } }
func setTool(in *store.IngestInput, n string) {
	in.Tool, in.Check, in.Source = n, model.IngestCheck(n), model.IngestSource(n)
}

// ingest posts one complete run at minute min with a fresh observed_at and
// a digest unique to the call, unless options say otherwise.
func (e *ingestEnv) ingest(min int, items []store.IngestItem, opts ...ingOpt) store.IngestResult {
	e.t.Helper()
	now := at(min)
	in := store.IngestInput{
		Scope: ingScope, AssetScope: model.ScopeExternal, Complete: true,
		ObservedAt: now, Digest: fmt.Sprintf("d-%d-%d", min, len(items)), Items: items, ResolveAfter: ingRA, Now: now,
	}
	setTool(&in, ingTool)
	for _, o := range opts {
		o(&in)
	}
	r, err := e.s.IngestFindings(e.ctx, in)
	if err != nil {
		e.t.Fatalf("IngestFindings: %v", err)
	}
	return r
}

func (e *ingestEnv) ingested(check, scope, key string) *model.Finding {
	e.t.Helper()
	fs, _, err := e.s.ListFindings(e.ctx, store.FindingFilter{Check: check, IncludeRemovedAssets: true})
	if err != nil {
		e.t.Fatalf("ListFindings: %v", err)
	}
	want := model.Fingerprint(check, scope, key)
	for i := range fs {
		if fs[i].Fingerprint == want {
			return &fs[i]
		}
	}
	e.t.Fatalf("no ingested finding %s/%s/%s", check, scope, key)
	return nil
}

func counts(r store.IngestResult) string {
	return fmt.Sprintf("opened=%d reopened=%d updated=%d refreshed=%d pending=%d resolved=%d rejected=%d complete=%v replay=%v",
		len(r.Opened), len(r.Reopened), len(r.Updated), r.Refreshed, r.Pending, len(r.Resolved), len(r.Rejected), r.Complete, r.Replay)
}

func expectCounts(t *testing.T, r store.IngestResult, want string) {
	t.Helper()
	if got := counts(r); got != want {
		t.Fatalf("result\n got %s\nwant %s", got, want)
	}
}

func testIngest(t *testing.T, f Factory, seed Seeder) {
	t.Run("opens findings and creates external non-probable assets", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		r := e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)})
		expectCounts(t, r, "opened=2 reopened=0 updated=0 refreshed=0 pending=0 resolved=0 rejected=0 complete=true replay=false")
		a := e.asset(model.KindCloudResource, "arn:aws:s3:::a")
		if a.Source != "ingest:prowler" || a.Scope != model.ScopeExternal || a.RemovedAt != nil {
			t.Fatalf("asset = %+v", a)
		}
		fd := e.ingested(ingCheck, ingScope, "a")
		if fd.Check != "ext.prowler" || fd.Source != "ingest:prowler" || fd.IngestScope != ingScope ||
			fd.AssetID != a.ID || fd.Status != model.StatusOpen || fd.Severity != model.SeverityHigh {
			t.Fatalf("finding = %+v", fd)
		}
	})

	t.Run("an allow-listed tool creates owned assets and re-asserts the class", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh)}, owned)
		if a := e.asset(model.KindCloudResource, "arn:aws:s3:::a"); a.Scope != model.ScopeOwned {
			t.Fatalf("scope = %s, want owned", a.Scope)
		}
		// The operator removed the allow-listing: the tool's assets follow.
		e.ingest(1, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		if a := e.asset(model.KindCloudResource, "arn:aws:s3:::a"); a.Scope != model.ScopeExternal {
			t.Fatalf("scope = %s, want external", a.Scope)
		}
	})

	t.Run("a complete run resolves absent findings after the usual misses", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)})
		r := e.ingest(1, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		expectCounts(t, r, "opened=0 reopened=0 updated=1 refreshed=1 pending=1 resolved=0 rejected=0 complete=true replay=false")
		if fd := e.ingested(ingCheck, ingScope, "b"); fd.Status != model.StatusOpen || fd.MissedRuns != 1 {
			t.Fatalf("b after one miss = %s missed %d", fd.Status, fd.MissedRuns)
		}
		r = e.ingest(2, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		expectCounts(t, r, "opened=0 reopened=0 updated=1 refreshed=1 pending=0 resolved=1 rejected=0 complete=true replay=false")
		if fd := e.ingested(ingCheck, ingScope, "b"); fd.Status != model.StatusResolved || fd.ResolvedAt == nil {
			t.Fatalf("b = %s", fd.Status)
		}
		// Seen again: reopened, same finding.
		r = e.ingest(3, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)})
		expectCounts(t, r, "opened=0 reopened=1 updated=1 refreshed=2 pending=0 resolved=0 rejected=0 complete=true replay=false")
		if fd := e.ingested(ingCheck, ingScope, "b"); fd.Status != model.StatusOpen || fd.ReopenedCount != 1 || fd.MissedRuns != 0 {
			t.Fatalf("b reopened = %+v", fd)
		}
	})

	t.Run("an empty complete run resolves everything in the scope", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		e.ingest(1, []store.IngestItem{})
		r := e.ingest(2, nil)
		if len(r.Resolved) != 1 || !r.Complete {
			t.Fatalf("result %s", counts(r))
		}
	})

	t.Run("an incomplete run never counts a miss or resolves", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)})
		e.ingest(1, []store.IngestItem{cr(0, "a", model.SeverityHigh)}) // b: one miss
		for i := 2; i < 8; i++ {
			r := e.ingest(i, nil, incomplete)
			expectCounts(t, r, "opened=0 reopened=0 updated=0 refreshed=0 pending=0 resolved=0 rejected=0 complete=false replay=false")
		}
		if fd := e.ingested(ingCheck, ingScope, "a"); fd.Status != model.StatusOpen || fd.MissedRuns != 0 {
			t.Fatalf("a = %s missed %d", fd.Status, fd.MissedRuns)
		}
		if fd := e.ingested(ingCheck, ingScope, "b"); fd.Status != model.StatusOpen || fd.MissedRuns != 1 {
			t.Fatalf("b = %s missed %d, want open with the one earlier miss", fd.Status, fd.MissedRuns)
		}
		// It still opens and refreshes.
		r := e.ingest(9, []store.IngestItem{cr(0, "a", model.SeverityCritical), cr(2, "c", model.SeverityLow)}, incomplete)
		expectCounts(t, r, "opened=1 reopened=0 updated=1 refreshed=1 pending=0 resolved=0 rejected=0 complete=false replay=false")
		if fd := e.ingested(ingCheck, ingScope, "a"); fd.Severity != model.SeverityCritical {
			t.Fatalf("a severity = %s, want refreshed to critical", fd.Severity)
		}
	})

	t.Run("a rejected item turns a complete run into one that cannot resolve", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)})
		for i := 1; i < 5; i++ {
			r := e.ingest(i, []store.IngestItem{cr(0, "a", model.SeverityHigh), ref(1, model.KindHostname, "missing.example.com", "x")})
			if r.Complete || r.NotCompleteReason == "" || len(r.Rejected) != 1 || r.Rejected[0].Index != 1 || r.Rejected[0].Reason == "" {
				t.Fatalf("run %d: %s reason %q rejected %+v", i, counts(r), r.NotCompleteReason, r.Rejected)
			}
			if len(r.Resolved) != 0 || r.Pending != 0 {
				t.Fatalf("run %d resolved or counted misses: %s", i, counts(r))
			}
		}
		if fd := e.ingested(ingCheck, ingScope, "b"); fd.Status != model.StatusOpen || fd.MissedRuns != 0 {
			t.Fatalf("b = %s missed %d", fd.Status, fd.MissedRuns)
		}
	})

	t.Run("a replayed request is a no-op even when complete", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)})
		same := []ingOpt{digest("run-1"), observed(at(1))}
		first := e.ingest(1, []store.IngestItem{cr(0, "a", model.SeverityHigh)}, same...)
		if first.Pending != 1 || first.Replay {
			t.Fatalf("first delivery %s", counts(first))
		}
		before := e.ingested(ingCheck, ingScope, "a").LastSeen
		for i := 2; i < 6; i++ {
			r := e.ingest(i, []store.IngestItem{cr(0, "a", model.SeverityHigh)}, same...)
			expectCounts(t, r, "opened=0 reopened=0 updated=0 refreshed=0 pending=0 resolved=0 rejected=0 complete=false replay=true")
		}
		if fd := e.ingested(ingCheck, ingScope, "b"); fd.Status != model.StatusOpen || fd.MissedRuns != 1 {
			t.Fatalf("replays counted misses: b = %s missed %d", fd.Status, fd.MissedRuns)
		}
		if got := e.ingested(ingCheck, ingScope, "a").LastSeen; !got.Equal(before) {
			t.Fatalf("replay refreshed last_seen %s -> %s", before, got)
		}
	})

	t.Run("a run observed no later than the newest accepted one cannot resolve", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)}, observed(at(10)))
		for i, o := range []time.Time{at(5), at(10)} { // older, then the same run delivered again with other content
			r := e.ingest(i+1, nil, observed(o))
			if r.Complete || r.NotCompleteReason == "" || len(r.Resolved) != 0 || r.Pending != 0 {
				t.Fatalf("observed %s: %s (%q)", o, counts(r), r.NotCompleteReason)
			}
		}
		r := e.ingest(3, nil, observed(at(11)))
		if !r.Complete || r.Pending != 2 {
			t.Fatalf("newer run: %s", counts(r))
		}
	})

	t.Run("scopes and tools are reconciled independently", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh)}, scope("aws:210987654321:eu-west-1"))
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh)}, tool("kubescape"))
		// Same producer key in three sets: three findings (fingerprints differ).
		fs, _, err := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusOpen}})
		if err != nil || len(fs) != 3 {
			t.Fatalf("open findings = %d err %v, want 3", len(fs), err)
		}
		for i := 1; i <= 2; i++ {
			e.ingest(i, nil)
		}
		if fd := e.ingested(ingCheck, ingScope, "a"); fd.Status != model.StatusResolved {
			t.Fatalf("default scope a = %s", fd.Status)
		}
		if fd := e.ingested(ingCheck, "aws:210987654321:eu-west-1", "a"); fd.Status != model.StatusOpen {
			t.Fatalf("other scope a = %s, want untouched", fd.Status)
		}
		if fd := e.ingested("ext.kubescape", ingScope, "a"); fd.Status != model.StatusOpen {
			t.Fatalf("other tool a = %s, want untouched", fd.Status)
		}
	})

	t.Run("a ref attaches to an existing owned asset without changing it", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.seed(t, e.s, "cf", []store.AssetUpsert{
			host("www.example.com", "cf"),
			au(model.KindHostname, "partner.example.net", "cf", model.ScopeExternal, nil),
		}, at(0))
		r := e.ingest(1, []store.IngestItem{
			ref(0, model.KindHostname, "www.example.com", "tls"),
			ref(1, model.KindHostname, "partner.example.net", "tls"),
			ref(2, model.KindIP, "192.0.2.10", "tls"),
		}, incomplete)
		if len(r.Opened) != 1 || len(r.Rejected) != 2 || r.Rejected[0].Index != 1 || r.Rejected[1].Index != 2 {
			t.Fatalf("result %s rejected %+v", counts(r), r.Rejected)
		}
		h := e.asset(model.KindHostname, "www.example.com")
		if h.Source != "cf" || h.Scope != model.ScopeOwned {
			t.Fatalf("referenced asset changed: %+v", h)
		}
		fd := e.ingested(ingCheck, ingScope, "tls")
		if fd.AssetID != h.ID || fd.Source != "ingest:prowler" {
			t.Fatalf("finding asset %d source %q, want %d ingest:prowler", fd.AssetID, fd.Source, h.ID)
		}
		// The source filter matches the finding's own source.
		fs, _, err := e.s.ListFindings(e.ctx, store.FindingFilter{Source: "ingest:prowler"})
		if err != nil || len(fs) != 1 {
			t.Fatalf("source filter: %d err %v", len(fs), err)
		}
		// The asset leaves the inventory: a ref to it is rejected.
		e.seed(t, e.s, "cf", nil, at(2))
		r = e.ingest(3, []store.IngestItem{ref(0, model.KindHostname, "www.example.com", "tls")}, incomplete)
		if len(r.Rejected) != 1 {
			t.Fatalf("ref to removed asset accepted: %+v", r)
		}
	})

	t.Run("a live asset of another source is attached untouched; a removed one is claimed", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.seed(t, e.s, "aws", []store.AssetUpsert{
			au(model.KindCloudResource, "arn:aws:s3:::live", "aws", model.ScopeExternal, map[string]any{"region": "us-west-2"}),
			au(model.KindCloudResource, "arn:aws:s3:::gone", "aws", model.ScopeExternal, nil),
		}, at(0))
		e.seed(t, e.s, "aws", []store.AssetUpsert{
			au(model.KindCloudResource, "arn:aws:s3:::live", "aws", model.ScopeExternal, map[string]any{"region": "us-west-2"}),
		}, at(1))
		e.ingest(2, []store.IngestItem{cr(0, "live", model.SeverityHigh), cr(1, "gone", model.SeverityHigh)})
		if a := e.asset(model.KindCloudResource, "arn:aws:s3:::live"); a.Source != "aws" || a.RemovedAt != nil {
			t.Fatalf("live asset changed: %+v", a)
		}
		g := e.asset(model.KindCloudResource, "arn:aws:s3:::gone")
		if g.Source != "ingest:prowler" || g.RemovedAt != nil {
			t.Fatalf("removed asset not claimed: %+v", g)
		}
		if fd := e.ingested(ingCheck, ingScope, "gone"); fd.Status != model.StatusOpen || fd.AssetID != g.ID {
			t.Fatalf("finding on claimed asset = %+v", fd)
		}
	})

	t.Run("an ingest-created asset survives source snapshots", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		e.seed(t, e.s, "aws", []store.AssetUpsert{au(model.KindCloudResource, "arn:aws:s3:::other", "aws", model.ScopeExternal, nil)}, at(1))
		e.seed(t, e.s, "aws", nil, at(2))
		if a := e.asset(model.KindCloudResource, "arn:aws:s3:::a"); a.RemovedAt != nil {
			t.Fatalf("ingest asset removed by a source snapshot: %+v", a)
		}
		if fd := e.ingested(ingCheck, ingScope, "a"); fd.Status != model.StatusOpen {
			t.Fatalf("finding = %s", fd.Status)
		}
	})

	t.Run("a finding follows its key to a new asset", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		first := e.ingested(ingCheck, ingScope, "a")
		moved := cr(0, "a", model.SeverityHigh)
		moved.AssetKey = "arn:aws:s3:::renamed"
		r := e.ingest(1, []store.IngestItem{moved})
		if len(r.Opened) != 0 || r.Refreshed != 1 {
			t.Fatalf("result %s", counts(r))
		}
		got := e.ingested(ingCheck, ingScope, "a")
		if got.ID != first.ID || got.AssetID == first.AssetID || got.AssetKey != "arn:aws:s3:::renamed" {
			t.Fatalf("finding %+v, first %+v", got, first)
		}
	})

	t.Run("operator statuses survive refreshes and resolution still applies", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)})
		a := e.ingested(ingCheck, ingScope, "a")
		b := e.ingested(ingCheck, ingScope, "b")
		for id, st := range map[int64]model.FindingStatus{a.ID: model.StatusAcknowledged, b.ID: model.StatusSuppressed} {
			if err := e.s.ChangeFindingStatus(e.ctx, id, store.StatusChange{Status: st, Note: "n", Actor: "op"}, at(0)); err != nil {
				t.Fatal(err)
			}
		}
		r := e.ingest(1, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		expectCounts(t, r, "opened=0 reopened=0 updated=0 refreshed=1 pending=1 resolved=0 rejected=0 complete=true replay=false")
		if fd := e.finding(a.ID); fd.Status != model.StatusAcknowledged {
			t.Fatalf("a = %s, want acknowledged kept", fd.Status)
		}
		e.ingest(2, []store.IngestItem{cr(0, "a", model.SeverityHigh)})
		if fd := e.finding(b.ID); fd.Status != model.StatusResolved {
			t.Fatalf("suppressed b = %s, want resolved after misses", fd.Status)
		}
	})

	t.Run("built-in findings on the same asset are never part of the set", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.seed(t, e.s, "cf", []store.AssetUpsert{host("www.example.com", "cf")}, at(0))
		h := e.asset(model.KindHostname, "www.example.com")
		e.reconcile(h.ID, "http.headers", []model.FindingInput{fi("http.headers", "hsts", model.SeverityLow)}, 1, at(0))
		e.ingest(1, []store.IngestItem{ref(0, model.KindHostname, "www.example.com", "hsts")})
		for i := 2; i < 5; i++ {
			e.ingest(i, nil)
		}
		if fd := e.findingByTitle(h.ID, "http.headers", "hsts"); fd.Status != model.StatusOpen || fd.MissedRuns != 0 ||
			fd.Source != "cf" || fd.IngestScope != "" || fd.Fingerprint != model.Fingerprint("http.headers", "www.example.com", "hsts") {
			t.Fatalf("built-in finding = %+v", fd)
		}
		if fd := e.ingested(ingCheck, ingScope, "hsts"); fd.Status != model.StatusResolved {
			t.Fatalf("ingested finding = %s", fd.Status)
		}
		// And a built-in run on the asset leaves the ingested finding alone.
		e.ingest(5, []store.IngestItem{ref(0, model.KindHostname, "www.example.com", "hsts")})
		e.reconcile(h.ID, "http.headers", nil, 1, at(6))
		if fd := e.ingested(ingCheck, ingScope, "hsts"); fd.Status != model.StatusOpen {
			t.Fatalf("built-in run touched the ingested finding: %s", fd.Status)
		}
	})

	t.Run("ListIngestScopes reports freshness and open counts", func(t *testing.T) {
		e := newIngestEnv(t, f, seed)
		e.ingest(0, []store.IngestItem{cr(0, "a", model.SeverityHigh), cr(1, "b", model.SeverityLow)})
		e.ingest(1, []store.IngestItem{cr(0, "a", model.SeverityHigh)}, scope("aws:210987654321:eu-west-1"), incomplete)
		e.ingest(2, nil, tool("gitleaks"), scope("github.com/example"))
		got, err := e.s.ListIngestScopes(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := []store.IngestScope{
			{Tool: "gitleaks", Scope: "github.com/example", CreatedAt: at(2), LastAt: at(2), CompleteAt: at(2), ObservedAt: at(2)},
			{Tool: "prowler", Scope: ingScope, CreatedAt: at(0), LastAt: at(0), CompleteAt: at(0), ObservedAt: at(0), Open: 2},
			{Tool: "prowler", Scope: "aws:210987654321:eu-west-1", CreatedAt: at(1), LastAt: at(1), ObservedAt: at(1), Open: 1},
		}
		if len(got) != len(want) {
			t.Fatalf("scopes = %+v", got)
		}
		for i := range want {
			g, w := got[i], want[i]
			if g.Tool != w.Tool || g.Scope != w.Scope || g.Open != w.Open || !g.CreatedAt.Equal(w.CreatedAt) ||
				!g.LastAt.Equal(w.LastAt) || !g.CompleteAt.Equal(w.CompleteAt) || !g.ObservedAt.Equal(w.ObservedAt) {
				t.Errorf("scope %d = %+v, want %+v", i, g, w)
			}
		}
		// An incomplete run later refreshes last_at but not complete_at.
		e.ingest(3, nil, incomplete)
		got, _ = e.s.ListIngestScopes(e.ctx)
		if g := got[1]; !g.LastAt.Equal(at(3)) || !g.CompleteAt.Equal(at(0)) {
			t.Errorf("after incomplete run: %+v", g)
		}
	})
}
