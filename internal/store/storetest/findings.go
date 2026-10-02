package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type recStep struct {
	name       string
	findings   []model.FindingInput
	now        time.Time
	opened     int
	reopened   int
	updated    int
	resolved   int
	wantStatus model.FindingStatus
	wantMissed int
	wantReopen int
}

func testReconcile(t *testing.T, f Factory) {
	const check = "dns.dangling"
	k1 := func(sev model.Severity) []model.FindingInput { return []model.FindingInput{fi(check, "k1", sev)} }

	steps := []recStep{
		{"open on first sight", k1(model.SeverityMedium), at(0), 1, 0, 0, 0, model.StatusOpen, 0, 0},
		{"updated when still present", k1(model.SeverityHigh), at(1), 0, 0, 1, 0, model.StatusOpen, 0, 0},
		{"first miss increments MissedRuns", nil, at(2), 0, 0, 0, 0, model.StatusOpen, 1, 0},
		{"seen again resets MissedRuns", k1(model.SeverityHigh), at(3), 0, 0, 1, 0, model.StatusOpen, 0, 0},
		{"miss 1 of 2", nil, at(4), 0, 0, 0, 0, model.StatusOpen, 1, 0},
		{"miss 2 of 2 resolves", nil, at(5), 0, 0, 0, 1, model.StatusResolved, 2, 0},
		{"further misses do nothing", nil, at(6), 0, 0, 0, 0, model.StatusResolved, 2, 0},
		{"reappearance reopens", k1(model.SeverityCritical), at(7), 0, 1, 0, 0, model.StatusOpen, 0, 1},
	}
	t.Run("full lifecycle with ResolveAfter=2", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		fp := model.Fingerprint(check, "a.x.io", "k1")
		for _, st := range steps {
			r := e.reconcile(a.ID, check, st.findings, 2, st.now)
			got := [4]int{len(r.Opened), len(r.Reopened), len(r.Updated), len(r.Resolved)}
			want := [4]int{st.opened, st.reopened, st.updated, st.resolved}
			if got != want {
				t.Fatalf("%s: opened/reopened/updated/resolved = %v, want %v", st.name, got, want)
			}
			fs, total, err := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: a.ID})
			if err != nil || total != 1 || len(fs) != 1 {
				t.Fatalf("%s: findings = %d/%d, err %v (must dedupe)", st.name, len(fs), total, err)
			}
			fd := fs[0]
			if fd.Status != st.wantStatus || fd.MissedRuns != st.wantMissed || fd.ReopenedCount != st.wantReopen {
				t.Errorf("%s: status/missed/reopened = %s/%d/%d, want %s/%d/%d", st.name,
					fd.Status, fd.MissedRuns, fd.ReopenedCount, st.wantStatus, st.wantMissed, st.wantReopen)
			}
			if fd.Fingerprint != fp || fd.AssetID != a.ID || fd.AssetKey != "a.x.io" || fd.Check != check || fd.Source != "cf" {
				t.Errorf("%s: identity = %+v", st.name, fd)
			}
			if st.wantStatus == model.StatusResolved {
				if fd.ResolvedAt == nil || !fd.ResolvedAt.Equal(at(5)) {
					t.Errorf("%s: ResolvedAt = %v, want %v", st.name, fd.ResolvedAt, at(5))
				}
			} else if fd.ResolvedAt != nil {
				t.Errorf("%s: ResolvedAt = %v, want nil", st.name, fd.ResolvedAt)
			}
			if len(st.findings) > 0 && !fd.LastSeen.Equal(st.now) {
				t.Errorf("%s: LastSeen = %v, want %v", st.name, fd.LastSeen, st.now)
			}
			if !fd.FirstSeen.Equal(at(0)) {
				t.Errorf("%s: FirstSeen = %v, want %v", st.name, fd.FirstSeen, at(0))
			}
		}
		fd := e.findingByTitle(a.ID, check, "k1")
		if fd.Severity != model.SeverityCritical {
			t.Errorf("severity not refreshed on reopen: %s", fd.Severity)
		}
	})

	t.Run("result findings carry transition data", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		in := model.FindingInput{
			Check: check, Key: "k", Severity: model.SeverityHigh, Title: "T", Description: "D",
			Evidence: map[string]any{"cname": "x.s3.amazonaws.com"}, Remediation: "R", Tags: []string{"takeover", "dns"},
		}
		r := e.reconcile(a.ID, check, []model.FindingInput{in}, 1, at(0))
		if len(r.Opened) != 1 {
			t.Fatalf("opened = %d", len(r.Opened))
		}
		o := r.Opened[0]
		if o.ID == 0 || o.Status != model.StatusOpen || o.Title != "T" || o.Description != "D" || o.Remediation != "R" ||
			o.Severity != model.SeverityHigh || o.Evidence["cname"] != "x.s3.amazonaws.com" ||
			len(o.Tags) != 2 || o.AssetKey != "a.x.io" {
			t.Errorf("opened = %+v", o)
		}
		in.Evidence = map[string]any{"cname": "y.s3.amazonaws.com"}
		in.Title = "T2"
		r = e.reconcile(a.ID, check, []model.FindingInput{in}, 1, at(1))
		if len(r.Updated) != 1 || r.Updated[0].Evidence["cname"] != "y.s3.amazonaws.com" || r.Updated[0].Title != "T2" {
			t.Errorf("updated = %+v", r.Updated)
		}
		r = e.reconcile(a.ID, check, nil, 1, at(2))
		if len(r.Resolved) != 1 || r.Resolved[0].Status != model.StatusResolved || r.Resolved[0].ID != o.ID {
			t.Errorf("resolved = %+v", r.Resolved)
		}
	})

	t.Run("ResolveAfter=1 and zero both resolve on first miss", func(t *testing.T) {
		for _, n := range []int{1, 0} {
			e := newEnv(t, f)
			a := e.seedHost("a.x.io", "cf", at(0))
			e.reconcile(a.ID, check, k1(model.SeverityLow), n, at(0))
			r := e.reconcile(a.ID, check, nil, n, at(1))
			if len(r.Resolved) != 1 {
				t.Errorf("ResolveAfter=%d resolved = %d, want 1", n, len(r.Resolved))
			}
		}
	})

	t.Run("dedup and isolation", func(t *testing.T) {
		e := newEnv(t, f)
		e.snapshot("cf", []store.AssetUpsert{host("a.x.io", "cf"), host("b.x.io", "cf")}, nil, at(0))
		a, b := e.asset(model.KindHostname, "a.x.io"), e.asset(model.KindHostname, "b.x.io")
		e.reconcile(a.ID, "c1", []model.FindingInput{fi("c1", "k", model.SeverityLow), fi("c1", "k2", model.SeverityLow)}, 1, at(1))
		e.reconcile(a.ID, "c2", []model.FindingInput{fi("c2", "k", model.SeverityLow)}, 1, at(1))
		e.reconcile(b.ID, "c1", []model.FindingInput{fi("c1", "k", model.SeverityLow)}, 1, at(1))
		_, total, _ := e.s.ListFindings(e.ctx, store.FindingFilter{})
		if total != 4 {
			t.Fatalf("total = %d, want 4 (same key on different check/asset is distinct)", total)
		}
		// Empty run of c1 on a must not touch c2 on a, nor c1 on b.
		r := e.reconcile(a.ID, "c1", nil, 1, at(2))
		if len(r.Resolved) != 2 {
			t.Fatalf("resolved = %d, want 2", len(r.Resolved))
		}
		open, _, _ := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusOpen}})
		if len(open) != 2 {
			t.Errorf("open = %d, want 2", len(open))
		}
		// Duplicate keys in one run collapse.
		e.reconcile(b.ID, "c3", []model.FindingInput{fi("c3", "dup", model.SeverityLow), fi("c3", "dup", model.SeverityHigh)}, 1, at(3))
		fs, _, _ := e.s.ListFindings(e.ctx, store.FindingFilter{AssetID: b.ID, Check: "c3"})
		if len(fs) != 1 {
			t.Errorf("dup findings = %d, want 1", len(fs))
		}
	})

	t.Run("several findings transition independently", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		e.reconcile(a.ID, check, []model.FindingInput{fi(check, "p80", model.SeverityLow), fi(check, "p22", model.SeverityLow)}, 1, at(1))
		r := e.reconcile(a.ID, check, []model.FindingInput{fi(check, "p80", model.SeverityLow), fi(check, "p443", model.SeverityLow)}, 1, at(2))
		if got := titles(r.Opened); !equalStrings(got, []string{"p443"}) {
			t.Errorf("opened = %v", got)
		}
		if got := titles(r.Updated); !equalStrings(got, []string{"p80"}) {
			t.Errorf("updated = %v", got)
		}
		if got := titles(r.Resolved); !equalStrings(got, []string{"p22"}) {
			t.Errorf("resolved = %v", got)
		}
	})

	t.Run("acknowledged absent resolves after misses", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		r := e.reconcile(a.ID, check, k1(model.SeverityLow), 2, at(1))
		if err := e.s.ChangeFindingStatus(e.ctx, r.Opened[0].ID, store.StatusChange{Status: model.StatusAcknowledged, Actor: "me"}, at(2)); err != nil {
			t.Fatal(err)
		}
		e.reconcile(a.ID, check, nil, 2, at(3))
		if got := e.finding(r.Opened[0].ID).Status; got != model.StatusAcknowledged {
			t.Errorf("after 1 miss status = %s", got)
		}
		e.reconcile(a.ID, check, nil, 2, at(4))
		if got := e.finding(r.Opened[0].ID).Status; got != model.StatusResolved {
			t.Errorf("after 2 misses status = %s", got)
		}
	})
}

func testPreservedStatuses(t *testing.T, f Factory) {
	const check = "http.headers"
	for _, st := range []model.FindingStatus{model.StatusAcknowledged, model.StatusSuppressed, model.StatusFalsePositive} {
		t.Run(string(st), func(t *testing.T) {
			e := newEnv(t, f)
			a := e.seedHost("a.x.io", "cf", at(0))
			r := e.reconcile(a.ID, check, []model.FindingInput{fi(check, "k", model.SeverityLow)}, 1, at(1))
			id := r.Opened[0].ID
			if err := e.s.ChangeFindingStatus(e.ctx, id, store.StatusChange{Status: st, Note: "n", Actor: "me"}, at(2)); err != nil {
				t.Fatal(err)
			}

			// Re-observed: not reopened, not duplicated, status kept, LastSeen advances.
			r = e.reconcile(a.ID, check, []model.FindingInput{fi(check, "k", model.SeverityHigh)}, 1, at(3))
			if len(r.Opened)+len(r.Reopened)+len(r.Resolved) != 0 {
				t.Errorf("transitions on re-observation: %+v", r)
			}
			fs, total, _ := e.s.ListFindings(e.ctx, store.FindingFilter{})
			if total != 1 || len(fs) != 1 {
				t.Fatalf("findings = %d, want 1", total)
			}
			got := fs[0]
			if got.Status != st || got.ReopenedCount != 0 || got.ID != id || !got.LastSeen.Equal(at(3)) || got.MissedRuns != 0 {
				t.Errorf("finding = %+v", got)
			}

			// Open-only listing must not include it.
			open, n, _ := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusOpen}})
			if len(open) != 0 || n != 0 {
				t.Errorf("open listing = %d", n)
			}
			// Absent runs count as misses for suppressed/false-positive findings
			// too, so a fixed-but-suppressed issue resolves instead of
			// re-alerting when the suppression expires.
			e.reconcile(a.ID, check, nil, 2, at(4))
			if got := e.finding(id); got.Status != st || got.MissedRuns != 1 {
				t.Errorf("after 1 miss: status=%s misses=%d", got.Status, got.MissedRuns)
			}
			// Reappearing resets the counter.
			e.reconcile(a.ID, check, []model.FindingInput{fi(check, "k", model.SeverityLow)}, 2, at(5))
			if got := e.finding(id); got.Status != st || got.MissedRuns != 0 {
				t.Errorf("after reappearance: status=%s misses=%d", got.Status, got.MissedRuns)
			}
			e.reconcile(a.ID, check, nil, 2, at(6))
			r = e.reconcile(a.ID, check, nil, 2, at(7))
			got = *e.finding(id)
			if len(r.Resolved) != 1 || got.Status != model.StatusResolved || !got.ResolvedAt.Equal(at(7)) {
				t.Errorf("after 2 misses: status=%s resolved=%d", got.Status, len(r.Resolved))
			}
			if got.SuppressionNote != "n" {
				t.Errorf("suppression note lost on resolve: %q", got.SuppressionNote)
			}
		})
	}
}

func testFindingStatus(t *testing.T, f Factory) {
	const check = "tls.cert"
	t.Run("suppress with until then reopen to open", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		r := e.reconcile(a.ID, check, []model.FindingInput{fi(check, "k", model.SeverityLow)}, 1, at(0))
		id := r.Opened[0].ID
		until := at(60)
		err := e.s.ChangeFindingStatus(e.ctx, id, store.StatusChange{Status: model.StatusSuppressed, Until: &until, Note: "accepted", Actor: "operator"}, at(1))
		if err != nil {
			t.Fatal(err)
		}
		fd := e.finding(id)
		if fd.Status != model.StatusSuppressed || fd.SuppressedUntil == nil || !fd.SuppressedUntil.Equal(until) || fd.SuppressionNote != "accepted" {
			t.Errorf("finding = %+v", fd)
		}
		if err := e.s.ChangeFindingStatus(e.ctx, id, store.StatusChange{Status: model.StatusOpen}, at(2)); err != nil {
			t.Fatal(err)
		}
		fd = e.finding(id)
		if fd.Status != model.StatusOpen || fd.SuppressedUntil != nil || fd.SuppressionNote != "" {
			t.Errorf("after reopen = %+v", fd)
		}
	})

	t.Run("indefinite suppression has no until", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		r := e.reconcile(a.ID, check, []model.FindingInput{fi(check, "k", model.SeverityLow)}, 1, at(0))
		if err := e.s.ChangeFindingStatus(e.ctx, r.Opened[0].ID, store.StatusChange{Status: model.StatusFalsePositive, Note: "fp"}, at(1)); err != nil {
			t.Fatal(err)
		}
		fd := e.finding(r.Opened[0].ID)
		if fd.Status != model.StatusFalsePositive || fd.SuppressedUntil != nil || fd.SuppressionNote != "fp" {
			t.Errorf("finding = %+v", fd)
		}
	})

	t.Run("ExpireSuppressions returns expired to open", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		var fs []model.FindingInput
		for _, k := range []string{"sup-past", "ack-past", "sup-future", "sup-forever", "fp", "open"} {
			fs = append(fs, fi(check, k, model.SeverityLow))
		}
		e.reconcile(a.ID, check, fs, 1, at(0))
		id := func(k string) int64 { return e.findingByTitle(a.ID, check, k).ID }
		past, future := at(10), at(100)
		set := func(k string, c store.StatusChange) {
			t.Helper()
			if err := e.s.ChangeFindingStatus(e.ctx, id(k), c, at(1)); err != nil {
				t.Fatal(err)
			}
		}
		set("sup-past", store.StatusChange{Status: model.StatusSuppressed, Until: &past, Note: "n"})
		set("ack-past", store.StatusChange{Status: model.StatusAcknowledged, Until: &past})
		set("sup-future", store.StatusChange{Status: model.StatusSuppressed, Until: &future})
		set("sup-forever", store.StatusChange{Status: model.StatusSuppressed})
		set("fp", store.StatusChange{Status: model.StatusFalsePositive})

		n, err := e.s.ExpireSuppressions(e.ctx, at(50))
		if err != nil || n != 2 {
			t.Fatalf("ExpireSuppressions = %d, %v; want 2", n, err)
		}
		want := map[string]model.FindingStatus{
			"sup-past": model.StatusOpen, "ack-past": model.StatusOpen, "sup-future": model.StatusSuppressed,
			"sup-forever": model.StatusSuppressed, "fp": model.StatusFalsePositive, "open": model.StatusOpen,
		}
		for k, st := range want {
			if got := e.finding(id(k)); got.Status != st {
				t.Errorf("%s status = %s, want %s", k, got.Status, st)
			}
		}
		if got := e.finding(id("sup-past")); got.SuppressedUntil != nil || got.SuppressionNote != "" {
			t.Errorf("expired finding keeps suppression data: %+v", got)
		}
		if n, _ := e.s.ExpireSuppressions(e.ctx, at(50)); n != 0 {
			t.Errorf("second ExpireSuppressions = %d, want 0", n)
		}
		// Boundary: until == now counts as expired.
		if n, _ := e.s.ExpireSuppressions(e.ctx, future); n != 1 {
			t.Errorf("at boundary = %d, want 1", n)
		}
	})

	t.Run("ResolvedSince", func(t *testing.T) {
		e := newEnv(t, f)
		a := e.seedHost("a.x.io", "cf", at(0))
		e.reconcile(a.ID, check, []model.FindingInput{fi(check, "early", model.SeverityLow), fi(check, "late", model.SeverityLow), fi(check, "still", model.SeverityLow)}, 1, at(0))
		e.reconcile(a.ID, check, []model.FindingInput{fi(check, "late", model.SeverityLow), fi(check, "still", model.SeverityLow)}, 1, at(10))
		e.reconcile(a.ID, check, []model.FindingInput{fi(check, "still", model.SeverityLow)}, 1, at(20))
		cases := []struct {
			since time.Time
			want  []string
		}{
			{at(0), []string{"early", "late"}},
			{at(10), []string{"early", "late"}},
			{at(11), []string{"late"}},
			{at(20), []string{"late"}},
			{at(21), nil},
		}
		for _, c := range cases {
			got, err := e.s.ResolvedSince(e.ctx, c.since)
			if err != nil {
				t.Fatal(err)
			}
			if !equalStrings(titles(got), c.want) {
				t.Errorf("since %v = %v, want %v", c.since, titles(got), c.want)
			}
			for _, fd := range got {
				if fd.Status != model.StatusResolved || fd.ResolvedAt == nil || fd.AssetKey != "a.x.io" {
					t.Errorf("finding = %+v", fd)
				}
			}
		}
	})
}

func testListFindings(t *testing.T, f Factory) {
	seed := func(e *env) (a1, a2 *model.Asset) {
		x := au(model.KindHostname, "a.x.io", "cf", model.ScopeOwned, nil)
		x.Zone = "x.io"
		y := au(model.KindHostname, "b.y.io", "r53", model.ScopeOwned, nil)
		y.Zone = "y.io"
		e.snapshot("cf", []store.AssetUpsert{x}, nil, at(0))
		e.snapshot("r53", []store.AssetUpsert{y}, nil, at(0))
		a1, a2 = e.asset(model.KindHostname, "a.x.io"), e.asset(model.KindHostname, "b.y.io")
		e.reconcile(a1.ID, "c1", []model.FindingInput{fi("c1", "crit", model.SeverityCritical), fi("c1", "low", model.SeverityLow)}, 1, at(1))
		e.reconcile(a1.ID, "c2", []model.FindingInput{fi("c2", "med", model.SeverityMedium)}, 1, at(1))
		e.reconcile(a2.ID, "c1", []model.FindingInput{fi("c1", "high", model.SeverityHigh), fi("c1", "info", model.SeverityInfo)}, 1, at(1))
		// resolve "info"
		e.reconcile(a2.ID, "c1", []model.FindingInput{fi("c1", "high", model.SeverityHigh)}, 1, at(2))
		return a1, a2
	}
	open := []model.FindingStatus{model.StatusOpen}
	cases := []struct {
		name      string
		f         func(a1, a2 *model.Asset) store.FindingFilter
		want      []string
		wantTotal int
	}{
		{"all", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{} }, []string{"crit", "high", "info", "low", "med"}, 5},
		{"open only", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{Statuses: open} }, []string{"crit", "high", "low", "med"}, 4},
		{"resolved only", func(a1, a2 *model.Asset) store.FindingFilter {
			return store.FindingFilter{Statuses: []model.FindingStatus{model.StatusResolved}}
		}, []string{"info"}, 1},
		{"multiple statuses", func(a1, a2 *model.Asset) store.FindingFilter {
			return store.FindingFilter{Statuses: []model.FindingStatus{model.StatusResolved, model.StatusOpen}}
		}, []string{"crit", "high", "info", "low", "med"}, 5},
		{"min severity high", func(a1, a2 *model.Asset) store.FindingFilter {
			return store.FindingFilter{MinSeverity: model.SeverityHigh}
		}, []string{"crit", "high"}, 2},
		{"min severity medium open", func(a1, a2 *model.Asset) store.FindingFilter {
			return store.FindingFilter{MinSeverity: model.SeverityMedium, Statuses: open}
		}, []string{"crit", "high", "med"}, 3},
		{"check", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{Check: "c2"} }, []string{"med"}, 1},
		{"zone", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{Zone: "y.io"} }, []string{"high", "info"}, 2},
		{"source", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{Source: "cf"} }, []string{"crit", "low", "med"}, 3},
		{"asset", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{AssetID: a2.ID} }, []string{"high", "info"}, 2},
		{"query on title", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{Query: "CRI"} }, []string{"crit"}, 1},
		{"query on asset key", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{Query: "b.y.io"} }, []string{"high", "info"}, 2},
		{"no match", func(a1, a2 *model.Asset) store.FindingFilter { return store.FindingFilter{Check: "nope"} }, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, f)
			a1, a2 := seed(e)
			got, total, err := e.s.ListFindings(e.ctx, tc.f(a1, a2))
			if err != nil {
				t.Fatal(err)
			}
			if !equalStrings(titles(got), tc.want) || total != tc.wantTotal {
				t.Errorf("got %v total %d, want %v total %d", titles(got), total, tc.want, tc.wantTotal)
			}
		})
	}

	t.Run("ordered by severity then pagination", func(t *testing.T) {
		e := newEnv(t, f)
		seed(e)
		all, total, err := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: open})
		if err != nil || total != 4 {
			t.Fatal(total, err)
		}
		var order []string
		for _, fd := range all {
			order = append(order, fd.Title)
		}
		if !equalStrings(order, []string{"crit", "high", "med", "low"}) {
			t.Errorf("order = %v, want severity desc", order)
		}
		page, total, _ := e.s.ListFindings(e.ctx, store.FindingFilter{Statuses: open, Limit: 2, Offset: 1})
		if total != 4 || len(page) != 2 || page[0].Title != "high" || page[1].Title != "med" {
			t.Errorf("page = %v total %d", titles(page), total)
		}
	})
}

func testNotFound(t *testing.T, f Factory) {
	const missing = 987654
	cases := []struct {
		name string
		call func(e *env) error
	}{
		{"GetAsset", func(e *env) error { _, err := e.s.GetAsset(e.ctx, missing); return err }},
		{"GetAssetByKey", func(e *env) error { _, err := e.s.GetAssetByKey(e.ctx, model.KindHostname, "nope"); return err }},
		{"GetFinding", func(e *env) error { _, err := e.s.GetFinding(e.ctx, missing); return err }},
		{"GetBaseline", func(e *env) error { _, err := e.s.GetBaseline(e.ctx, missing, "c"); return err }},
		{"ChangeFindingStatus", func(e *env) error {
			return e.s.ChangeFindingStatus(e.ctx, missing, store.StatusChange{Status: model.StatusSuppressed}, at(0))
		}},
		{"ReconcileFindings", func(e *env) error {
			_, err := e.s.ReconcileFindings(e.ctx, store.ReconcileInput{AssetID: missing, Check: "c", ResolveAfter: 1, Now: at(0)})
			return err
		}},
		{"SaveObservation", func(e *env) error {
			return e.s.SaveObservation(e.ctx, missing, model.ObservationInput{Check: "c"}, at(0))
		}},
		{"SaveBaseline", func(e *env) error {
			return e.s.SaveBaseline(e.ctx, store.Baseline{AssetID: missing, Check: "c", UpdatedAt: at(0)})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, f)
			if err := tc.call(e); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		})
	}
}
