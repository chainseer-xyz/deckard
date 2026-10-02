package finding_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

var epoch = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func newAsset(t *testing.T, st store.Store, key string) model.Asset {
	t.Helper()
	_, err := st.AddDiscovered(context.Background(), []store.AssetUpsert{{
		AssetInput: model.AssetInput{Kind: model.KindHostname, Key: key, Source: "test", Zone: "example.com"}, Scope: model.ScopeOwned,
	}}, nil, epoch)
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.GetAssetByKey(context.Background(), model.KindHostname, key)
	if err != nil {
		t.Fatal(err)
	}
	return *a
}

func ports(p ...int) map[string]any {
	ps := make([]any, len(p))
	for i, x := range p {
		ps[i] = x
	}
	return map[string]any{"open_ports": ps, "rtt_ms": 1}
}

func portRes(p ...int) *check.Result {
	return &check.Result{Observations: []model.ObservationInput{{Check: "net.ports", Data: ports(p...)}}}
}

func titles(fs []model.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}

func TestProcessDriftLifecycle(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "www.example.com")
	clk := &clock{epoch}
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1, StableAfter: 2}, quiet, finding.WithClock(clk.now))

	step := func(r *check.Result) store.ReconcileResult {
		t.Helper()
		clk.advance(time.Minute)
		out, err := p.Process(ctx, a, "net.ports", r)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	for i := 0; i < 2; i++ {
		if r := step(portRes(80)); len(r.Opened)+len(r.Updated) != 0 {
			t.Fatalf("no findings while learning: %+v", r)
		}
	}
	bl, _ := st.GetBaseline(ctx, a.ID, "net.ports")
	if !bl.Stable {
		t.Fatalf("baseline should be stable: %+v", bl)
	}
	obs, _ := st.LatestObservations(ctx, a.ID)
	if len(obs) != 1 || obs[0].Check != "net.ports" {
		t.Fatalf("observation not saved: %+v", obs)
	}

	r := step(portRes(80, 22))
	if len(r.Opened) != 1 || r.Opened[0].Check != "drift.net.ports" || r.Opened[0].Severity != model.SeverityHigh {
		t.Fatalf("drift must open: %+v", r)
	}
	if r := step(portRes(80, 22)); len(r.Resolved) != 1 {
		// second consecutive run adopts the value: drift finding resolves (resolve_after=1)
		t.Fatalf("adoption must resolve the drift finding: %+v", r)
	}
	bl, _ = st.GetBaseline(ctx, a.ID, "net.ports")
	if bl.Data["open_ports"] == nil || len(bl.Data["open_ports"].([]any)) != 2 {
		t.Fatalf("baseline must have adopted 22: %+v", bl.Data)
	}
}

func TestProcessMergesCheckFindingsAndResolves(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "www.example.com")
	clk := &clock{epoch}
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 2, StableAfter: 3}, quiet, finding.WithClock(clk.now))
	fi := model.FindingInput{Check: "tls.cert", Key: "expiry", Severity: model.SeverityMedium, Title: "Cert expires soon"}

	r, err := p.Process(ctx, a, "tls.cert", &check.Result{Findings: []model.FindingInput{fi}})
	if err != nil || len(r.Opened) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	empty := &check.Result{}
	if r, _ := p.Process(ctx, a, "tls.cert", empty); len(r.Resolved) != 0 {
		t.Fatal("resolve_after=2: first miss must not resolve")
	}
	if r, _ := p.Process(ctx, a, "tls.cert", empty); len(r.Resolved) != 1 {
		t.Fatalf("second miss resolves: %+v", r)
	}
	if _, err := p.Process(ctx, a, "tls.cert", nil); err == nil {
		t.Fatal("nil result must error")
	}
}

func TestProcessConfigSuppression(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "blog.example.com")
	clk := &clock{epoch}
	until := epoch.Add(24 * time.Hour)
	cfg := finding.ProcessorConfig{ResolveAfter: 2, StableAfter: 3, Suppressions: []config.Suppression{
		{Match: "check=http.headers asset=blog.example.com", Reason: "accepted risk", Until: &until},
	}}
	p := finding.NewProcessor(st, cfg, quiet, finding.WithClock(clk.now))
	res := func(keys ...string) *check.Result {
		r := &check.Result{}
		for _, k := range keys {
			r.Findings = append(r.Findings, model.FindingInput{Check: "http.headers", Key: k, Severity: model.SeverityLow, Title: "Missing " + k})
		}
		return r
	}

	r, err := p.Process(ctx, a, "http.headers", res("hsts"))
	if err != nil || len(r.Opened) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	f := r.Opened[0]
	if f.Status != model.StatusSuppressed || !strings.HasPrefix(f.SuppressionNote, finding.ConfigNotePrefix+"accepted risk") || f.SuppressedUntil == nil {
		t.Fatalf("result must show suppressed: %+v", f)
	}
	got, _ := st.GetFinding(ctx, f.ID)
	if got.Status != model.StatusSuppressed || !got.SuppressedUntil.Equal(until) {
		t.Fatalf("stored: %+v", got)
	}

	// Still suppressed across runs (reconcile leaves suppressed alone).
	clk.advance(time.Hour)
	if _, err := p.Process(ctx, a, "http.headers", res("hsts")); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetFinding(ctx, f.ID); got.Status != model.StatusSuppressed {
		t.Fatalf("still suppressed: %+v", got)
	}

	// Lapse: until passes -> returns to open and is NOT re-suppressed.
	clk.t = until.Add(time.Minute)
	if _, err := p.Process(ctx, a, "http.headers", res("hsts")); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetFinding(ctx, f.ID); got.Status != model.StatusOpen {
		t.Fatalf("lapsed suppression must reopen: %+v", got)
	}
	if _, err := p.Process(ctx, a, "http.headers", res("hsts")); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetFinding(ctx, f.ID); got.Status != model.StatusOpen {
		t.Fatalf("must stay open: %+v", got)
	}
}

func TestProcessSuppressionRemovedFromConfigLifts(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "blog.example.com")
	clk := &clock{epoch}
	mk := func(sups ...config.Suppression) *finding.Processor {
		return finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 5, StableAfter: 3, Suppressions: sups}, quiet, finding.WithClock(clk.now))
	}
	res := &check.Result{Findings: []model.FindingInput{{Check: "c", Key: "k", Severity: model.SeverityInfo, Title: "t"}}}
	r, _ := mk(config.Suppression{Match: "check=c", Reason: "x"}).Process(ctx, a, "c", res)
	id := r.Opened[0].ID
	if got, _ := st.GetFinding(ctx, id); got.Status != model.StatusSuppressed {
		t.Fatal("setup")
	}
	// Config reloaded without the rule: next run lifts it.
	if _, err := mk().Process(ctx, a, "c", res); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetFinding(ctx, id); got.Status != model.StatusOpen {
		t.Fatalf("rule removed -> open: %+v", got)
	}
	// A newly added rule suppresses an already-open finding (Updated list).
	r, _ = mk(config.Suppression{Match: "check=c", Reason: "late"}).Process(ctx, a, "c", res)
	if len(r.Updated) != 1 || r.Updated[0].Status != model.StatusSuppressed {
		t.Fatalf("%+v", r)
	}
}

func TestProcessOperatorDecisionsWin(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "blog.example.com")
	clk := &clock{epoch}
	sups := []config.Suppression{{Match: "check=c", Reason: "cfg"}}
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 5, StableAfter: 3, Suppressions: sups}, quiet, finding.WithClock(clk.now))
	pNone := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 5, StableAfter: 3}, quiet, finding.WithClock(clk.now))
	mk := func(k string) *check.Result {
		return &check.Result{Findings: []model.FindingInput{{Check: "c", Key: k, Severity: model.SeverityInfo, Title: k}}}
	}
	// Create three open findings without any rule, then operator acts on them.
	r, _ := pNone.Process(ctx, a, "c", &check.Result{Findings: append(append(mk("ack").Findings, mk("fp").Findings...), mk("opsup").Findings...)})
	byTitle := map[string]int64{}
	for _, f := range r.Opened {
		byTitle[f.Title] = f.ID
	}
	_ = st.ChangeFindingStatus(ctx, byTitle["ack"], store.StatusChange{Status: model.StatusAcknowledged, Actor: "alice"}, clk.now())
	_ = st.ChangeFindingStatus(ctx, byTitle["fp"], store.StatusChange{Status: model.StatusFalsePositive, Actor: "alice"}, clk.now())
	_ = st.ChangeFindingStatus(ctx, byTitle["opsup"], store.StatusChange{Status: model.StatusSuppressed, Note: "ui reason", Actor: "alice"}, clk.now())

	// Now run with a matching config rule.
	all := &check.Result{Findings: append(append(mk("ack").Findings, mk("fp").Findings...), mk("opsup").Findings...)}
	if _, err := p.Process(ctx, a, "c", all); err != nil {
		t.Fatal(err)
	}
	want := map[string]model.FindingStatus{"ack": model.StatusAcknowledged, "fp": model.StatusFalsePositive, "opsup": model.StatusSuppressed}
	for title, st0 := range want {
		got, _ := st.GetFinding(ctx, byTitle[title])
		if got.Status != st0 {
			t.Errorf("%s: status %s want %s", title, got.Status, st0)
		}
	}
	if got, _ := st.GetFinding(ctx, byTitle["opsup"]); got.SuppressionNote != "ui reason" {
		t.Fatalf("operator note overwritten: %q", got.SuppressionNote)
	}
	// An operator (non-config) suppression is not lifted though no rule matches.
	if _, err := pNone.Process(ctx, a, "c", all); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetFinding(ctx, byTitle["opsup"]); got.Status != model.StatusSuppressed {
		t.Fatalf("operator suppression lifted: %+v", got)
	}
}

func TestProcessInvalidSuppressionsMatchNothing(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "a.example.com")
	// An empty match must never become match-everything.
	p := finding.NewProcessor(st, finding.ProcessorConfig{Suppressions: []config.Suppression{{Match: "", Reason: "oops"}}}, nil)
	r, err := p.Process(ctx, a, "c", &check.Result{Findings: []model.FindingInput{{Check: "c", Key: "k", Severity: model.SeverityHigh, Title: "t"}}})
	if err != nil || len(r.Opened) != 1 || r.Opened[0].Status != model.StatusOpen {
		t.Fatalf("%v %+v", err, titles(r.Opened))
	}
}

func TestProcessIgnoreKeysOption(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "a.example.com")
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1, StableAfter: 1}, quiet,
		finding.WithIgnoreKeys(map[string][]string{"http.probe": {"etag"}}))
	run := func(etag string) store.ReconcileResult {
		r, err := p.Process(ctx, a, "http.probe", &check.Result{Observations: []model.ObservationInput{{Check: "http.probe", Data: map[string]any{"status": 200, "etag": etag}}}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	run("a")
	if r := run("b"); len(r.Opened) != 0 {
		t.Fatalf("ignored key must not drift: %+v", r)
	}
}
