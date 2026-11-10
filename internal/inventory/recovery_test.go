package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestCompleteMetadataRetirementKeepsFindingsVisible(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	svc := inventory.New(st, &fakeCls{}, quiet)
	now := time.Now().UTC()
	image := "sha256:" + strings.Repeat("a", 64)
	pkg := "pkg:golang/example.com/lib@v1.0.0"
	src := &fakeSrc{name: "native", typ: "kubernetes", d: &source.Discovery{
		Assets:    []model.AssetInput{{Kind: model.KindWorkload, Key: "pod:old"}, {Kind: model.KindContainerImage, Key: image}, {Kind: model.KindPackage, Key: pkg}},
		Relations: []model.RelationInput{{FromKind: model.KindContainerImage, FromKey: image, ToKind: model.KindPackage, ToKey: pkg, Type: model.RelContains}},
	}}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	pod, err := st.GetAssetByKey(ctx, model.KindWorkload, "pod:old")
	if err != nil {
		t.Fatal(err)
	}
	in := store.IngestInput{Tool: "kubescape", Scope: "posture", Check: model.IngestCheck("kubescape"), Source: model.IngestSource("kubescape"), AssetScope: model.ScopeExternal, ObservedAt: now, Now: now, Digest: "first"}
	for _, key := range []string{"open", "ack", "suppressed"} {
		in.Items = append(in.Items, store.IngestItem{AssetKind: pod.Kind, AssetKey: pod.Key, Finding: model.FindingInput{Key: key, Title: key, Severity: model.SeverityHigh}})
	}
	result, err := st.IngestFindings(ctx, in)
	if err != nil || len(result.Opened) != 3 {
		t.Fatalf("ingest: %+v %v", result, err)
	}
	for _, f := range result.Opened {
		status := model.StatusOpen
		if f.Title == "ack" {
			status = model.StatusAcknowledged
		}
		if f.Title == "suppressed" {
			status = model.StatusSuppressed
		}
		if err := st.ChangeFindingStatus(ctx, f.ID, store.StatusChange{Status: status, Note: "operator decision"}, now); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := st.ReconcileFindings(ctx, store.ReconcileInput{AssetID: pod.ID, Check: model.IngestCheck("tetragon"), Now: now, PartialRun: true,
		Findings: []model.FindingInput{{Key: "incident", Title: "runtime incident", Severity: model.SeverityHigh}}})
	if err != nil || len(runtime.Opened) != 1 {
		t.Fatalf("runtime incident: %+v %v", runtime, err)
	}
	src.d = &source.Discovery{}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	pod, err = st.GetAsset(ctx, pod.ID)
	if err != nil || pod.RemovedAt == nil {
		t.Fatalf("old Pod not retired: %+v %v", pod, err)
	}
	for _, before := range result.Opened {
		after, err := st.GetFinding(ctx, before.ID)
		want := model.StatusOpen
		if before.Title == "ack" {
			want = model.StatusAcknowledged
		}
		if before.Title == "suppressed" {
			want = model.StatusSuppressed
		}
		note := "operator decision"
		if want == model.StatusOpen {
			note = ""
		}
		if err != nil || after.Status != want || after.AssetID != pod.ID || after.ResolvedAt != nil || after.Fingerprint != before.Fingerprint || after.SuppressionNote != note {
			t.Fatalf("metadata retirement changed finding: %+v %v", after, err)
		}
	}
	incident, err := st.GetFinding(ctx, runtime.Opened[0].ID)
	if err != nil || incident.Status != model.StatusOpen || incident.ResolvedAt != nil {
		t.Fatalf("metadata retirement healed runtime incident: %+v %v", incident, err)
	}
	findings, total, err := st.ListFindings(ctx, store.FindingFilter{})
	if err != nil || total != 4 || len(findings) != 4 {
		t.Fatalf("retired metadata findings hidden: %d %+v %v", total, findings, err)
	}
	groups, total, err := st.ListFindingGroups(ctx, store.FindingFilter{GroupBy: "check"})
	if err != nil || total != 2 || len(groups) != 2 || groups[0].Total != 3 || groups[1].Total != 1 {
		t.Fatalf("groups: %+v %v", groups, err)
	}
	stats, err := st.Stats(ctx)
	if err != nil || stats.FindingsBySev["high"] != 2 || stats.FindingsByCheck[in.Check] != 1 || stats.FindingsByCheck[incident.Check] != 1 {
		t.Fatalf("stats: %+v %v", stats, err)
	}
	scopes, err := st.ListIngestScopes(ctx)
	if err != nil || len(scopes) != 1 || scopes[0].Open != 1 {
		t.Fatalf("scope counts: %+v %v", scopes, err)
	}
	for _, kindKey := range []struct {
		kind model.AssetKind
		key  string
	}{{model.KindContainerImage, image}, {model.KindPackage, pkg}} {
		a, err := st.GetAssetByKey(ctx, kindKey.kind, kindKey.key)
		if err != nil || a.RemovedAt != nil {
			t.Fatalf("immutable artifact retired: %+v %v", a, err)
		}
		if a.Kind == model.KindContainerImage {
			edges, err := st.Edges(ctx, a.ID)
			if err != nil || len(edges) != 1 || edges[0].Type != model.RelContains {
				t.Fatalf("immutable contents lost: %+v %v", edges, err)
			}
		}
	}
}

func TestArtifactHistoryDoesNotInflateShrinkGuard(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	svc := inventory.New(st, &fakeCls{}, quiet)
	src := &fakeSrc{name: "native", typ: "kubernetes", d: &source.Discovery{}}
	for i := range 30 {
		src.d.Assets = append(src.d.Assets, model.AssetInput{Kind: model.KindContainerImage, Key: fmt.Sprintf("sha256:%064x", i)})
	}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	src.d = &source.Discovery{}
	if diff, err := svc.Sync(ctx, src); err != nil || len(diff.Removed) != 0 {
		t.Fatalf("additive history blocked complete sync: %+v %v", diff, err)
	}
}

func TestAcceptShrinkRequiresCompleteDiscoveryAndDoesNotChangeScheduledGuard(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	svc := inventory.New(st, &fakeCls{}, quiet)
	current := model.AssetInput{Kind: model.KindWorkload, Key: "pod:current", Attrs: map[string]any{"uid": "current"}}
	shared := model.AssetInput{Kind: model.KindWorkload, Key: "pod:shared", Attrs: map[string]any{"owner": "native"}}
	src := &fakeSrc{name: "native", typ: "kubernetes", d: &source.Discovery{Assets: []model.AssetInput{current, shared}}}
	for i := range 30 {
		src.d.Assets = append(src.d.Assets, model.AssetInput{Kind: model.KindWorkload, Key: fmt.Sprintf("pod:old:%d", i)})
	}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	before, err := st.GetAssetByKey(ctx, current.Kind, current.Key)
	if err != nil {
		t.Fatal(err)
	}
	shared.Attrs = map[string]any{"owner": "other"}
	other := &fakeSrc{name: "other", typ: "kubernetes", d: &source.Discovery{Assets: []model.AssetInput{shared}}}
	if _, err := svc.Sync(ctx, other); err != nil {
		t.Fatal(err)
	}
	sharedBefore, err := st.GetAssetByKey(ctx, shared.Kind, shared.Key)
	if err != nil {
		t.Fatal(err)
	}

	// A true API gap retains absent Pod generations. An explicit recovery
	// cannot reinterpret that gap as evidence of disappearance or write additions.
	src.d = &source.Discovery{Partial: true, PartialReasons: []string{"pod list failed"}, Assets: []model.AssetInput{current, {Kind: model.KindWorkload, Key: "pod:new-partial"}}}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	src.d.Assets = append(src.d.Assets, model.AssetInput{Kind: model.KindWorkload, Key: "pod:refused"})
	if diff, err := svc.SyncWithOptions(ctx, src, inventory.SyncOptions{AcceptShrink: true}); err == nil || !diff.Empty() {
		t.Fatalf("partial recovery: %+v %v", diff, err)
	}
	if _, err := st.GetAssetByKey(ctx, model.KindWorkload, "pod:refused"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("partial recovery wrote additions: %v", err)
	}
	src.err = errors.New("API unavailable")
	if diff, err := svc.SyncWithOptions(ctx, src, inventory.SyncOptions{AcceptShrink: true}); err == nil || !diff.Empty() {
		t.Fatalf("failed recovery: %+v %v", diff, err)
	}
	src.err = nil
	src.d = &source.Discovery{Assets: []model.AssetInput{current}}
	if _, err := svc.Sync(ctx, src); !errors.Is(err, inventory.ErrSuspiciousShrink) {
		t.Fatalf("normal shrink guard: %v", err)
	}
	if diff, err := svc.SyncWithOptions(ctx, src, inventory.SyncOptions{AcceptShrink: true}); err != nil || len(diff.Removed) != 31 {
		t.Fatalf("complete recovery: %+v %v", diff, err)
	}
	after, err := st.GetAsset(ctx, before.ID)
	if err != nil || after.RemovedAt != nil || after.Key != before.Key {
		t.Fatalf("current identity changed: %+v %v", after, err)
	}
	retained, err := st.GetAsset(ctx, sharedBefore.ID)
	if err != nil || retained.RemovedAt != nil || retained.Source != "other" || len(retained.Reporters) != 1 || retained.SourceFacts["other"].Attrs["owner"] != "other" {
		t.Fatalf("other source facts lost: %+v %v", retained, err)
	}

	// The one-shot option is not persistent configuration. A later ordinary
	// scheduled sync still refuses a fresh suspicious shrink.
	for i := range 30 {
		src.d.Assets = append(src.d.Assets, model.AssetInput{Kind: model.KindWorkload, Key: fmt.Sprintf("pod:next:%d", i)})
	}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	src.d = &source.Discovery{Assets: []model.AssetInput{current}}
	if _, err := svc.Sync(ctx, src); !errors.Is(err, inventory.ErrSuspiciousShrink) {
		t.Fatalf("operator invocation disabled scheduled guard: %v", err)
	}
}
