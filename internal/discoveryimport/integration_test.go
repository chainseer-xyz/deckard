package discoveryimport

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

type authorityFixture struct{ discovery source.Discovery }

func (*authorityFixture) Name() string { return "cf" }
func (*authorityFixture) Type() string { return "cloudflare" }
func (s *authorityFixture) Discover(context.Context) (*source.Discovery, error) {
	return &s.discovery, nil
}

func importGuard(t *testing.T) *scope.Guard {
	t.Helper()
	g, err := scope.NewGuard(config.ScopeConfig{Exclude: []string{"excluded.example.com"}}, scope.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	g.SetSharedRanges([]netip.Prefix{netip.MustParsePrefix("93.184.216.34/32")})
	return g
}

func TestIntegrationImportPreservesAuthorityScopeAndPartialLifecycle(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	g := importGuard(t)
	inv := inventory.New(st, g, slog.New(slog.NewTextHandler(io.Discard, nil)))
	native := &authorityFixture{discovery: source.Discovery{Zones: []source.Zone{{Name: "example.com"}}, Assets: []model.AssetInput{{Kind: model.KindHostname, Key: "web.example.com", Attrs: map[string]any{"proxied": true}}}}}
	if _, err := inv.Sync(ctx, native); err != nil {
		t.Fatal(err)
	}
	original, err := st.GetAssetByKey(ctx, model.KindHostname, "web.example.com")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(inv, []string{"remote-recon"})
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Join([]string{
		`{"type":"DNS_NAME","data":"web.example.com","attrs":{"proxied":false,"owned":true}}`,
		`{"type":"DNS_NAME","data":"discovered.example.com","tags":["target","in-scope"]}`,
		`{"type":"DNS_NAME","data":"excluded.example.com","scope":"owned"}`,
		`{"type":"DNS_ZONE","data":"attacker.example.net","owned":true}`,
		`{"type":"DNS_NAME","data":"evil.attacker.example.net","zone":"attacker.example.net"}`,
		`{"type":"IP_ADDRESS","data":"93.184.216.34","owned":true,"attrs":{"owned":true}}`,
	}, "\n")
	diff, err := svc.Import(ctx, "remote-recon", []byte(raw))
	if err != nil || len(diff.Added) != 4 || len(diff.Removed) != 0 {
		t.Fatalf("remote import: %+v %v", diff, err)
	}
	for key, want := range map[string]model.ScopeClass{"web.example.com": model.ScopeOwned, "discovered.example.com": model.ScopeOwned, "excluded.example.com": model.ScopeExcluded, "evil.attacker.example.net": model.ScopeExternal} {
		a, err := st.GetAssetByKey(ctx, model.KindHostname, key)
		if err != nil || a.Scope != want {
			t.Fatalf("classification %s: %+v %v", key, a, err)
		}
	}
	web, err := st.GetAssetByKey(ctx, model.KindHostname, "web.example.com")
	if err != nil || web.ID != original.ID || web.Source != "cf" || web.Attrs["proxied"] != true || !slices.Equal(web.Reporters, []string{"cf", "remote-recon"}) || web.SourceFacts["remote-recon"].Attrs["owned"] != nil || web.SourceFacts["remote-recon"].Attrs["proxied"] != nil {
		t.Fatalf("authoritative facts lost or forged: %+v %v", web, err)
	}
	ip, err := st.GetAssetByKey(ctx, model.KindIP, "93.184.216.34")
	if err != nil || ip.Scope != model.ScopeShared || ip.Attrs["owned"] != nil {
		t.Fatalf("BBOT granted IP ownership: %+v %v", ip, err)
	}
	excluded, err := st.GetAssetByKey(ctx, model.KindHostname, "excluded.example.com")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := st.ReconcileFindings(ctx, store.ReconcileInput{AssetID: excluded.ID, Check: "http.exposed", ResolveAfter: 1, Now: time.Now().UTC(), Findings: []model.FindingInput{{Key: "historical", Title: "Historical exposure", Severity: model.SeverityHigh}}})
	if err != nil || len(opened.Opened) != 1 {
		t.Fatalf("finding fixture: %+v %v", opened, err)
	}
	for i := 0; i < 3; i++ {
		if diff, err := svc.Import(ctx, "remote-recon", nil); err != nil || len(diff.Removed) != 0 {
			t.Fatalf("empty event window removed inventory: %+v %v", diff, err)
		}
		f, err := st.GetFinding(ctx, opened.Opened[0].ID)
		if err != nil || f.Status != model.StatusOpen {
			t.Fatalf("partial import healed finding: %+v %v", f, err)
		}
	}
	assets, total, err := st.ListAssets(ctx, store.AssetFilter{Source: "remote-recon"})
	if err != nil || len(assets) != 5 || total != 5 {
		t.Fatalf("partial import lost reporters: total %d len %d %v", total, len(assets), err)
	}
	syncs, err := st.ListSyncs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range syncs {
		if status.Source == "remote-recon" && (status.Type != "bbot" || status.LastOK.IsZero() || status.Error != "" || !strings.Contains(status.Warning, "non-authoritative")) {
			t.Fatalf("partial source health missing: %+v", status)
		}
	}
	freshGuard := importGuard(t)
	if err := inventory.New(st, freshGuard, slog.New(slog.NewTextHandler(io.Discard, nil))).Rehydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if freshGuard.Classify(model.KindIP, ip.Key) != model.ScopeShared || freshGuard.Classify(model.KindHostname, "evil.attacker.example.net") != model.ScopeExternal {
		t.Fatal("restart promoted BBOT observations into authority")
	}
}

func TestIntegrationMalformedImportRecordsHealthWithoutPartialWrites(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	inv := inventory.New(st, importGuard(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc, err := New(inv, []string{"remote-recon"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Import(ctx, "remote-recon", []byte(`{"type":"DNS_NAME","data":"existing.example.com"}`)); err != nil {
		t.Fatal(err)
	}
	raw := []byte("{\"type\":\"DNS_NAME\",\"data\":\"not-written.example.com\"}\n{\"type\":\"IP_ADDRESS\",\"data\":\"SECRET\"}")
	if diff, err := svc.Import(ctx, "remote-recon", raw); err == nil || !diff.Empty() {
		t.Fatalf("malformed batch accepted: %+v %v", diff, err)
	}
	if _, err := st.GetAssetByKey(ctx, model.KindHostname, "not-written.example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("malformed batch partially wrote inventory: %v", err)
	}
	existing, err := st.GetAssetByKey(ctx, model.KindHostname, "existing.example.com")
	if err != nil || existing.RemovedAt != nil {
		t.Fatalf("failed import removed existing inventory: %+v %v", existing, err)
	}
	statuses, err := st.ListSyncs(ctx)
	if err != nil || len(statuses) != 1 {
		t.Fatalf("source health missing: %+v %v", statuses, err)
	}
	if statuses[0].Error == "" || statuses[0].LastOK.IsZero() || strings.Contains(statuses[0].Error, "SECRET") {
		t.Fatalf("unsafe failure health: %+v", statuses[0])
	}
}
