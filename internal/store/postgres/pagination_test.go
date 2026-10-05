package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

func TestInventoryPaginationBeyond5000(t *testing.T) {
	ctx := context.Background()
	url := freshDB(t, true)
	s, err := postgres.New(ctx, url, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, `INSERT INTO assets(kind,key,source,scope,zone,first_seen,last_seen)
		SELECT 'hostname', 'host-' || g || '.example', 'static', 'owned',
			CASE WHEN g <= 6000 THEN 'alpha.example' WHEN g = 6006 THEN '' ELSE 'beta.example' END,
			'2026-10-01'::timestamptz, '2026-10-04'::timestamptz FROM generate_series(1,6006) g;
		INSERT INTO findings(fingerprint,check_name,asset_id,severity,severity_rank,title,tags,evidence,status,first_seen,last_seen)
		SELECT 'fp-' || id, CASE WHEN id <= 6000 THEN 'mass' WHEN id = 6004 THEN 'tls.cert' ELSE 'tail' END,
			id, CASE WHEN id = 6002 THEN 'critical' WHEN id = 6003 THEN 'medium' WHEN id = 6005 THEN 'low' ELSE 'high' END,
			CASE WHEN id = 6002 THEN 4 WHEN id = 6003 THEN 2 WHEN id = 6005 THEN 1 ELSE 3 END,
			CASE WHEN id = 6004 THEN 'Expired certificate' ELSE 'Finding ' || id END,
			CASE WHEN id = 6002 THEN ARRAY['takeover'] ELSE ARRAY[]::text[] END,
			CASE WHEN id = 6003 THEN '{"kev":true}'::jsonb ELSE '{}'::jsonb END, 'open',
			'2026-10-01'::timestamptz + id * interval '1 second', '2026-10-04'::timestamptz FROM assets`)
	if err != nil {
		t.Fatal(err)
	}

	items, total, err := s.ListFindings(ctx, store.FindingFilter{Severity: model.SeverityHigh, Sort: "first_seen", Direction: "asc", Limit: 50, Offset: 6000})
	if err != nil || total != 6003 || len(items) != 3 || items[0].AssetID != 6001 || items[1].AssetID != 6004 || items[2].AssetID != 6006 {
		t.Fatalf("exact severity page: total=%d items=%+v err=%v", total, items, err)
	}
	items, _, err = s.ListFindings(ctx, store.FindingFilter{AttentionOnly: true, Sort: "attention", Limit: 3})
	if err != nil || len(items) != 3 || items[0].AssetID != 6002 || items[1].AssetID != 6004 {
		t.Fatalf("attention must rank tail takeover and expiry before paging: %+v %v", items, err)
	}
	kevItems, kevTotal, err := s.ListFindings(ctx, store.FindingFilter{AttentionOnly: true, Severity: model.SeverityMedium, Limit: 1})
	if err != nil || kevTotal != 1 || len(kevItems) != 1 || kevItems[0].AssetID != 6003 {
		t.Fatalf("medium KEV: %+v total=%d err=%v", kevItems, kevTotal, err)
	}
	freshItems, freshTotal, err := s.ListFindings(ctx, store.FindingFilter{FirstSeenAfter: time.Date(2026, 10, 1, 1, 40, 1, 0, time.UTC), Limit: 1})
	if err != nil || freshTotal != 6 || len(freshItems) != 1 {
		t.Fatalf("fresh count must include complete set: %+v total=%d err=%v", freshItems, freshTotal, err)
	}
	groups, groupTotal, err := s.ListFindingGroups(ctx, store.FindingFilter{GroupBy: "zone", MinSeverity: model.SeverityMedium, Sort: "count", Limit: 2})
	if err != nil || groupTotal != 3 || len(groups) != 2 || groups[0].Key != "alpha.example" || groups[0].Total != 6000 || groups[1].Total != 4 || groups[1].Counts["critical"] != 1 {
		t.Fatalf("group aggregates: %+v total=%d err=%v", groups, groupTotal, err)
	}
	group := "alpha.example"
	members, memberTotal, err := s.ListFindings(ctx, store.FindingFilter{GroupBy: "zone", GroupKey: &group, Sort: "first_seen", Direction: "asc", Offset: 5000, Limit: 50})
	if err != nil || memberTotal != 6000 || len(members) != 50 || members[0].AssetID != 5001 {
		t.Fatalf("group member pagination: %+v total=%d err=%v", members, memberTotal, err)
	}
	empty := ""
	noZone, total, err := s.ListFindings(ctx, store.FindingFilter{GroupBy: "zone", GroupKey: &empty, Limit: 50})
	if err != nil || total != 1 || len(noZone) != 1 || noZone[0].AssetID != 6006 {
		t.Fatalf("empty-zone members: %+v total=%d err=%v", noZone, total, err)
	}
	assets, assetTotal, err := s.ListAssets(ctx, store.AssetFilter{OpenMinSeverity: model.SeverityMedium, Limit: 50})
	if err != nil || assetTotal != 6005 || len(assets) != 50 || assets[0].ID != 6002 {
		t.Fatalf("asset finding filter: first=%+v total=%d err=%v", assets, assetTotal, err)
	}
	// Removing verbose history must leave the inventory's last-scan column intact.
	scannedAt := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if err := s.RecordScan(ctx, store.ScanRun{AssetID: 6001, Check: "mass", Tier: "passive", StartedAt: scannedAt}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneScans(ctx, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	summaries, err := s.AssetSummaries(ctx, []int64{6001, 6002, 6005})
	if err != nil || len(summaries) != 3 || summaries[0].OpenFindings != 1 || summaries[0].LastScan == nil || !summaries[0].LastScan.Equal(scannedAt) || summaries[1].TopSeverity != model.SeverityCritical || summaries[2].TopSeverity != model.SeverityLow {
		t.Fatalf("durable asset summaries: %+v %v", summaries, err)
	}
}
