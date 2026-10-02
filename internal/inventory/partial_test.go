package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func hosts(n int) []model.AssetInput {
	var out []model.AssetInput
	for i := 0; i < n; i++ {
		out = append(out, host(fmt.Sprintf("h%03d.example.com", i)))
	}
	return out
}

func listLive(ctx context.Context, st store.Store) ([]model.Asset, int, error) {
	return st.ListAssets(ctx, store.AssetFilter{})
}

func TestPartialDiscoveryNeverRemoves(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{}
	r := &rec{}
	svc := inventory.New(st, cls, quiet, inventory.WithRecorder(r))
	src := &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{
		Zones:  []source.Zone{zone("example.com")},
		Assets: []model.AssetInput{host("a.example.com"), host("b.example.com")},
	}}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}

	// Tunnels were skipped: b is unseen, c is new.
	src.d = &source.Discovery{
		Zones:   []source.Zone{zone("example.com")},
		Assets:  []model.AssetInput{host("a.example.com"), host("c.example.com")},
		Partial: true, PartialReasons: []string{"cloudflare tunnels skipped"},
	}
	diff, err := svc.Sync(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Removed) != 0 || len(diff.Added) != 1 || diff.Added[0].Key != "c.example.com" {
		t.Fatalf("partial diff = %+v", diff)
	}
	b, _ := st.GetAssetByKey(ctx, model.KindHostname, "b.example.com")
	if b.RemovedAt != nil {
		t.Fatal("unseen asset removed by a partial discovery")
	}
	syncs, _ := st.ListSyncs(ctx)
	if syncs[0].Error != "" || syncs[0].LastOK.IsZero() || !strings.Contains(syncs[0].Warning, "tunnels skipped") {
		t.Fatalf("sync status = %+v", syncs[0])
	}
	if r.m["removed"] != 0 || r.m["added"] != 3 {
		t.Fatalf("recorder = %v", r.m)
	}

	// The next complete sync removes b and clears the warning.
	src.d = &source.Discovery{
		Zones:  []source.Zone{zone("example.com")},
		Assets: []model.AssetInput{host("a.example.com"), host("c.example.com")},
	}
	diff, err = svc.Sync(ctx, src)
	if err != nil || len(diff.Removed) != 1 || diff.Removed[0].Key != "b.example.com" {
		t.Fatalf("complete sync diff = %+v err=%v", diff, err)
	}
	if syncs, _ = st.ListSyncs(ctx); syncs[0].Warning != "" {
		t.Fatalf("warning not cleared: %+v", syncs[0])
	}
}

func TestPartialDiscoveryKeepsClassificationState(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{}
	svc := inventory.New(st, cls, quiet)
	src := &fakeSrc{name: "k8s", typ: "kubernetes", d: &source.Discovery{
		Zones:  []source.Zone{zone("one.com"), zone("two.com")},
		Assets: []model.AssetInput{ip("198.51.100.7", nil), ip("198.51.100.8", nil)},
	}}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	// A partial run lacks a zone and an IP (a skipped feature produced them):
	// they must stay classified owned.
	src.d = &source.Discovery{
		Zones: []source.Zone{zone("one.com")}, Assets: []model.AssetInput{ip("198.51.100.7", nil)},
		Partial: true, PartialReasons: []string{"nodes forbidden"},
	}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	if got := cls.Classify(model.KindHostname, "x.two.com"); got != model.ScopeOwned {
		t.Errorf("zone dropped by partial run: %s", got)
	}
	if got := cls.Classify(model.KindIP, "198.51.100.8"); got != model.ScopeOwned {
		t.Errorf("prefix dropped by partial run: %s", got)
	}
	// A complete run shrinks them again.
	src.d = &source.Discovery{Zones: []source.Zone{zone("one.com")}, Assets: []model.AssetInput{ip("198.51.100.7", nil)}}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	if got := cls.Classify(model.KindHostname, "x.two.com"); got != model.ScopeExternal {
		t.Errorf("zone survived complete run: %s", got)
	}
}

func TestSuspiciousShrinkRefusesRemoval(t *testing.T) {
	cases := []struct {
		name       string
		existing   int
		keep       int
		opts       []inventory.Option
		wantRefuse bool
	}{
		{"default: 40 of 50 vanish", 50, 10, nil, true},
		{"default: half exactly is allowed", 40, 20, nil, false}, // 20 removed = 50%, not more than 50%
		{"default: more than half but only 10 removed is allowed", 18, 8, nil, false},
		{"default: more than half and 11 removed is refused", 20, 9, nil, true},
		{"default: under half is allowed", 100, 60, nil, false},
		{"guard disabled", 50, 0, []inventory.Option{inventory.WithShrinkGuard(0, 0)}, false},
		{"custom threshold", 10, 6, []inventory.Option{inventory.WithShrinkGuard(0.3, 2)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := pgtest.New(t)
			svc := inventory.New(st, &fakeCls{}, quiet, tc.opts...)
			src := &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{
				Zones: []source.Zone{zone("example.com")}, Assets: hosts(tc.existing),
			}}
			if _, err := svc.Sync(ctx, src); err != nil {
				t.Fatal(err)
			}
			prev, _ := st.ListSyncs(ctx)
			src.d = &source.Discovery{Zones: src.d.Zones, Assets: hosts(tc.keep)}
			diff, err := svc.Sync(ctx, src)
			_, live, _ := listLive(ctx, st)
			syncs, _ := st.ListSyncs(ctx)
			if tc.wantRefuse {
				if !errors.Is(err, inventory.ErrSuspiciousShrink) {
					t.Fatalf("err = %v, want ErrSuspiciousShrink", err)
				}
				if len(diff.Removed) != 0 || live != tc.existing {
					t.Fatalf("removed %d, live %d of %d", len(diff.Removed), live, tc.existing)
				}
				if !strings.Contains(syncs[0].Error, "suspicious shrink") || !syncs[0].LastOK.Equal(prev[0].LastOK) {
					t.Fatalf("sync status = %+v (prev ok %v)", syncs[0], prev[0].LastOK)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if live != tc.keep || syncs[0].Error != "" {
				t.Fatalf("live %d want %d, status %+v", live, tc.keep, syncs[0])
			}
		})
	}
}

func TestSuspiciousShrinkAllowsGrowthAndRecovery(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	svc := inventory.New(st, &fakeCls{}, quiet)
	src := &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{Zones: []source.Zone{zone("example.com")}, Assets: hosts(30)}}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	src.d = &source.Discovery{Zones: src.d.Zones, Assets: hosts(5)}
	if _, err := svc.Sync(ctx, src); !errors.Is(err, inventory.ErrSuspiciousShrink) {
		t.Fatalf("err = %v", err)
	}
	// The upstream recovers: a normal sync clears the error.
	src.d = &source.Discovery{Zones: src.d.Zones, Assets: hosts(28)}
	diff, err := svc.Sync(ctx, src)
	if err != nil || len(diff.Removed) != 2 {
		t.Fatalf("recovery diff=%+v err=%v", diff, err)
	}
	if syncs, _ := st.ListSyncs(ctx); syncs[0].Error != "" {
		t.Fatalf("error not cleared: %+v", syncs[0])
	}
}
