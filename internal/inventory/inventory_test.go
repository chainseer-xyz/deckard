package inventory_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeCls is a tiny Classifier: owned if under a set zone or in an owned
// prefix, shared if in sharedPfx (owned wins, like scope.Guard).
type fakeCls struct {
	mu        sync.Mutex
	zones     []string
	owned     []netip.Prefix
	sharedPfx []netip.Prefix
	include   []string
}

func (f *fakeCls) SetZones(z []string) { f.mu.Lock(); f.zones = z; f.mu.Unlock() }
func (f *fakeCls) SetOwnedPrefixes(p []netip.Prefix) {
	f.mu.Lock()
	f.owned = p
	f.mu.Unlock()
}
func (f *fakeCls) ClassifyUnregistered(ip string) model.ScopeClass {
	return f.classify(model.KindIP, ip, false)
}
func (f *fakeCls) Classify(kind model.AssetKind, key string) model.ScopeClass {
	return f.classify(kind, key, true)
}
func (f *fakeCls) classify(kind model.AssetKind, key string, registered bool) model.ScopeClass {
	f.mu.Lock()
	defer f.mu.Unlock()
	if kind == model.KindIP {
		ip, err := netip.ParseAddr(key)
		if err != nil {
			return model.ScopeExternal
		}
		for _, p := range f.owned {
			if registered && p.Contains(ip) {
				return model.ScopeOwned
			}
		}
		for _, p := range f.sharedPfx {
			if p.Contains(ip) {
				return model.ScopeShared
			}
		}
		return model.ScopeExternal
	}
	for _, z := range f.zones {
		if key == z || len(key) > len(z) && key[len(key)-len(z)-1:] == "."+z {
			return model.ScopeOwned
		}
	}
	for _, i := range f.include {
		if key == i {
			return model.ScopeOwned
		}
	}
	return model.ScopeExternal
}

type fakeSrc struct {
	name, typ string
	d         *source.Discovery
	err       error
}

func (s *fakeSrc) Name() string { return s.name }
func (s *fakeSrc) Type() string { return s.typ }
func (s *fakeSrc) Discover(context.Context) (*source.Discovery, error) {
	return s.d, s.err
}

type rec struct {
	mu sync.Mutex
	m  map[string]int
}

func (r *rec) InventoryChange(kind string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]int{}
	}
	r.m[kind] += n
}

func host(k string) model.AssetInput { return model.AssetInput{Kind: model.KindHostname, Key: k} }
func ip(k string, attrs map[string]any) model.AssetInput {
	return model.AssetInput{Kind: model.KindIP, Key: k, Attrs: attrs}
}
func zone(n string) source.Zone { return source.Zone{Name: n} }

func keys(as []model.Asset) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Key)
	}
	return out
}

func pfx(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func TestSyncClassifiesAndDiffs(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{}
	r := &rec{}
	svc := inventory.New(st, cls, quiet, inventory.WithRecorder(r))

	src := &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{
		Zones:  []source.Zone{zone("Example.com.")},
		Assets: []model.AssetInput{host("www.example.com"), host("evil.other.org")},
	}}
	diff, err := svc.Sync(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) != 2 || r.m["added"] != 2 {
		t.Fatalf("diff=%+v rec=%v", diff, r.m)
	}
	if !reflect.DeepEqual(cls.zones, []string{"example.com"}) {
		t.Fatalf("zones: %v", cls.zones)
	}
	www, _ := st.GetAssetByKey(ctx, model.KindHostname, "www.example.com")
	ext, _ := st.GetAssetByKey(ctx, model.KindHostname, "evil.other.org")
	if www.Scope != model.ScopeOwned || www.Source != "cf" || ext.Scope != model.ScopeExternal {
		t.Fatalf("scopes: %v %v", www, ext)
	}
	syncs, _ := st.ListSyncs(ctx)
	if len(syncs) != 1 || syncs[0].Error != "" || syncs[0].AssetCount != 2 || syncs[0].LastOK.IsZero() {
		t.Fatalf("sync status: %+v", syncs)
	}

	// Second sync drops one asset -> removed diff.
	src.d = &source.Discovery{Zones: src.d.Zones, Assets: []model.AssetInput{host("www.example.com")}}
	diff, err = svc.Sync(ctx, src)
	if err != nil || !reflect.DeepEqual(keys(diff.Removed), []string{"evil.other.org"}) || r.m["removed"] != 1 {
		t.Fatalf("diff=%+v err=%v", diff, err)
	}
}

func TestSyncFailureNeverRemovesAssets(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{}
	svc := inventory.New(st, cls, quiet)
	src := &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{
		Zones: []source.Zone{zone("example.com")}, Assets: []model.AssetInput{host("a.example.com")},
	}}
	if _, err := svc.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	src.d, src.err = nil, errors.New("api 500")
	diff, err := svc.Sync(ctx, src)
	if err == nil || !diff.Empty() {
		t.Fatalf("want error + empty diff, got %v %+v", err, diff)
	}
	a, _ := st.GetAssetByKey(ctx, model.KindHostname, "a.example.com")
	if a.RemovedAt != nil {
		t.Fatal("asset removed after failed sync")
	}
	if !reflect.DeepEqual(cls.zones, []string{"example.com"}) {
		t.Fatalf("zones must survive failed sync: %v", cls.zones)
	}
	syncs, _ := st.ListSyncs(ctx)
	if syncs[0].Error == "" || syncs[0].LastOK.IsZero() {
		t.Fatalf("failure must record error and keep last_ok: %+v", syncs[0])
	}
	// nil discovery without error is also treated as failure.
	src.err = nil
	if _, err := svc.Sync(ctx, src); err == nil {
		t.Fatal("nil discovery must error")
	}
}

func TestSyncContextCancelled(t *testing.T) {
	st := pgtest.New(t)
	svc := inventory.New(st, &fakeCls{}, quiet)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := &fakeSrc{name: "cf", typ: "x", d: &source.Discovery{Assets: []model.AssetInput{host("a.example.com")}}}
	if _, err := svc.Sync(ctx, src); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if syncs, _ := st.ListSyncs(context.Background()); len(syncs) != 0 {
		t.Fatalf("cancellation must not record a sync failure: %+v", syncs)
	}
}

func TestZoneUnionShrinks(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{}
	svc := inventory.New(st, cls, quiet)
	a := &fakeSrc{name: "a", typ: "x", d: &source.Discovery{Zones: []source.Zone{zone("one.com"), zone("two.com")}}}
	b := &fakeSrc{name: "b", typ: "x", d: &source.Discovery{Zones: []source.Zone{zone("two.com"), zone("three.com")}}}
	for _, s := range []*fakeSrc{a, b} {
		if _, err := svc.Sync(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"one.com", "three.com", "two.com"}; !reflect.DeepEqual(cls.zones, want) {
		t.Fatalf("union %v want %v", cls.zones, want)
	}
	// a drops two.com and one.com: two.com still held by b.
	a.d = &source.Discovery{}
	if _, err := svc.Sync(ctx, a); err != nil {
		t.Fatal(err)
	}
	if want := []string{"three.com", "two.com"}; !reflect.DeepEqual(cls.zones, want) {
		t.Fatalf("after shrink %v want %v", cls.zones, want)
	}
	// a failure of b keeps b's zones.
	b.d, b.err = nil, errors.New("down")
	_, _ = svc.Sync(ctx, b)
	if want := []string{"three.com", "two.com"}; !reflect.DeepEqual(cls.zones, want) {
		t.Fatalf("after failure %v want %v", cls.zones, want)
	}
}

func TestOwnedPrefixRegistration(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{sharedPfx: pfx("104.16.0.0/13")}
	svc := inventory.New(st, cls, quiet)

	cf := &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{Assets: []model.AssetInput{
		ip("192.0.2.10", map[string]any{"origin": true}),
		ip("104.16.1.1", map[string]any{"origin": true}),  // shared edge: never owned
		ip("192.0.2.99", map[string]any{"proxied": true}), // no claim
	}}}
	k8s := &fakeSrc{name: "k8s", typ: "kubernetes", d: &source.Discovery{Assets: []model.AssetInput{
		ip("198.51.100.7", map[string]any{"cluster": "prod"}),
	}}}
	stat := &fakeSrc{name: "static", typ: "static", d: &source.Discovery{Assets: []model.AssetInput{
		ip("203.0.113.5", map[string]any{"owned": true}),
		{Kind: model.KindHostname, Key: "x.example.com", Attrs: map[string]any{"owned": true}},
	}}}
	for _, s := range []*fakeSrc{cf, k8s, stat} {
		if _, err := svc.Sync(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]model.ScopeClass{
		"192.0.2.10": model.ScopeOwned, "104.16.1.1": model.ScopeShared, "192.0.2.99": model.ScopeExternal,
		"198.51.100.7": model.ScopeOwned, "203.0.113.5": model.ScopeOwned,
	}
	for k, w := range want {
		if got := cls.Classify(model.KindIP, k); got != w {
			t.Errorf("%s: got %s want %s", k, got, w)
		}
		a, err := st.GetAssetByKey(ctx, model.KindIP, k)
		if err != nil || a.Scope != w {
			t.Errorf("%s stored scope %v err %v want %s", k, a, err, w)
		}
	}

	// The origin IP is removed from the source: its registration goes away.
	cf.d = &source.Discovery{}
	if _, err := svc.Sync(ctx, cf); err != nil {
		t.Fatal(err)
	}
	if got := cls.Classify(model.KindIP, "192.0.2.10"); got != model.ScopeExternal {
		t.Errorf("registration must shrink, got %s", got)
	}
	if got := cls.Classify(model.KindIP, "198.51.100.7"); got != model.ScopeOwned {
		t.Errorf("other sources' registrations stay, got %s", got)
	}
}

// An owned registration must not vouch for itself: once the IP's range is
// shared (the shared list grew after it was registered), the next sync drops
// the registration exactly as a first registration would have been refused.
func TestOwnedPrefixDroppedWhenRangeBecomesShared(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{}
	svc := inventory.New(st, cls, quiet)
	cf := &fakeSrc{name: "cf", typ: "cloudflare", d: &source.Discovery{Assets: []model.AssetInput{
		ip("192.0.2.10", map[string]any{"origin": true}),
	}}}
	if _, err := svc.Sync(ctx, cf); err != nil {
		t.Fatal(err)
	}
	if got := cls.Classify(model.KindIP, "192.0.2.10"); got != model.ScopeOwned {
		t.Fatalf("precondition: origin IP should be owned, got %s", got)
	}

	cls.mu.Lock()
	cls.sharedPfx = pfx("192.0.2.0/24")
	cls.mu.Unlock()
	if _, err := svc.Sync(ctx, cf); err != nil {
		t.Fatal(err)
	}

	if got := cls.Classify(model.KindIP, "192.0.2.10"); got != model.ScopeShared {
		t.Errorf("IP in a now-shared range stays registered as owned: got %s, want shared", got)
	}
}

func TestOwnedPrefixCIDRKey(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{}
	svc := inventory.New(st, cls, quiet)
	s := &fakeSrc{name: "s", typ: "static", d: &source.Discovery{Assets: []model.AssetInput{
		ip("203.0.113.0/24", map[string]any{"owned": true}),
		ip("not-an-ip", map[string]any{"owned": true}),
	}}}
	if _, err := svc.Sync(ctx, s); err != nil {
		t.Fatal(err)
	}
	if got := cls.Classify(model.KindIP, "203.0.113.77"); got != model.ScopeOwned {
		t.Fatalf("got %s", got)
	}
}

func TestAddDiscoveredOnlyOwned(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	cls := &fakeCls{include: []string{"extra.net"}}
	r := &rec{}
	svc := inventory.New(st, cls, quiet, inventory.WithRecorder(r))
	if _, err := svc.Sync(ctx, &fakeSrc{name: "s", typ: "x", d: &source.Discovery{
		Zones: []source.Zone{zone("example.com")}, Assets: []model.AssetInput{host("www.example.com")},
	}}); err != nil {
		t.Fatal(err)
	}
	diff, err := svc.AddDiscovered(ctx, "check:tls.cert",
		[]model.AssetInput{host("new.example.com"), host("evil.org"), host("extra.net")},
		[]model.RelationInput{{FromKind: model.KindHostname, FromKey: "www.example.com", ToKind: model.KindHostname, ToKey: "new.example.com", Type: model.RelCNAMETo}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keys(diff.Added), []string{"new.example.com", "extra.net"}) && len(diff.Added) != 2 {
		t.Fatalf("added: %v", keys(diff.Added))
	}
	if _, err := st.GetAssetByKey(ctx, model.KindHostname, "evil.org"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("out-of-scope asset must not be stored: %v", err)
	}
	n, _ := st.GetAssetByKey(ctx, model.KindHostname, "new.example.com")
	if n.Source != "check:tls.cert" || n.Scope != model.ScopeOwned {
		t.Fatalf("%+v", n)
	}
	if r.m["dropped"] != 1 {
		t.Fatalf("dropped metric: %v", r.m)
	}
	// All dropped -> empty diff, no error; cancelled ctx -> error.
	if d, err := svc.AddDiscovered(ctx, "x", []model.AssetInput{host("evil.org")}, nil); err != nil || !d.Empty() {
		t.Fatalf("%v %v", d, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.AddDiscovered(cctx, "x", []model.AssetInput{host("a.example.com")}, nil); err == nil {
		t.Fatal("want ctx error")
	}
}

func TestNilRecorderAndClock(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := inventory.New(st, &fakeCls{}, nil, inventory.WithClock(func() time.Time { return fixed }), inventory.WithRecorder(nil))
	if _, err := svc.Sync(ctx, &fakeSrc{name: "s", typ: "x", d: &source.Discovery{Assets: []model.AssetInput{host("a.example.com")}}}); err != nil {
		t.Fatal(err)
	}
	syncs, _ := st.ListSyncs(ctx)
	if !syncs[0].LastRun.Equal(fixed) {
		t.Fatalf("%v", syncs[0])
	}
}
