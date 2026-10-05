package finding_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/notify"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// gstore adds a tiny asset graph and event feed to dstore.
type gstore struct {
	dstore
	assets map[int64]model.Asset
	edges  map[int64][]store.Edge
	events []store.Event
}

func (s *gstore) GetAsset(_ context.Context, id int64) (*model.Asset, error) {
	a := s.assets[id]
	return &a, nil
}
func (s *gstore) Edges(_ context.Context, id int64) ([]store.Edge, error) { return s.edges[id], nil }
func (s *gstore) ListEvents(context.Context, time.Time, int) ([]store.Event, error) {
	return s.events, nil
}

type capture struct {
	mu   sync.Mutex
	open []model.Finding
}

func (c *capture) Name() string { return "capture" }
func (c *capture) Notify(_ context.Context, open, _ []model.Finding) error {
	c.mu.Lock()
	c.open = append(c.open, open...)
	c.mu.Unlock()
	return nil
}

var _ notify.Notifier = (*capture)(nil)

func newGStore() *gstore {
	host := model.Asset{ID: 1, Kind: model.KindHostname, Key: "api.example.com", Source: "cloudflare", Zone: "example.com"}
	cf := model.Asset{ID: 2, Kind: model.KindCloudResource, Key: "cloudflare", Source: "cloudflare"}
	ip := model.Asset{ID: 3, Kind: model.KindIP, Key: "44.55.66.77", Source: "cloudflare"}
	svc := model.Asset{ID: 4, Kind: model.KindService, Key: "44.55.66.77:8080/tcp", Source: "kubernetes",
		Attrs: map[string]any{"cluster": "prod", "namespace": "web", "name": "api"}}
	g := &gstore{assets: map[int64]model.Asset{1: host, 2: cf, 3: ip, 4: svc}, edges: map[int64][]store.Edge{}}
	link := func(f, t model.Asset, rt model.RelationType) {
		g.edges[f.ID] = append(g.edges[f.ID], store.Edge{Other: t, Type: rt, Outbound: true})
		g.edges[t.ID] = append(g.edges[t.ID], store.Edge{Other: f, Type: rt, Outbound: false})
	}
	link(host, cf, model.RelProxiedBy)
	link(cf, ip, model.RelOriginOf)
	link(ip, svc, model.RelExposes)
	return g
}

func TestDispatcherEnrichesOpenFindings(t *testing.T) {
	g := newGStore()
	first := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	changedAt := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	g.events = []store.Event{{Type: "asset_changed", Subject: "44.55.66.77:8080/tcp", At: changedAt}}
	g.open = []model.Finding{{
		ID: 1, Check: "net.ports", AssetID: 4, AssetKey: "44.55.66.77:8080/tcp", Status: model.StatusOpen, FirstSeen: first,
		Evidence: map[string]any{"previous": []int{22}, "current": []int{22, 8080}},
	}}
	cap := &capture{}
	d := finding.NewDispatcher(g, []notify.Notifier{cap}, time.Minute, nil)
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cap.open) != 1 {
		t.Fatalf("got %d", len(cap.open))
	}
	c := cap.open[0].Context
	wantLineage := "api.example.com --proxied_by--> cloudflare --origin_of--> 44.55.66.77 --exposes--> 44.55.66.77:8080/tcp"
	if c["lineage"] != wantLineage {
		t.Errorf("lineage = %v", c["lineage"])
	}
	if c["previous_state"] != "[22]" || c["current_state"] != "[22,8080]" {
		t.Errorf("states: %v / %v", c["previous_state"], c["current_state"])
	}
	owner, _ := c["owner"].(string)
	if !strings.Contains(owner, "cloudflare zone=example.com") || !strings.Contains(owner, "kubernetes cluster=prod namespace=web service=api") {
		t.Errorf("owner = %q", owner)
	}
	if c["first_seen"] != "2026-10-01T00:00:00Z" || c["last_changed"] != "2026-10-02T08:00:00Z" {
		t.Errorf("times: %v %v", c["first_seen"], c["last_changed"])
	}
	// The store's own finding must not be mutated.
	if g.open[0].Context != nil {
		t.Error("store finding mutated")
	}
}

func TestDispatcherEnricherOptOut(t *testing.T) {
	g := newGStore()
	g.open = []model.Finding{{ID: 1, AssetID: 4, AssetKey: "x", Status: model.StatusOpen}}
	cap := &capture{}
	d := finding.NewDispatcher(g, []notify.Notifier{cap}, time.Minute, nil, finding.WithEnricher(nil))
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cap.open[0].Context != nil {
		t.Errorf("enrichment should be disabled: %v", cap.open[0].Context)
	}
}

func TestEnricherIncludesSecondarySourceFacts(t *testing.T) {
	g := newGStore()
	a := g.assets[3]
	a.Reporters = []string{"cloudflare", "aws", "cluster", "legacy"}
	a.SourceFacts = map[string]model.SourceFact{
		"cloudflare": {Zone: "example.com", Attrs: map[string]any{"zone_id": "cf-zone"}},
		"aws":        {Attrs: map[string]any{"account_id": "123456789012", "region": "us-west-2", "resource_id": "i-owned"}},
		"cluster":    {Attrs: map[string]any{"cluster": "staging", "namespace": "web", "name": "api"}},
		"retired":    {Attrs: map[string]any{"account_id": "must-not-appear"}},
	}
	g.assets[3] = a
	result := finding.NewEnricher(g).Enrich(context.Background(), []model.Finding{{AssetID: 3, AssetKey: a.Key}})
	owner, _ := result[0].Context["owner"].(string)
	for _, expected := range []string{"aws account_id=123456789012", "cluster cluster=staging", "cloudflare zone=example.com", "legacy"} {
		if !strings.Contains(owner, expected) {
			t.Errorf("missing %q from %q", expected, owner)
		}
	}
	if strings.Contains(owner, "must-not-appear") || strings.Contains(owner, "retired") {
		t.Errorf("withdrawn source facts leaked: %q", owner)
	}
	if g.assets[3].Attrs["account_id"] != nil {
		t.Fatal("enrichment mutated canonical attributes")
	}
}

func TestEnricherSurvivesStoreFailure(t *testing.T) {
	// dstore panics on Edges/GetAsset (nil embedded Store); enrichment must
	// degrade to the plain finding, never break notification.
	s := &dstore{open: []model.Finding{{ID: 7, AssetID: 1, AssetKey: "a", Status: model.StatusOpen}}}
	cap := &capture{}
	d := finding.NewDispatcher(s, []notify.Notifier{cap}, time.Minute, nil)
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cap.open) != 1 || cap.open[0].ID != 7 || cap.open[0].Context != nil {
		t.Errorf("%+v", cap.open)
	}
}

func TestStates(t *testing.T) {
	cases := []struct {
		name       string
		f          model.Finding
		prev, curr string
	}{
		{"old/new", model.Finding{Evidence: map[string]any{"old": "v1", "new": "v2"}}, "v1", "v2"},
		{"was/now map", model.Finding{Evidence: map[string]any{"was": map[string]any{"a": 1}, "now": map[string]any{"a": 2}}}, `{"a":1}`, `{"a":2}`},
		{"drift tag fallback", model.Finding{Tags: []string{"drift"}, Evidence: map[string]any{"port": 8080}},
			"not present in the learned baseline", `{"port":8080}`},
		{"none", model.Finding{Evidence: map[string]any{"port": 1}}, "", ""},
		{"empty", model.Finding{}, "", ""},
	}
	for _, tc := range cases {
		p, c := finding.States(tc.f)
		if p != tc.prev || c != tc.curr {
			t.Errorf("%s: %q %q", tc.name, p, c)
		}
	}
	long := strings.Repeat("x", 5000)
	_, c := finding.States(model.Finding{Evidence: map[string]any{"current": long}})
	if len([]rune(c)) > 520 {
		t.Errorf("state not truncated: %d", len(c))
	}
}
