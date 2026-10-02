package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type graph struct {
	assets map[int64]model.Asset
	adj    map[int64][]store.Edge
	calls  int
	errOn  map[int64]bool
}

func newGraph() *graph {
	return &graph{assets: map[int64]model.Asset{}, adj: map[int64][]store.Edge{}, errOn: map[int64]bool{}}
}

func (g *graph) node(id int64, kind model.AssetKind, key string) model.Asset {
	a := model.Asset{ID: id, Kind: kind, Key: key}
	g.assets[id] = a
	return a
}

func (g *graph) edge(from, to int64, t model.RelationType) {
	g.adj[from] = append(g.adj[from], store.Edge{Other: g.assets[to], Type: t, Outbound: true})
	g.adj[to] = append(g.adj[to], store.Edge{Other: g.assets[from], Type: t, Outbound: false})
}

func (g *graph) Edges(_ context.Context, id int64) ([]store.Edge, error) {
	g.calls++
	if g.errOn[id] {
		return nil, errors.New("boom")
	}
	return g.adj[id], nil
}

func TestComputeLineage(t *testing.T) {
	cases := []struct {
		name  string
		build func(g *graph) model.Asset
		want  string
	}{
		{"proxy chain", func(g *graph) model.Asset {
			g.node(1, model.KindHostname, "api.example.com")
			g.node(2, model.KindCloudResource, "cloudflare")
			g.node(3, model.KindIP, "44.55.66.77")
			a := g.node(4, model.KindService, "44.55.66.77:8080/tcp")
			g.edge(1, 2, model.RelProxiedBy)
			g.edge(2, 3, model.RelOriginOf)
			g.edge(3, 4, model.RelExposes)
			return a
		}, "api.example.com --proxied_by--> cloudflare --origin_of--> 44.55.66.77 --exposes--> 44.55.66.77:8080/tcp"},
		{"prefers longer chain over higher rank", func(g *graph) model.Asset {
			g.node(1, model.KindHostname, "api.example.com")
			g.node(2, model.KindCloudResource, "cloudflare")
			g.node(3, model.KindIP, "44.55.66.77")
			g.edge(1, 3, model.RelResolvesTo)
			g.edge(1, 2, model.RelProxiedBy)
			g.edge(2, 3, model.RelOriginOf)
			return g.assets[3]
		}, "api.example.com --proxied_by--> cloudflare --origin_of--> 44.55.66.77"},
		{"k8s service", func(g *graph) model.Asset {
			g.node(1, model.KindHostname, "app.example.com")
			g.node(2, model.KindService, "prod/web")
			g.node(3, model.KindService, "10.0.0.5:8080/tcp")
			g.edge(1, 2, model.RelServes)
			g.edge(2, 3, model.RelExposes)
			return g.assets[3]
		}, "app.example.com --serves--> prod/web --exposes--> 10.0.0.5:8080/tcp"},
		{"aws lb", func(g *graph) model.Asset {
			g.node(1, model.KindHostname, "shop.example.com")
			g.node(2, model.KindCloudResource, "arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/x")
			g.node(3, model.KindIP, "52.1.1.1")
			g.edge(1, 2, model.RelAliasTo)
			g.edge(2, 3, model.RelResolvesTo)
			return g.assets[3]
		}, "shop.example.com --alias_to--> arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/x --resolves_to--> 52.1.1.1"},
		{"cycle terminates", func(g *graph) model.Asset {
			g.node(1, model.KindHostname, "a.example.com")
			g.node(2, model.KindHostname, "b.example.com")
			g.node(3, model.KindHostname, "c.example.com")
			g.edge(1, 2, model.RelCNAMETo)
			g.edge(2, 3, model.RelCNAMETo)
			g.edge(3, 1, model.RelCNAMETo)
			return g.assets[3]
		}, "a.example.com --cname_to--> b.example.com --cname_to--> c.example.com"},
		{"missing edges", func(g *graph) model.Asset {
			return g.node(1, model.KindIP, "1.2.3.4")
		}, "1.2.3.4"},
		{"root continues downstream", func(g *graph) model.Asset {
			g.node(1, model.KindHostname, "api.example.com")
			g.node(2, model.KindCloudResource, "cloudflare")
			g.edge(1, 2, model.RelProxiedBy)
			return g.assets[1]
		}, "api.example.com --proxied_by--> cloudflare"},
		{"edge lookup error is tolerated", func(g *graph) model.Asset {
			g.node(1, model.KindHostname, "a.example.com")
			g.node(2, model.KindIP, "1.1.1.1")
			g.node(3, model.KindService, "1.1.1.1:22/tcp")
			g.edge(1, 2, model.RelResolvesTo)
			g.edge(2, 3, model.RelExposes)
			g.errOn[2] = true
			return g.assets[3]
		}, "1.1.1.1 --exposes--> 1.1.1.1:22/tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGraph()
			a := tc.build(g)
			got := ComputeLineage(context.Background(), g, a, nil)
			if got.Text != tc.want {
				t.Errorf("lineage\n got %q\nwant %q", got.Text, tc.want)
			}
		})
	}
}

func TestLineageFanOutCap(t *testing.T) {
	g := newGraph()
	root := g.node(1, model.KindIP, "10.0.0.1")
	for i := 0; i < 500; i++ {
		id := int64(100 + i)
		g.node(id, model.KindHostname, fmt.Sprintf("h%03d.example.com", i))
		g.edge(id, 1, model.RelResolvesTo)
	}
	got := ComputeLineage(context.Background(), g, root, nil)
	if got.Explored > maxLineageNodes || !got.Truncated {
		t.Errorf("explored=%d truncated=%v", got.Explored, got.Truncated)
	}
	if got.Text != "h000.example.com --resolves_to--> 10.0.0.1" {
		t.Errorf("deterministic chain expected, got %q", got.Text)
	}
}

func TestLineageDepthCap(t *testing.T) {
	g := newGraph()
	for i := 1; i <= 20; i++ {
		g.node(int64(i), model.KindHostname, fmt.Sprintf("n%02d", i))
	}
	for i := 1; i < 20; i++ {
		g.edge(int64(i), int64(i+1), model.RelCNAMETo)
	}
	got := ComputeLineage(context.Background(), g, g.assets[20], nil)
	if n := strings.Count(got.Text, "-->"); n > maxLineageDepth {
		t.Errorf("%d hops exceeds depth cap: %s", n, got.Text)
	}
	if !strings.HasSuffix(got.Text, "n20") {
		t.Errorf("chain must end at the asset: %s", got.Text)
	}
}

func TestLineageCache(t *testing.T) {
	g := newGraph()
	a := g.node(1, model.KindIP, "1.1.1.1")
	cache := map[int64][]store.Edge{}
	ComputeLineage(context.Background(), g, a, cache)
	n := g.calls
	ComputeLineage(context.Background(), g, a, cache)
	if g.calls != n {
		t.Errorf("cache not used: %d -> %d", n, g.calls)
	}
}
