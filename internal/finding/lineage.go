package finding

import (
	"context"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Lineage traversal bounds. They keep enrichment cheap on dense graphs (a
// shared load balancer can have thousands of neighbours).
const (
	maxLineageDepth = 6
	maxLineageNodes = 50
)

// EdgeSource is the part of store.Store lineage needs.
type EdgeSource interface {
	Edges(ctx context.Context, assetID int64) ([]store.Edge, error)
}

// LineageResult is the outcome of one lineage computation.
type LineageResult struct {
	// Text is the human-readable chain, e.g.
	// "api.example.com --proxied_by--> cloudflare --origin_of--> 1.2.3.4".
	// It is just the asset key when the asset has no known edges.
	Text string
	// Chain is the assets of the chain in order, ending at (or starting from)
	// the finding's asset.
	Chain []model.Asset
	// Explored is how many assets the bounded BFS visited.
	Explored int
	// Truncated reports that the node cap stopped the traversal early.
	Truncated bool
}

type gedge struct {
	from, to int64
	typ      model.RelationType
}

var relRank = map[model.RelationType]int{
	model.RelResolvesTo: 0, model.RelCNAMETo: 1, model.RelAliasTo: 2,
	model.RelProxiedBy: 3, model.RelOriginOf: 4, model.RelExposes: 5,
	model.RelServes: 6, model.RelHasCert: 7, model.RelInZone: 8,
}

func rank(t model.RelationType) int {
	if r, ok := relRank[t]; ok {
		return r
	}
	return len(relRank)
}

func label(a model.Asset) string {
	if a.Key != "" {
		return a.Key
	}
	return string(a.Kind)
}

// ComputeLineage explores the asset graph around a with a bounded,
// cycle-safe BFS (depth <= 6, <= 50 assets) and renders the best chain
// through a. The chain walks upstream (against edge direction) from a by
// preferring more specific relations, so a service renders as
// "host --resolves_to--> ip --exposes--> ip:port/tcp". An asset with no
// incoming edges instead continues downstream along its outgoing edges.
// Edge lookup errors for a node are ignored (a partial chain beats none).
func ComputeLineage(ctx context.Context, es EdgeSource, a model.Asset, cache map[int64][]store.Edge) LineageResult {
	nodes := map[int64]model.Asset{a.ID: a}
	depth := map[int64]int{a.ID: 0}
	var edges []gedge
	seenEdge := map[gedge]bool{}
	truncated := false
	queue := []int64{a.ID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if depth[id] >= maxLineageDepth {
			continue
		}
		es1, ok := cache[id]
		if !ok {
			var err error
			es1, err = es.Edges(ctx, id)
			if err != nil {
				es1 = nil
			}
			if cache != nil {
				cache[id] = es1
			}
		}
		sorted := append([]store.Edge(nil), es1...)
		sort.SliceStable(sorted, func(i, j int) bool {
			if ri, rj := rank(sorted[i].Type), rank(sorted[j].Type); ri != rj {
				return ri < rj
			}
			return label(sorted[i].Other) < label(sorted[j].Other)
		})
		for _, e := range sorted {
			o := e.Other
			if _, known := nodes[o.ID]; !known {
				if len(nodes) >= maxLineageNodes {
					truncated = true
					continue
				}
				nodes[o.ID] = o
				depth[o.ID] = depth[id] + 1
				queue = append(queue, o.ID)
			}
			ge := gedge{from: id, to: o.ID, typ: e.Type}
			if !e.Outbound {
				ge = gedge{from: o.ID, to: id, typ: e.Type}
			}
			if !seenEdge[ge] {
				seenEdge[ge] = true
				edges = append(edges, ge)
			}
		}
	}

	chain, rels := walk(a.ID, edges, nodes, true)
	if len(rels) == 0 {
		chain, rels = walk(a.ID, edges, nodes, false)
	}
	var b strings.Builder
	for i, n := range chain {
		if i > 0 {
			b.WriteString(" --" + string(rels[i-1]) + "--> ")
		}
		b.WriteString(label(n))
	}
	return LineageResult{Text: b.String(), Chain: chain, Explored: len(nodes), Truncated: truncated}
}

type step struct {
	next int64
	typ  model.RelationType
}

// candidates lists the edges leaving cur in the walk direction, best first
// (relation rank, then label), skipping visited nodes.
func candidates(cur int64, edges []gedge, nodes map[int64]model.Asset, upstream bool, visited map[int64]bool) []step {
	var out []step
	for _, e := range edges {
		from, next := e.from, e.to
		if upstream {
			from, next = e.to, e.from
		}
		if from == cur && !visited[next] {
			out = append(out, step{next, e.typ})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := rank(out[i].typ), rank(out[j].typ); ri != rj {
			return ri < rj
		}
		return label(nodes[out[i].next]) < label(nodes[out[j].next])
	})
	return out
}

// greedyLen is how far a plain best-first walk gets from cur.
func greedyLen(cur int64, edges []gedge, nodes map[int64]model.Asset, upstream bool, visited map[int64]bool, budget int) int {
	seen := map[int64]bool{}
	for k := range visited {
		seen[k] = true
	}
	n := 0
	for ; n < budget; n++ {
		c := candidates(cur, edges, nodes, upstream, seen)
		if len(c) == 0 {
			break
		}
		cur = c[0].next
		seen[cur] = true
	}
	return n
}

// walk follows one edge at a time from start, upstream (against edge
// direction, chain returned root-first) or downstream, never revisiting a node
// (cycle-safe) and stopping at the depth bound. Among the candidate edges it
// takes the one that leads to the longest best-first continuation, ties broken
// by relation rank then label, so a proxy hop is not lost to a shorter,
// higher-ranked branch.
func walk(start int64, edges []gedge, nodes map[int64]model.Asset, upstream bool) ([]model.Asset, []model.RelationType) {
	visited := map[int64]bool{start: true}
	cur := start
	chain := []model.Asset{nodes[start]}
	var rels []model.RelationType
	for i := 0; i < maxLineageDepth; i++ {
		cands := candidates(cur, edges, nodes, upstream, visited)
		if len(cands) == 0 {
			break
		}
		best, bestLen := cands[0], -1
		for _, c := range cands {
			visited[c.next] = true
			l := greedyLen(c.next, edges, nodes, upstream, visited, maxLineageDepth-i-1)
			delete(visited, c.next)
			if l > bestLen {
				best, bestLen = c, l
			}
		}
		visited[best.next] = true
		cur = best.next
		if upstream {
			chain = append([]model.Asset{nodes[best.next]}, chain...)
			rels = append([]model.RelationType{best.typ}, rels...)
		} else {
			chain = append(chain, nodes[best.next])
			rels = append(rels, best.typ)
		}
	}
	return chain, rels
}
