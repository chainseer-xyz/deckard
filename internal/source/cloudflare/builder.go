package cloudflare

import (
	"sort"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

type assetID struct {
	kind model.AssetKind
	key  string
}

// builder accumulates and de-duplicates assets and relations so the same
// hostname or IP seen in several records yields one merged asset.
type builder struct {
	src    string
	assets map[assetID]*model.AssetInput
	order  []assetID
	rels   map[model.RelationInput]bool
	rorder []model.RelationInput

	partial []string
}

// skip records a feature that could not be read, making the discovery partial.
func (b *builder) skip(reason string) { b.partial = append(b.partial, reason) }

func newBuilder(src string) *builder {
	return &builder{src: src, assets: map[assetID]*model.AssetInput{}, rels: map[model.RelationInput]bool{}}
}

// asset returns the (created on first use) asset; a non-empty zone is kept.
func (b *builder) asset(kind model.AssetKind, key, zone string) *model.AssetInput {
	id := assetID{kind, key}
	a, ok := b.assets[id]
	if !ok {
		a = &model.AssetInput{Kind: kind, Key: key, Source: b.src, Attrs: map[string]any{}}
		b.assets[id] = a
		b.order = append(b.order, id)
	}
	if a.Zone == "" && zone != "" {
		a.Zone = zone
	}
	return a
}

func (b *builder) host(name, zone string) *model.AssetInput {
	return b.asset(model.KindHostname, name, zone)
}

func (b *builder) cloudResource(key string, attrs map[string]any) {
	a := b.asset(model.KindCloudResource, key, "")
	for k, v := range attrs {
		a.Attrs[k] = v
	}
}

func (b *builder) rel(fk model.AssetKind, fkey string, tk model.AssetKind, tkey string, t model.RelationType) {
	r := model.RelationInput{FromKind: fk, FromKey: fkey, ToKind: tk, ToKey: tkey, Type: t}
	if !b.rels[r] {
		b.rels[r] = true
		b.rorder = append(b.rorder, r)
	}
}

func (b *builder) discovery() *source.Discovery {
	d := &source.Discovery{}
	for _, id := range b.order {
		a := b.assets[id]
		if len(a.Attrs) == 0 {
			a.Attrs = nil
		}
		d.Assets = append(d.Assets, *a)
	}
	d.Relations = append(d.Relations, b.rorder...)
	d.Partial, d.PartialReasons = len(b.partial) > 0, b.partial
	return d
}

// addUniq appends v to the []string attr k if absent, keeping it sorted.
func addUniq(attrs map[string]any, k, v string) {
	cur, _ := attrs[k].([]string)
	for _, e := range cur {
		if e == v {
			return
		}
	}
	cur = append(cur, v)
	if k != "origin_ips" { // origin_ips keeps record order; origin_ip is its first element
		sort.Strings(cur)
	}
	attrs[k] = cur
}
