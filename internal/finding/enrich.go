package finding

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Context keys set by the Enricher on model.Finding.Context.
const (
	CtxLineage       = "lineage"
	CtxPreviousState = "previous_state"
	CtxCurrentState  = "current_state"
	CtxOwner         = "owner"
	CtxOwners        = "owners"
	CtxFirstSeen     = "first_seen"
	CtxLastChanged   = "last_changed"
)

const (
	maxStateRunes = 512
	eventWindow   = 7 * 24 * time.Hour
	eventLimit    = 2000
)

// Enricher adds actionable context (lineage, owner, previous/current state,
// change times) to open findings just before they are notified. It is
// best-effort: any store failure leaves the finding unenriched.
type Enricher struct {
	st  store.Store
	now func() time.Time
}

// NewEnricher builds an Enricher over st.
func NewEnricher(st store.Store) *Enricher { return &Enricher{st: st, now: time.Now} }

// Enrich returns copies of fs with Context filled; the inputs are not
// modified. Edge lookups are cached across findings for the call.
func (e *Enricher) Enrich(ctx context.Context, fs []model.Finding) (out []model.Finding) {
	out = fs
	defer func() {
		if r := recover(); r != nil {
			out = fs
		}
	}()
	if e == nil || e.st == nil || len(fs) == 0 {
		return fs
	}
	changed := e.lastChanged(ctx)
	cache := map[int64][]store.Edge{}
	res := make([]model.Finding, len(fs))
	for i, f := range fs {
		res[i] = e.one(ctx, f, cache, changed)
	}
	return res
}

func (e *Enricher) one(ctx context.Context, f model.Finding, cache map[int64][]store.Edge, changed map[string]time.Time) (out model.Finding) {
	out = f
	defer func() {
		if r := recover(); r != nil {
			out = f
		}
	}()
	c := map[string]any{}
	asset := model.Asset{ID: f.AssetID, Key: f.AssetKey, Zone: f.Zone, Source: f.Source}
	if a, err := e.st.GetAsset(ctx, f.AssetID); err == nil && a != nil {
		asset = *a
	}
	lr := ComputeLineage(ctx, e.st, asset, cache)
	if len(lr.Chain) > 1 {
		c[CtxLineage] = lr.Text
	}
	if owners := ownersOf(lr.Chain, asset); len(owners) > 0 {
		c[CtxOwners] = owners
		c[CtxOwner] = ownerString(owners)
	}
	prev, cur := States(f)
	if prev != "" {
		c[CtxPreviousState] = prev
	}
	if cur != "" {
		c[CtxCurrentState] = cur
	}
	if !f.FirstSeen.IsZero() {
		c[CtxFirstSeen] = f.FirstSeen.UTC().Format(time.RFC3339)
		lc := f.FirstSeen
		if t, ok := changed[f.AssetKey]; ok && t.After(lc) {
			lc = t
		}
		c[CtxLastChanged] = lc.UTC().Format(time.RFC3339)
	}
	if len(c) > 0 {
		out.Context = c
	}
	return out
}

// lastChanged maps asset key -> time of its latest change/open/reopen event
// within the window. One query per flush.
func (e *Enricher) lastChanged(ctx context.Context) (m map[string]time.Time) {
	m = map[string]time.Time{}
	defer func() { _ = recover() }()
	evs, err := e.st.ListEvents(ctx, e.now().Add(-eventWindow), eventLimit)
	if err != nil {
		return m
	}
	for _, ev := range evs {
		switch ev.Type {
		case "asset_changed", "finding_opened", "finding_reopened":
			if ev.At.After(m[ev.Subject]) {
				m[ev.Subject] = ev.At
			}
		}
	}
	return m
}

var (
	prevKeys = []string{"previous_state", "previous", "old", "was", "before", "baseline"}
	curKeys  = []string{"current_state", "current", "new", "now", "after", "observed"}
)

// States derives previous/current state summaries from a finding's evidence.
// Explicit pairs (previous/current, old/new, was/now, before/after, baseline/
// observed) win. A drift-tagged finding with no explicit pair reports its
// evidence as the current state and the baseline as the previous state.
func States(f model.Finding) (prev, cur string) {
	pick := func(keys []string) string {
		for _, k := range keys {
			if v, ok := f.Evidence[k]; ok {
				return summarise(v)
			}
		}
		return ""
	}
	prev, cur = pick(prevKeys), pick(curKeys)
	if prev == "" && cur == "" {
		for _, t := range f.Tags {
			if t == "drift" && len(f.Evidence) > 0 {
				return "not present in the learned baseline", summarise(f.Evidence)
			}
		}
	}
	return prev, cur
}

func summarise(v any) string {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case nil:
		return ""
	default:
		if raw, err := json.Marshal(x); err == nil {
			s = string(raw)
		} else {
			s = fmt.Sprint(x)
		}
	}
	s = strings.ToValidUTF8(s, "�")
	if r := []rune(s); len(r) > maxStateRunes {
		s = string(r[:maxStateRunes]) + "…"
	}
	return s
}

// ownersOf collects, per owning source, the identifying attributes of the
// chain assets (and the finding's own asset): kubernetes cluster/namespace/
// service, aws account/region/resource, cloudflare zone.
func ownersOf(chain []model.Asset, asset model.Asset) []map[string]any {
	by := map[string]map[string]any{}
	addFact := func(a model.Asset) {
		if a.Source == "" {
			return
		}
		m := by[a.Source]
		if m == nil {
			m = map[string]any{"source": a.Source}
			by[a.Source] = m
		}
		set := func(k string, v any) {
			if s, ok := v.(string); ok && s == "" {
				return
			}
			if v != nil {
				if _, exists := m[k]; !exists {
					m[k] = v
				}
			}
		}
		if _, ok := a.Attrs["cluster"]; ok {
			set("cluster", a.Attrs["cluster"])
			set("namespace", a.Attrs["namespace"])
			if a.Attrs["name"] != nil {
				set("service", a.Attrs["name"])
			}
		}
		for _, k := range []string{"account_id", "account", "region", "arn", "resource_id", "resource", "zone_id"} {
			if v, ok := a.Attrs[k]; ok {
				set(k, v)
			}
		}
		if a.Zone != "" {
			set("zone", a.Zone)
		} else if a.Kind == model.KindZone {
			set("zone", a.Key)
		}
	}
	add := func(a model.Asset) {
		for _, source := range a.Reporters {
			fact := a.SourceFacts[source]
			addFact(model.Asset{Kind: a.Kind, Key: a.Key, Source: source, Zone: fact.Zone, Attrs: fact.Attrs})
		}
		_, known := a.SourceFacts[a.Source]
		if !known && (len(a.Reporters) == 0 || slices.Contains(a.Reporters, a.Source)) {
			addFact(a)
		}
	}
	for _, a := range chain {
		add(a)
	}
	add(asset)
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, by[k])
	}
	return out
}

func ownerString(owners []map[string]any) string {
	parts := make([]string, 0, len(owners))
	for _, o := range owners {
		keys := make([]string, 0, len(o))
		for k := range o {
			if k != "source" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		p := fmt.Sprint(o["source"])
		for _, k := range keys {
			p += fmt.Sprintf(" %s=%v", k, o[k])
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}
