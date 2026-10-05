package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chainseer-xyz/deckard/docs"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), s.d.ReadyzTimeout)
	defer cancel()
	if err := s.d.Store.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) openapi(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(docs.OpenAPI)
}

type meResponse struct {
	Subject   string   `json:"subject"`
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	AuthMode  string   `json:"auth_mode"`
	Method    string   `json:"method"`
	CanWrite  bool     `json:"can_write"`
	CSRFToken string   `json:"csrf_token,omitempty"`
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	writeJSON(w, http.StatusOK, meResponse{
		Subject: id.Subject, Name: id.Name, Email: id.Email, Groups: id.Groups,
		AuthMode: s.authn.Mode(), Method: id.Method,
		// Every authenticated identity may perform operator actions; group
		// membership is enforced at login for OIDC.
		CanWrite: true, CSRFToken: id.CSRFToken,
	})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	if newQuery(r).reject(w) {
		return
	}
	st, err := s.d.Store.Stats(r.Context())
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	for _, m := range []*map[string]int{&st.AssetsByKind, &st.AssetsBySource, &st.AssetsByScope, &st.FindingsBySev, &st.FindingsByCheck} {
		if *m == nil {
			*m = map[string]int{}
		}
	}
	writeJSON(w, http.StatusOK, st)
}

// ---- assets ----

var assetKinds = map[string]bool{
	string(model.KindZone): true, string(model.KindHostname): true, string(model.KindIP): true,
	string(model.KindService): true, string(model.KindURL): true, string(model.KindCertificate): true,
	string(model.KindCloudResource): true,
}

var scopeClasses = map[string]bool{
	string(model.ScopeOwned): true, string(model.ScopeShared): true,
	string(model.ScopeExternal): true, string(model.ScopeExcluded): true,
}

var findingStatuses = map[string]bool{
	string(model.StatusOpen): true, string(model.StatusAcknowledged): true, string(model.StatusSuppressed): true,
	string(model.StatusFalsePositive): true, string(model.StatusResolved): true,
}

func in(set map[string]bool) func(string) bool { return func(s string) bool { return set[s] } }

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r, "kind", "source", "scope", "zone", "q", "include_removed", "open_min_severity", "include_summary", "limit", "offset")
	f := store.AssetFilter{
		Kind:            model.AssetKind(q.enum("kind", in(assetKinds))),
		Source:          q.str("source"),
		Scope:           model.ScopeClass(q.enum("scope", in(scopeClasses))),
		Zone:            q.str("zone"),
		Query:           q.str("q"),
		IncludeRemoved:  q.boolean("include_removed"),
		OpenMinSeverity: model.Severity(q.enum("open_min_severity", func(v string) bool { return model.Severity(v).Valid() })),
		Limit:           q.limit(),
		Offset:          q.offset(),
	}
	summary := q.boolean("include_summary")
	if q.reject(w) {
		return
	}
	items, total, err := s.d.Store.ListAssets(r.Context(), f)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	if summary {
		ids := make([]int64, len(items))
		for i, a := range items {
			ids[i] = a.ID
		}
		summaries, err := s.d.Store.AssetSummaries(r.Context(), ids)
		if err != nil {
			s.storeError(w, r, err)
			return
		}
		byID := make(map[int64]store.AssetSummary, len(summaries))
		for _, v := range summaries {
			byID[v.AssetID] = v
		}
		type item struct {
			model.Asset
			OpenFindings int            `json:"open_findings"`
			TopSeverity  model.Severity `json:"top_severity"`
			LastScan     *time.Time     `json:"last_scan"`
		}
		out := make([]item, 0, len(items))
		for _, a := range items {
			v := byID[a.ID]
			out = append(out, item{Asset: a, OpenFindings: v.OpenFindings, TopSeverity: v.TopSeverity, LastScan: v.LastScan})
		}
		writeJSON(w, http.StatusOK, newList(out, total, f.Limit, f.Offset))
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, f.Limit, f.Offset))
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_id", "id must be a positive integer")
		return 0, false
	}
	return id, true
}

type edgeJSON struct {
	Direction string             `json:"direction"` // out|in
	Type      model.RelationType `json:"type"`
	Asset     model.Asset        `json:"asset"`
}

type baselineJSON struct {
	Check      string         `json:"check"`
	Data       map[string]any `json:"data"`
	Stable     bool           `json:"stable"`
	Consistent int            `json:"consistent"`
	UpdatedAt  string         `json:"updated_at"`
}

type assetDetail struct {
	Asset        model.Asset         `json:"asset"`
	Edges        []edgeJSON          `json:"edges"`
	Observations []model.Observation `json:"observations"`
	Baselines    []baselineJSON      `json:"baselines"`
	Findings     []model.Finding     `json:"findings"`
}

func direction(out bool) string {
	if out {
		return "out"
	}
	return "in"
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if newQuery(r).reject(w) {
		return
	}
	ctx := r.Context()
	a, err := s.d.Store.GetAsset(ctx, id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	edges, err := s.d.Store.Edges(ctx, id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	obs, err := s.d.Store.LatestObservations(ctx, id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	findings, _, err := s.d.Store.ListFindings(ctx, store.FindingFilter{
		AssetID: id, Statuses: []model.FindingStatus{model.StatusOpen}, Limit: s.d.MaxFindingsEmbed,
	})
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	d := assetDetail{Asset: *a, Edges: []edgeJSON{}, Observations: obs, Baselines: []baselineJSON{}, Findings: findings}
	if d.Observations == nil {
		d.Observations = []model.Observation{}
	}
	if d.Findings == nil {
		d.Findings = []model.Finding{}
	}
	for _, e := range edges {
		d.Edges = append(d.Edges, edgeJSON{Direction: direction(e.Outbound), Type: e.Type, Asset: e.Other})
	}
	seen := map[string]bool{}
	for _, o := range obs {
		if seen[o.Check] {
			continue
		}
		seen[o.Check] = true
		b, err := s.d.Store.GetBaseline(ctx, id, o.Check)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			s.storeError(w, r, err)
			return
		}
		d.Baselines = append(d.Baselines, baselineJSON{
			Check: b.Check, Data: b.Data, Stable: b.Stable, Consistent: b.Consistent,
			UpdatedAt: b.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	writeJSON(w, http.StatusOK, d)
}

type graphNode struct {
	ID    int64            `json:"id"`
	Kind  model.AssetKind  `json:"kind"`
	Key   string           `json:"key"`
	Scope model.ScopeClass `json:"scope"`
}

type graphEdge struct {
	From int64              `json:"from"`
	To   int64              `json:"to"`
	Type model.RelationType `json:"type"`
}

type graphResponse struct {
	Nodes     []graphNode `json:"nodes"`
	Edges     []graphEdge `json:"edges"`
	Truncated bool        `json:"truncated"`
}

func (s *Server) assetGraph(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := newQuery(r, "depth")
	depth := q.depth()
	if q.reject(w) {
		return
	}
	ctx := r.Context()
	root, err := s.d.Store.GetAsset(ctx, id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	resp := graphResponse{Nodes: []graphNode{}, Edges: []graphEdge{}}
	nodes := map[int64]bool{}
	addNode := func(a model.Asset) bool {
		if nodes[a.ID] {
			return true
		}
		if len(nodes) >= s.d.MaxGraphNodes {
			resp.Truncated = true
			return false
		}
		nodes[a.ID] = true
		resp.Nodes = append(resp.Nodes, graphNode{ID: a.ID, Kind: a.Kind, Key: a.Key, Scope: a.Scope})
		return true
	}
	type ek struct {
		from, to int64
		t        model.RelationType
	}
	edgeSeen := map[ek]bool{}
	addNode(*root)
	frontier := []int64{root.ID}
	expanded := map[int64]bool{}
	for d := 0; d < depth && len(frontier) > 0; d++ {
		var next []int64
		for _, cur := range frontier {
			if expanded[cur] {
				continue
			}
			expanded[cur] = true
			edges, err := s.d.Store.Edges(ctx, cur)
			if err != nil {
				s.storeError(w, r, err)
				return
			}
			for _, e := range edges {
				fresh := !nodes[e.Other.ID]
				if !addNode(e.Other) {
					continue
				}
				from, to := cur, e.Other.ID
				if !e.Outbound {
					from, to = to, from
				}
				k := ek{from, to, e.Type}
				if !edgeSeen[k] {
					edgeSeen[k] = true
					resp.Edges = append(resp.Edges, graphEdge{From: from, To: to, Type: e.Type})
				}
				if fresh {
					next = append(next, e.Other.ID)
				}
			}
		}
		frontier = next
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- findings ----

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r, "status", "min_severity", "severity", "check", "zone", "source", "asset_id", "q", "sort", "direction", "group_by", "group_key", "attention", "first_seen_after", "limit", "offset")
	f := store.FindingFilter{
		MinSeverity:   model.Severity(q.enum("min_severity", func(v string) bool { return model.Severity(v).Valid() })),
		Severity:      model.Severity(q.enum("severity", func(v string) bool { return model.Severity(v).Valid() })),
		Sort:          q.enum("sort", in(map[string]bool{"severity": true, "first_seen": true, "last_seen": true, "attention": true, "count": true})),
		Direction:     q.enum("direction", in(map[string]bool{"asc": true, "desc": true})),
		GroupBy:       q.enum("group_by", in(map[string]bool{"asset": true, "check": true, "zone": true})),
		AttentionOnly: q.boolean("attention"),
		Check:         q.str("check"),
		Zone:          q.str("zone"),
		Source:        q.str("source"),
		AssetID:       q.posInt64("asset_id"),
		Query:         q.str("q"),
		Limit:         q.limit(),
		Offset:        q.offset(),
	}
	if _, present := q.v["group_key"]; present {
		// Asset keys include URLs and cloud-resource IDs, longer than search text.
		key := q.strMax("group_key", 8192)
		f.GroupKey = &key
		if f.GroupBy == "" {
			q.fail("group_key requires group_by")
		}
	}
	if f.Sort == "count" && (f.GroupBy == "" || f.GroupKey != nil) {
		q.fail("sort=count requires grouped results")
	}
	if after, ok := q.timeParam("first_seen_after"); ok {
		f.FirstSeenAfter = after
	}
	for _, st := range q.enums("status", in(findingStatuses)) {
		f.Statuses = append(f.Statuses, model.FindingStatus(st))
	}
	if q.reject(w) {
		return
	}
	if f.GroupBy != "" && f.GroupKey == nil {
		groups, total, err := s.d.Store.ListFindingGroups(r.Context(), f)
		if err != nil {
			s.storeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, newList(groups, total, f.Limit, f.Offset))
		return
	}
	items, total, err := s.d.Store.ListFindings(r.Context(), f)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, f.Limit, f.Offset))
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if newQuery(r).reject(w) {
		return
	}
	f, err := s.d.Store.GetFinding(r.Context(), id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// ---- sources, scans, changes ----

func (s *Server) listSources(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r, "limit", "offset")
	limit, offset := q.limit(), q.offset()
	if q.reject(w) {
		return
	}
	all, err := s.d.Store.ListSyncs(r.Context())
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	lo := min(offset, len(all))
	hi := min(lo+limit, len(all))
	writeJSON(w, http.StatusOK, newList(all[lo:hi], len(all), limit, offset))
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r, "limit", "offset")
	limit, offset := q.limit(), q.offset()
	if q.reject(w) {
		return
	}
	// The store paginates by limit only: fetch through the requested window
	// and slice. Total is the number of rows seen within that window.
	rows, err := s.d.Store.ListScans(r.Context(), offset+limit)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	lo := min(offset, len(rows))
	writeJSON(w, http.StatusOK, newList(rows[lo:], len(rows), limit, offset))
}

func (s *Server) changes(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r, "since", "limit")
	limit := q.limit()
	since, ok := q.timeParam("since")
	if q.reject(w) {
		return
	}
	if !ok {
		since = s.clock.Now().Add(-24 * time.Hour)
	}
	evs, err := s.d.Store.ListEvents(r.Context(), since, limit)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(evs, len(evs), limit, 0))
}

// ---- operator actions ----

type actionRequest struct {
	Note  string     `json:"note"`
	Until *time.Time `json:"until"`
}

const maxNote = 2000

var actionStatus = map[string]model.FindingStatus{
	"acknowledge":    model.StatusAcknowledged,
	"suppress":       model.StatusSuppressed,
	"false-positive": model.StatusFalsePositive,
	"reopen":         model.StatusOpen,
}

func (s *Server) findingAction(action string) http.HandlerFunc {
	target := actionStatus[action]
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		if newQuery(r).reject(w) {
			return
		}
		var req actionRequest
		if !decodeBody(w, r, &req) {
			return
		}
		req.Note = strings.TrimSpace(req.Note)
		switch {
		case len(req.Note) > maxNote:
			writeError(w, http.StatusBadRequest, "invalid_body", "note too long")
			return
		case action == "suppress" && req.Note == "":
			writeError(w, http.StatusBadRequest, "invalid_body", "suppress requires a note")
			return
		case req.Until != nil && action != "suppress" && action != "acknowledge":
			writeError(w, http.StatusBadRequest, "invalid_body", "until is only valid for suppress and acknowledge")
			return
		case req.Until != nil && !req.Until.After(s.clock.Now()):
			writeError(w, http.StatusBadRequest, "invalid_body", "until must be in the future")
			return
		}
		ctx := r.Context()
		f, err := s.d.Store.GetFinding(ctx, id)
		if err != nil {
			s.storeError(w, r, err)
			return
		}
		if f.Status == model.StatusResolved {
			writeError(w, http.StatusConflict, "conflict", "finding is resolved")
			return
		}
		actor := identityFrom(ctx).Actor()
		err = s.d.Store.ChangeFindingStatus(ctx, id, store.StatusChange{
			Status: target, Until: req.Until, Note: req.Note, Actor: actor,
		}, s.clock.Now())
		if err != nil {
			s.storeError(w, r, err)
			return
		}
		s.log.Info("finding status changed", "finding_id", id, "action", action, "actor", actor)
		updated, err := s.d.Store.GetFinding(ctx, id)
		if err != nil {
			s.storeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

// decodeBody parses an optional JSON object body strictly.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	dec := newStrictDecoder(r)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, errEmptyBody) {
			return true
		}
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_body", "malformed JSON body")
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid_body", "unexpected trailing data")
		return false
	}
	return true
}

func (s *Server) actionError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotSupported):
		writeError(w, http.StatusNotImplemented, "not_implemented", "action is not available on this instance")
	case errors.Is(err, ErrUnknownSource), errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrBusy):
		writeError(w, http.StatusConflict, "busy", "already in progress")
	case errors.Is(err, ErrNotScannable):
		writeError(w, http.StatusConflict, "not_scannable", "asset has no applicable, in-scope, enabled checks to run")
	default:
		s.storeError(w, r, err)
	}
}

func (s *Server) rescanAsset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if newQuery(r).reject(w) {
		return
	}
	ctx := r.Context()
	a, err := s.d.Store.GetAsset(ctx, id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	if a.RemovedAt != nil {
		writeError(w, http.StatusConflict, "conflict", "asset is removed")
		return
	}
	if err := s.d.Actions.RescanAsset(ctx, id); err != nil {
		s.actionError(w, r, err)
		return
	}
	s.log.Info("rescan requested", "asset_id", id, "actor", identityFrom(ctx).Actor())
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) syncSource(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" || len(name) > maxTextParam {
		writeError(w, http.StatusBadRequest, "invalid_name", "invalid source name")
		return
	}
	if newQuery(r).reject(w) {
		return
	}
	if err := s.d.Actions.TriggerSync(r.Context(), name); err != nil {
		s.actionError(w, r, err)
		return
	}
	s.log.Info("source sync requested", "source", name, "actor", identityFrom(r.Context()).Actor())
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}
