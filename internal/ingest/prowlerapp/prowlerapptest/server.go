// Package prowlerapptest is a fake Prowler App API for tests: the JSON:API
// shapes, filters, pagination links and auth of the real service (Prowler
// 5.22.0), served from in-memory data. It exists so no test needs a network.
package prowlerapptest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Provider is a provider as the fake serves it.
type Provider struct {
	ID, Type, UID string
	Connected     bool
	// OmitConnection serves no connection object at all.
	OmitConnection bool
}

// Scan is a scan of a provider.
type Scan struct {
	ID, ProviderID, State string
	StartedAt             time.Time
	CompletedAt           time.Time // zero: absent
}

// Finding is a finding of a provider's latest completed scan.
type Finding struct {
	ID, UID, ProviderID, ScanID string
	CheckID, CheckTitle         string
	Severity, Status            string
	StatusExtended              string
	Muted                       bool
	Delta                       string
	FirstSeenAt                 string
	Risk, RecText, RecURL       string
	Service, ResourceType       string
	// ResourceIDs are the ids of the resources the finding is about (looked
	// up in Server.Resources); none means a finding without a resource.
	ResourceIDs []string
	// OmitResourcesRel serves the finding without a resources relationship.
	OmitResourcesRel bool
	// RawAttrs are merged into the attributes (to plant extra or odd fields).
	RawAttrs map[string]any
}

// Resource is a resource of a provider.
type Resource struct {
	ID, UID, Name, Region, Service, Type string
}

// Reply is what an Intercept hook answers instead of the normal handler.
type Reply struct {
	Status int
	Header map[string]string
	Body   string
}

// Server is the fake. Set the fields before the first request.
type Server struct {
	*httptest.Server

	Providers []Provider
	Scans     []Scan
	Findings  []Finding
	Resources []Resource

	// APIKey is accepted as "Api-Key <APIKey>". Email and Password are
	// accepted by /tokens, which answers JWT; the JWT is accepted as Bearer.
	APIKey, Email, Password string
	JWT                     string
	// PageSize is the largest page served (the server clamps page[size]).
	PageSize int
	// RejectSparse answers 400 to requests with fields[...] parameters.
	RejectSparse bool
	// IgnoreFilters makes /findings/latest return every finding of the
	// provider, whatever status, muted or severity was asked for.
	IgnoreFilters bool
	// EchoCredentials puts the Authorization header into error details, the
	// way a careless server might.
	EchoCredentials bool
	// Intercept, if set, is consulted first: n counts the requests so far to
	// the same path (1-based). A nil result lets the normal handler run.
	Intercept func(r *http.Request, n int) *Reply
	// CountDelta is added to the announced meta.pagination.count (a server
	// whose count disagrees with its pages).
	CountDelta int
	// ShiftPages serves page n's items for page n+1 (the result set shifting
	// while a client pages through it), so items repeat.
	ShiftPages bool
	// PlantSecrets adds raw_result and resource tags carrying sentinel values.
	PlantSecrets bool

	mu       sync.Mutex
	counts   map[string]int
	requests []string
	headers  []http.Header
}

// Sentinels planted when PlantSecrets is set; they must never reach a request.
// #nosec G101 -- fake values that exist to be detected if they leak
const (
	SecretRaw  = "PLANTED-RAW-RESULT-SECRET"
	SecretTag  = "PLANTED-RESOURCE-TAG-SECRET"
	SecretMeta = "PLANTED-RESOURCE-DETAILS-SECRET"
)

// New starts a fake with defaults (page size 2, JWT "jwt-access-token").
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{PageSize: 2, JWT: "jwt-access-token", counts: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

type data struct {
	Providers []Provider
	Scans     []Scan
	Findings  []Finding
	Resources []Resource
}

// data snapshots the mutable data (handlers run on their own goroutines).
func (s *Server) data() data {
	s.mu.Lock()
	defer s.mu.Unlock()
	return data{
		Providers: append([]Provider(nil), s.Providers...), Scans: append([]Scan(nil), s.Scans...),
		Findings: append([]Finding(nil), s.Findings...), Resources: append([]Resource(nil), s.Resources...),
	}
}

// Mutate changes the served data safely while the server is running, for
// example to complete a new scan in the middle of a run.
func (s *Server) Mutate(fn func(s *Server)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// Requests returns "METHOD path?query" of every request served, in order.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// Headers returns the headers of every request served, in order.
func (s *Server) Headers() []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]http.Header(nil), s.headers...)
}

// Count is how many requests reached a path (for example /api/v1/scans).
func (s *Server) Count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[path]
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.counts[r.URL.Path]++
	n := s.counts[r.URL.Path]
	s.requests = append(s.requests, r.Method+" "+r.URL.RequestURI())
	s.headers = append(s.headers, r.Header.Clone())
	s.mu.Unlock()

	if s.Intercept != nil {
		if rep := s.Intercept(r, n); rep != nil {
			for k, v := range rep.Header {
				w.Header().Set(k, v)
			}
			if w.Header().Get("Content-Type") == "" {
				w.Header().Set("Content-Type", "application/vnd.api+json")
			}
			w.WriteHeader(rep.Status)
			_, _ = w.Write([]byte(rep.Body))
			return
		}
	}
	if r.URL.Path == "/api/v1/tokens" && r.Method == http.MethodPost {
		s.tokens(w, r)
		return
	}
	if !s.authorised(r) {
		detail := "Invalid or missing credentials."
		if s.EchoCredentials {
			detail = "Invalid credentials: " + r.Header.Get("Authorization")
		}
		s.errorDoc(w, 401, "authentication_failed", detail)
		return
	}
	if r.Method != http.MethodGet {
		s.errorDoc(w, 405, "method_not_allowed", "read-only fake")
		return
	}
	if s.RejectSparse {
		for k := range r.URL.Query() {
			if strings.HasPrefix(k, "fields[") {
				s.errorDoc(w, 400, "invalid", "unsupported sparse fieldset")
				return
			}
		}
	}
	switch r.URL.Path {
	case "/api/v1/providers":
		s.providers(w, r)
	case "/api/v1/scans":
		s.scans(w, r)
	case "/api/v1/findings/latest":
		s.findings(w, r)
	default:
		s.errorDoc(w, 404, "not_found", "no such endpoint")
	}
}

func (s *Server) authorised(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	switch {
	case s.APIKey != "" && h == "Api-Key "+s.APIKey:
		return true
	case s.JWT != "" && s.Email != "" && h == "Bearer "+s.JWT:
		return true
	}
	return false
}

func (s *Server) errorDoc(w http.ResponseWriter, status int, code, detail string) {
	s.writeJSON(w, status, map[string]any{"errors": []map[string]any{{"status": strconv.Itoa(status), "code": code, "detail": detail}}})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) tokens(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Data.Type != "tokens" ||
		s.Email == "" || in.Data.Attributes.Email != s.Email || in.Data.Attributes.Password != s.Password {
		s.errorDoc(w, 401, "authentication_failed", "No active account found with the given credentials")
		return
	}
	s.writeJSON(w, 200, map[string]any{"data": map[string]any{
		"type": "tokens", "id": nil,
		"attributes": map[string]any{"access": s.JWT, "refresh": "jwt-refresh-token"},
	}})
}

// page slices items for the request's page[number] and page[size], returning
// the slice and the pagination links and meta.
func (s *Server) page(r *http.Request, total int) (lo, hi int, links, meta map[string]any) {
	q := r.URL.Query()
	size, _ := strconv.Atoi(q.Get("page[size]"))
	if size <= 0 || size > s.PageSize {
		size = s.PageSize
	}
	num, _ := strconv.Atoi(q.Get("page[number]"))
	if num <= 0 {
		num = 1
	}
	pages := (total + size - 1) / size
	served := num
	if s.ShiftPages && num > 1 {
		served = num - 1
	}
	lo = min((served-1)*size, total)
	hi = min(lo+size, total)
	link := func(n int) any {
		v := url.Values{}
		for k, vs := range q {
			v[k] = vs
		}
		v.Set("page[number]", strconv.Itoa(n))
		return fmt.Sprintf("http://%s%s?%s", r.Host, r.URL.Path, v.Encode())
	}
	links = map[string]any{"first": link(1), "last": link(max(pages, 1)), "next": nil, "prev": nil}
	if num < pages {
		links["next"] = link(num + 1)
	}
	if num > 1 {
		links["prev"] = link(num - 1)
	}
	meta = map[string]any{"pagination": map[string]any{"page": num, "pages": pages, "count": total + s.CountDelta}}
	return lo, hi, links, meta
}

func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	d := s.data()
	lo, hi, links, meta := s.page(r, len(d.Providers))
	data := []map[string]any{}
	for _, p := range d.Providers[lo:hi] {
		attrs := map[string]any{"provider": p.Type, "uid": p.UID, "alias": nil}
		if !p.OmitConnection {
			attrs["connection"] = map[string]any{"connected": p.Connected, "last_checked_at": "2026-10-03T06:00:00Z"}
		}
		data = append(data, map[string]any{"type": "providers", "id": p.ID, "attributes": attrs})
	}
	s.writeJSON(w, 200, map[string]any{"data": data, "links": links, "meta": meta})
}

func (s *Server) scans(w http.ResponseWriter, r *http.Request) {
	d := s.data()
	prov := r.URL.Query().Get("filter[provider]")
	var scans []Scan
	for _, sc := range d.Scans {
		if prov == "" || sc.ProviderID == prov {
			scans = append(scans, sc)
		}
	}
	sort.SliceStable(scans, func(i, j int) bool { return scans[i].StartedAt.After(scans[j].StartedAt) })
	lo, hi, links, meta := s.page(r, len(scans))
	data := []map[string]any{}
	for _, sc := range scans[lo:hi] {
		attrs := map[string]any{"name": "scan", "trigger": "scheduled", "state": sc.State,
			"inserted_at": sc.StartedAt.Format(time.RFC3339Nano), "started_at": nil, "completed_at": nil}
		if !sc.StartedAt.IsZero() && sc.State != "scheduled" && sc.State != "available" {
			attrs["started_at"] = sc.StartedAt.Format(time.RFC3339Nano)
		}
		if !sc.CompletedAt.IsZero() {
			attrs["completed_at"] = sc.CompletedAt.Format(time.RFC3339Nano)
		}
		data = append(data, map[string]any{"type": "scans", "id": sc.ID, "attributes": attrs,
			"relationships": map[string]any{"provider": map[string]any{"data": map[string]any{"type": "providers", "id": sc.ProviderID}}}})
	}
	s.writeJSON(w, 200, map[string]any{"data": data, "links": links, "meta": meta})
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	d := s.data()
	q := r.URL.Query()
	prov := q.Get("filter[provider]")
	sevs := map[string]bool{}
	for _, v := range strings.Split(q.Get("filter[severity__in]"), ",") {
		if v != "" {
			sevs[v] = true
		}
	}
	var fs []Finding
	for _, f := range d.Findings {
		switch {
		case prov != "" && f.ProviderID != prov:
			continue
		case !s.IgnoreFilters && q.Get("filter[status]") != "" && f.Status != q.Get("filter[status]"):
			continue
		case !s.IgnoreFilters && q.Get("filter[muted]") == "false" && f.Muted:
			continue
		case !s.IgnoreFilters && len(sevs) > 0 && !sevs[f.Severity]:
			continue
		}
		fs = append(fs, f)
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].CheckID != fs[j].CheckID {
			return fs[i].CheckID < fs[j].CheckID
		}
		return fs[i].ID < fs[j].ID
	})
	lo, hi, links, meta := s.page(r, len(fs))
	byID := map[string]Resource{}
	for _, res := range d.Resources {
		byID[res.ID] = res
	}
	include := strings.Contains(q.Get("include"), "resources")
	data := []map[string]any{}
	included := []map[string]any{}
	seen := map[string]bool{}
	for _, f := range fs[lo:hi] {
		md := map[string]any{"provider": "x", "checkid": f.CheckID, "checktitle": f.CheckTitle, "servicename": f.Service,
			"resourcetype": f.ResourceType, "severity": f.Severity, "risk": f.Risk,
			"remediation": map[string]any{"recommendation": map[string]any{"text": f.RecText, "url": f.RecURL}, "code": map[string]any{"cli": "aws s3api ..."}}}
		attrs := map[string]any{"uid": f.UID, "delta": nilIfEmpty(f.Delta), "status": f.Status, "status_extended": f.StatusExtended,
			"severity": f.Severity, "check_id": f.CheckID, "check_metadata": md, "muted": f.Muted,
			"first_seen_at": nilIfEmpty(f.FirstSeenAt), "inserted_at": "2026-10-03T06:00:00Z", "raw_result": map[string]any{}}
		if s.PlantSecrets {
			attrs["raw_result"] = map[string]any{"password": SecretRaw}
		}
		for k, v := range f.RawAttrs {
			attrs[k] = v
		}
		rels := map[string]any{"scan": map[string]any{"data": map[string]any{"type": "scans", "id": f.ScanID}}}
		if !f.OmitResourcesRel {
			refs := []map[string]any{}
			for _, id := range f.ResourceIDs {
				refs = append(refs, map[string]any{"type": "resources", "id": id})
				if res, ok := byID[id]; ok && include && !seen[id] {
					seen[id] = true
					rattrs := map[string]any{"uid": res.UID, "name": res.Name, "region": res.Region, "service": res.Service, "type": res.Type,
						"tags": map[string]any{}, "details": "", "metadata": ""}
					if s.PlantSecrets {
						rattrs["tags"] = map[string]any{"secret": SecretTag}
						rattrs["details"], rattrs["metadata"] = SecretMeta, SecretMeta
					}
					included = append(included, map[string]any{"type": "resources", "id": id, "attributes": rattrs})
				}
			}
			rels["resources"] = map[string]any{"data": refs, "meta": map[string]any{"count": len(refs)}}
		}
		data = append(data, map[string]any{"type": "findings", "id": f.ID, "attributes": attrs, "relationships": rels})
	}
	doc := map[string]any{"data": data, "links": links, "meta": meta}
	if include && len(included) > 0 {
		doc["included"] = included
	}
	s.writeJSON(w, 200, doc)
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
