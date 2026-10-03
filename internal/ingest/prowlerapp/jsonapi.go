// Package prowlerapp pulls scan results from a running Prowler App (its REST
// API, a JSON:API service) and turns them into ingest requests, one per
// provider. Prowler keeps scanning; deckard only reads what Prowler already
// found, and only ever claims a run is complete when it can prove it.
//
// This file is the JSON:API decoder. It is deliberately forgiving about what
// it does not need (unknown members are ignored, every attribute is optional)
// and strict about what it does: a malformed document is an error, never a
// guess, and nothing here panics on hostile input (see the fuzz test).
package prowlerapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Document is a decoded JSON:API response. Data is always a list: a document
// whose primary data is a single object (the token endpoint) has one entry.
type Document struct {
	Data     []Resource
	Included []Resource
	Links    Links
	Meta     Meta
	Errors   []APIError
}

// Links are the pagination links of a list response.
type Links struct {
	Next string
}

// Meta is the part of the response metadata the client cross-checks.
type Meta struct {
	// Count is meta.pagination.count, the total number of primary items, or -1
	// when the server did not say.
	Count int
}

// APIError is one entry of a JSON:API error document.
type APIError struct {
	Status string
	Code   string
	Detail string
}

// Resource is a JSON:API resource object. Attributes stay raw so that one
// malformed item does not fail the whole page.
type Resource struct {
	Type          string
	ID            string
	Attributes    json.RawMessage
	Relationships map[string]Relationship
}

// Ref is a resource identifier object.
type Ref struct {
	Type string
	ID   string
}

// Relationship is the linkage of a resource. Known reports whether the server
// gave linkage at all (a relationship with only links is unknown, an empty
// list is a known absence).
type Relationship struct {
	Known bool
	Refs  []Ref
}

// Decode parses one response body.
func Decode(body []byte) (*Document, error) {
	var raw struct {
		Data     json.RawMessage `json:"data"`
		Included json.RawMessage `json:"included"`
		Links    json.RawMessage `json:"links"`
		Meta     json.RawMessage `json:"meta"`
		Errors   json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", jsonErr(err))
	}
	doc := &Document{Meta: Meta{Count: -1}}
	var err error
	if doc.Data, err = decodeResources(raw.Data); err != nil {
		return nil, fmt.Errorf("data: %w", err)
	}
	if doc.Included, err = decodeResources(raw.Included); err != nil {
		return nil, fmt.Errorf("included: %w", err)
	}
	if len(raw.Links) > 0 {
		var l struct {
			Next *string `json:"next"`
		}
		if err := json.Unmarshal(raw.Links, &l); err == nil && l.Next != nil {
			doc.Links.Next = strings.TrimSpace(*l.Next)
		}
	}
	if len(raw.Meta) > 0 {
		var m struct {
			Pagination struct {
				Count *int `json:"count"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(raw.Meta, &m); err == nil && m.Pagination.Count != nil && *m.Pagination.Count >= 0 {
			doc.Meta.Count = *m.Pagination.Count
		}
	}
	if len(raw.Errors) > 0 {
		var es []struct {
			Status string `json:"status"`
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(raw.Errors, &es); err == nil {
			for _, e := range es {
				doc.Errors = append(doc.Errors, APIError{Status: e.Status, Code: e.Code, Detail: e.Detail})
			}
		}
	}
	return doc, nil
}

// decodeResources accepts null or absent (no resources), one object or a list.
func decodeResources(raw json.RawMessage) ([]Resource, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var items []json.RawMessage
	switch raw[0] {
	case '[':
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, jsonErr(err)
		}
	case '{':
		items = []json.RawMessage{raw}
	default:
		return nil, fmt.Errorf("expected an object or a list")
	}
	out := make([]Resource, 0, len(items))
	for i, it := range items {
		r, err := decodeResource(it)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func decodeResource(raw json.RawMessage) (Resource, error) {
	var r struct {
		Type          string                     `json:"type"`
		ID            string                     `json:"id"`
		Attributes    json.RawMessage            `json:"attributes"`
		Relationships map[string]json.RawMessage `json:"relationships"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return Resource{}, jsonErr(err)
	}
	out := Resource{Type: r.Type, ID: r.ID, Attributes: r.Attributes}
	if len(r.Relationships) > 0 {
		out.Relationships = make(map[string]Relationship, len(r.Relationships))
		for name, rel := range r.Relationships {
			out.Relationships[name] = decodeRelationship(rel)
		}
	}
	return out, nil
}

// decodeRelationship never fails: linkage it cannot read is unknown.
func decodeRelationship(raw json.RawMessage) Relationship {
	var rel struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &rel) != nil {
		return Relationship{}
	}
	data := bytes.TrimSpace(rel.Data)
	switch {
	case len(data) == 0:
		return Relationship{}
	case bytes.Equal(data, []byte("null")):
		return Relationship{Known: true}
	}
	var refs []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	if data[0] == '{' {
		var one struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if json.Unmarshal(data, &one) != nil {
			return Relationship{}
		}
		refs = append(refs, one)
	} else if json.Unmarshal(data, &refs) != nil {
		return Relationship{}
	}
	out := Relationship{Known: true}
	for _, r := range refs {
		out.Refs = append(out.Refs, Ref{Type: r.Type, ID: r.ID})
	}
	return out
}

// jsonErr drops the offending input from a decoding error: encoding/json
// errors can quote a value, and a response body may carry sensitive data.
func jsonErr(err error) error {
	var typeErr *json.UnmarshalTypeError
	var syntaxErr *json.SyntaxError
	switch {
	case errors.As(err, &typeErr):
		return fmt.Errorf("unexpected JSON type for %q at offset %d", typeErr.Field, typeErr.Offset)
	case errors.As(err, &syntaxErr):
		return fmt.Errorf("invalid JSON at offset %d", syntaxErr.Offset)
	}
	return fmt.Errorf("invalid JSON")
}

// Index finds resources of Included by (type, id).
type Index map[Ref]Resource

// IndexIncluded builds the lookup of a document's included resources.
func (d *Document) IndexIncluded() Index {
	ix := make(Index, len(d.Included))
	for _, r := range d.Included {
		ix[Ref{Type: r.Type, ID: r.ID}] = r
	}
	return ix
}

// Provider is a cloud, cluster or organisation Prowler scans.
type Provider struct {
	ID   string
	Type string // aws, gcp, azure, github, kubernetes, ...
	UID  string // account id, project id, subscription id, organisation, cluster name
	// Connected is true only when Prowler reports connection.connected = true.
	Connected bool
}

// Scan is one scan of a provider.
type Scan struct {
	ID          string
	State       string
	CompletedAt time.Time // zero when absent or unparseable
	// Sort is the instant used to order scans newest first: the start, else
	// the creation time.
	Sort time.Time
}

// AsProvider decodes a provider resource.
func AsProvider(r Resource) (Provider, error) {
	var a struct {
		Provider   string `json:"provider"`
		UID        string `json:"uid"`
		Connection *struct {
			Connected *bool `json:"connected"`
		} `json:"connection"`
	}
	if err := decodeAttrs(r, &a); err != nil {
		return Provider{}, err
	}
	p := Provider{ID: r.ID, Type: strings.ToLower(strings.TrimSpace(a.Provider)), UID: strings.TrimSpace(a.UID)}
	if a.Connection != nil && a.Connection.Connected != nil {
		p.Connected = *a.Connection.Connected
	}
	if p.ID == "" || p.Type == "" || p.UID == "" {
		return Provider{}, fmt.Errorf("provider without id, type or uid")
	}
	return p, nil
}

// AsScan decodes a scan resource.
func AsScan(r Resource) (Scan, error) {
	var a struct {
		State       string  `json:"state"`
		InsertedAt  *string `json:"inserted_at"`
		StartedAt   *string `json:"started_at"`
		CompletedAt *string `json:"completed_at"`
	}
	if err := decodeAttrs(r, &a); err != nil {
		return Scan{}, err
	}
	s := Scan{ID: r.ID, State: strings.ToLower(strings.TrimSpace(a.State))}
	if s.ID == "" {
		return Scan{}, fmt.Errorf("scan without id")
	}
	s.CompletedAt = parseTime(a.CompletedAt)
	if s.Sort = parseTime(a.StartedAt); s.Sort.IsZero() {
		s.Sort = parseTime(a.InsertedAt)
	}
	return s, nil
}

// RawFinding is a finding as Prowler reported it, reduced to the fields the
// mapper may use. raw_result, tags and resource details are never decoded.
type RawFinding struct {
	ID             string
	UID            string
	Status         string
	StatusExtended string
	Severity       string
	CheckID        string
	Delta          string
	FirstSeenAt    string
	Muted          bool
	// CheckMetadata is Prowler's metadata for the check, with keys lowercased
	// and stripped of underscores (checktitle, servicename, ...).
	CheckMetadata map[string]any
	// Scan is the scan relationship, when the server gave one.
	Scan Relationship
	// Resources is the resources relationship.
	Resources Relationship
}

// RawResource is the allow-listed part of a resource.
type RawResource struct {
	ID      string
	UID     string
	Name    string
	Region  string
	Service string
	Type    string
}

// AsFinding decodes a finding resource.
func AsFinding(r Resource) (RawFinding, error) {
	var a struct {
		UID            string          `json:"uid"`
		Status         string          `json:"status"`
		StatusExtended string          `json:"status_extended"`
		Severity       string          `json:"severity"`
		CheckID        string          `json:"check_id"`
		Delta          *string         `json:"delta"`
		FirstSeenAt    *string         `json:"first_seen_at"`
		Muted          *bool           `json:"muted"`
		CheckMetadata  json.RawMessage `json:"check_metadata"`
	}
	if err := decodeAttrs(r, &a); err != nil {
		return RawFinding{}, err
	}
	f := RawFinding{
		ID: r.ID, UID: a.UID, Status: strings.ToUpper(strings.TrimSpace(a.Status)), StatusExtended: a.StatusExtended,
		Severity: a.Severity, CheckID: strings.TrimSpace(a.CheckID),
		Scan: r.Relationships["scan"], Resources: r.Relationships["resources"],
	}
	if a.Delta != nil {
		f.Delta = *a.Delta
	}
	if a.FirstSeenAt != nil {
		f.FirstSeenAt = *a.FirstSeenAt
	}
	// Only an explicit true is muted: the query already excludes muted
	// findings, and a missing flag must not make findings vanish silently.
	f.Muted = a.Muted != nil && *a.Muted
	if md := bytes.TrimSpace(a.CheckMetadata); len(md) > 0 && md[0] == '{' {
		var m map[string]any
		if err := json.Unmarshal(md, &m); err == nil {
			f.CheckMetadata = normKeys(m, 0).(map[string]any)
		}
	}
	return f, nil
}

// AsResource decodes a resource resource, keeping only the allow-listed
// attributes (never tags, details or metadata).
func AsResource(r Resource) (RawResource, error) {
	var a struct {
		UID     string `json:"uid"`
		Name    string `json:"name"`
		Region  string `json:"region"`
		Service string `json:"service"`
		Type    string `json:"type"`
	}
	if err := decodeAttrs(r, &a); err != nil {
		return RawResource{}, err
	}
	return RawResource{ID: r.ID, UID: a.UID, Name: a.Name, Region: a.Region, Service: a.Service, Type: a.Type}, nil
}

func decodeAttrs(r Resource, into any) error {
	attrs := bytes.TrimSpace(r.Attributes)
	if len(attrs) == 0 || bytes.Equal(attrs, []byte("null")) {
		return nil
	}
	if err := json.Unmarshal(attrs, into); err != nil {
		return fmt.Errorf("%s %q attributes: %w", r.Type, r.ID, jsonErr(err))
	}
	return nil
}

// normKeys lowercases map keys and strips underscores and dashes, to the
// depth Prowler's check metadata uses, so CheckTitle, check_title and
// checktitle read the same.
func normKeys(v any, depth int) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			k = strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(k))
			if depth < 6 {
				e = normKeys(e, depth+1)
			}
			if _, dup := out[k]; !dup {
				out[k] = e
			}
		}
		return out
	}
	return v
}

func parseTime(s *string) time.Time {
	if s == nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
