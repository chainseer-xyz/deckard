package ingest

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

var now = time.Date(2026, 10, 3, 7, 0, 0, 0, time.UTC)

func valid() *Request {
	obs := now.Add(-time.Minute)
	return &Request{
		Tool: "prowler", Scope: "aws:123456789012:us-west-2", Complete: true, ObservedAt: &obs,
		Findings: []Finding{{
			Key:   "s3_bucket_public_access:arn:aws:s3:::example",
			Asset: Asset{Kind: model.KindCloudResource, Key: "arn:aws:s3:::example"},
			Title: "S3 bucket allows public access", Description: "The bucket policy grants public read.", Severity: model.SeverityHigh,
			Tags: []string{"prowler", "s3"}, Evidence: map[string]any{"region": "us-west-2"},
		}},
	}
}

func TestValidateAcceptsAValidRequest(t *testing.T) {
	if p := Validate(valid(), Options{Now: now}); len(p) != 0 {
		t.Fatalf("problems: %v", p)
	}
	r := valid()
	r.Findings = []Finding{}
	if p := Validate(r, Options{Now: now}); len(p) != 0 {
		t.Fatalf("empty run rejected: %v", p)
	}
	r = valid()
	r.Findings[0].Asset = Asset{Ref: &AssetRef{Kind: model.KindHostname, Key: "www.example.com"}}
	if p := Validate(r, Options{Now: now}); len(p) != 0 {
		t.Fatalf("ref rejected: %v", p)
	}
}

func TestValidateRejects(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	tests := []struct {
		name   string
		mutate func(r *Request)
		index  int
		want   string
	}{
		{"bad tool", func(r *Request) { r.Tool = "Prowler" }, -1, "tool must match"},
		{"one-char tool", func(r *Request) { r.Tool = "p" }, -1, "tool must match"},
		{"empty scope", func(r *Request) { r.Scope = "" }, -1, "scope is required"},
		{"long scope", func(r *Request) { r.Scope = long(201) }, -1, "scope longer than 200"},
		{"padded scope", func(r *Request) { r.Scope = " aws " }, -1, "whitespace"},
		{"control in scope", func(r *Request) { r.Scope = "a\x00b" }, -1, "control characters"},
		{"no observed_at", func(r *Request) { r.ObservedAt = nil }, -1, "observed_at is required"},
		{"future observed_at", func(r *Request) { f := now.Add(time.Hour); r.ObservedAt = &f }, -1, "in the future"},
		{"missing findings", func(r *Request) { r.Findings = nil }, -1, "findings is required"},
		{"no key", func(r *Request) { r.Findings[0].Key = "" }, 0, "key is required"},
		{"long key", func(r *Request) { r.Findings[0].Key = long(513) }, 0, "key longer"},
		{"duplicate key", func(r *Request) { r.Findings = append(r.Findings, r.Findings[0]) }, 1, "duplicates findings[0]"},
		{"probable kind", func(r *Request) { r.Findings[0].Asset.Kind = model.KindHostname }, 0, "cannot be created by ingest"},
		{"ip kind", func(r *Request) { r.Findings[0].Asset.Kind = model.KindIP }, 0, "cannot be created by ingest"},
		{"no asset", func(r *Request) { r.Findings[0].Asset = Asset{} }, 0, "cannot be created by ingest"},
		{"no asset key", func(r *Request) { r.Findings[0].Asset.Key = "" }, 0, "asset.key"},
		{"ref and kind", func(r *Request) { r.Findings[0].Asset.Ref = &AssetRef{Kind: model.KindHostname, Key: "a"} }, 0, "not both"},
		{"bad ref kind", func(r *Request) { r.Findings[0].Asset = Asset{Ref: &AssetRef{Kind: "repo", Key: "a"}} }, 0, "not an asset kind"},
		{"empty ref key", func(r *Request) { r.Findings[0].Asset = Asset{Ref: &AssetRef{Kind: model.KindHostname}} }, 0, "asset.ref.key"},
		{"no title", func(r *Request) { r.Findings[0].Title = "  " }, 0, "title is required"},
		{"long title", func(r *Request) { r.Findings[0].Title = long(301) }, 0, "title longer"},
		{"newline title", func(r *Request) { r.Findings[0].Title = "a\nb" }, 0, "title must be"},
		{"bad severity", func(r *Request) { r.Findings[0].Severity = "urgent" }, 0, "severity"},
		{"no description", func(r *Request) { r.Findings[0].Description = " " }, 0, "description is required"},
		{"long description", func(r *Request) { r.Findings[0].Description = long(8001) }, 0, "description"},
		{"NUL description", func(r *Request) { r.Findings[0].Description = "a\x00" }, 0, "description"},
		{"long remediation", func(r *Request) { r.Findings[0].Remediation = long(4001) }, 0, "remediation"},
		{"too many tags", func(r *Request) { r.Findings[0].Tags = make([]string, 21) }, 0, "more than 20 tags"},
		{"empty tag", func(r *Request) { r.Findings[0].Tags = []string{""} }, 0, "tags must be"},
		{"big evidence", func(r *Request) { r.Findings[0].Evidence = map[string]any{"x": long(17 << 10)} }, 0, "evidence larger"},
		{"NUL in evidence", func(r *Request) { r.Findings[0].Evidence = map[string]any{"x": []any{"a\x00"}} }, 0, "NUL"},
		{"NUL evidence key", func(r *Request) { r.Findings[0].Evidence = map[string]any{"a\x00": 1} }, 0, "NUL"},
		{"deep evidence", func(r *Request) {
			var v any = "leaf"
			for i := 0; i < 10; i++ {
				v = map[string]any{"n": v}
			}
			r.Findings[0].Evidence = v.(map[string]any)
		}, 0, "nested deeper"},
		{"invalid utf8 title", func(r *Request) { r.Findings[0].Title = "\xff" }, 0, "title must be"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := valid()
			tc.mutate(r)
			p := Validate(r, Options{Now: now})
			for _, x := range p {
				if x.Index == tc.index && strings.Contains(x.Reason, tc.want) {
					return
				}
			}
			t.Fatalf("problems %v lack index %d %q", p, tc.index, tc.want)
		})
	}
}

func TestValidateLimitsFindingsAndProblems(t *testing.T) {
	r := valid()
	r.Findings = make([]Finding, 11)
	p := Validate(r, Options{MaxFindings: 10, Now: now})
	if len(p) != 1 || !strings.Contains(p[0].Reason, "11 findings exceed the limit of 10") {
		t.Fatalf("problems %v", p)
	}
	r.Findings = make([]Finding, MaxFindings+1)
	if p := Validate(r, Options{MaxFindings: 100000}); len(p) != 1 || !strings.Contains(p[0].Reason, "limit of 5000") {
		t.Fatalf("hard cap not applied: %v", p)
	}
	r.Findings = make([]Finding, 500) // every item invalid
	if p := Validate(r, Options{}); len(p) != MaxProblems {
		t.Fatalf("problems = %d, want capped at %d", len(p), MaxProblems)
	}
}

func TestDigestIdentifiesContent(t *testing.T) {
	a, b := valid(), valid()
	if Digest(a) != Digest(b) || Digest(a) == "" {
		t.Fatal("equal requests must have equal digests")
	}
	b.Findings[0].Evidence = map[string]any{"region": "us-west-2"} // same content, new map
	if Digest(a) != Digest(b) {
		t.Fatal("map identity must not matter")
	}
	later := a.ObservedAt.Add(time.Second)
	b.ObservedAt = &later
	if Digest(a) == Digest(b) {
		t.Fatal("another run must have another digest")
	}
	c := valid()
	c.Complete = false
	if Digest(a) == Digest(c) {
		t.Fatal("complete must be part of the digest")
	}
}

func TestDecodeIsStrict(t *testing.T) {
	for _, body := range []string{
		`{"tool":"x","bogus":1}`,
		`{"tool":"x","findings":[{"key":"k","asset":{"kind":"cloud_resource","key":"a","extra":1}}]}`,
		`{"tool":"x"} {"tool":"y"}`,
		`[]`,
		`{"tool":`,
	} {
		if _, err := Decode([]byte(body)); err == nil {
			t.Errorf("Decode(%s) accepted", body)
		}
	}
	r, err := Decode([]byte(`{"tool":"prowler","scope":"s","complete":true,"observed_at":"2026-10-03T07:00:00Z","findings":[]}` + "\n"))
	if err != nil || r.Findings == nil || !r.Complete {
		t.Fatalf("Decode valid: %+v %v", r, err)
	}
}

func TestSummary(t *testing.T) {
	var ps []Rejection
	for i := 0; i < 8; i++ {
		ps = append(ps, Rejection{Index: i, Reason: fmt.Sprintf("r%d", i)})
	}
	got := Summary(append([]Rejection{{Index: -1, Reason: "top"}}, ps...))
	if !strings.HasPrefix(got, "top; findings[0]: r0") || !strings.HasSuffix(got, "and 4 more") {
		t.Fatalf("summary %q", got)
	}
}
