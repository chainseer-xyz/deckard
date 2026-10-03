package prowlerapp

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const (
	seedFindings = `{"data":[{"type":"findings","id":"f1","attributes":{"uid":"u1","status":"FAIL","status_extended":"public","severity":"high","check_id":"s3_public","delta":"new","first_seen_at":"2026-10-01T00:00:00Z","muted":false,"raw_result":{"k":"v"},"check_metadata":{"checktitle":"T","servicename":"s3","risk":"R","remediation":{"recommendation":{"text":"fix","url":"https://docs.example.com"}}}},"relationships":{"scan":{"data":{"type":"scans","id":"s1"}},"resources":{"data":[{"type":"resources","id":"r1"}]}}}],"included":[{"type":"resources","id":"r1","attributes":{"uid":"arn:aws:s3:::b","name":"b","region":"us-east-1","service":"s3","type":"AwsS3Bucket","tags":{"a":"b"}}}],"links":{"next":"http://h/api/v1/findings/latest?page%5Bnumber%5D=2"},"meta":{"pagination":{"page":1,"pages":2,"count":2}}}`
	seedProvider = `{"data":[{"type":"providers","id":"p1","attributes":{"provider":"aws","uid":"123456789012","connection":{"connected":true,"last_checked_at":"2026-10-03T00:00:00Z"}}}]}`
	seedScan     = `{"data":[{"type":"scans","id":"s1","attributes":{"state":"completed","inserted_at":"2026-10-03T05:00:00Z","started_at":"2026-10-03T05:01:00Z","completed_at":"2026-10-03T06:00:00Z"}}]}`
	seedToken    = `{"data":{"type":"tokens","id":null,"attributes":{"access":"a","refresh":"r"}}}`
	seedErrors   = `{"errors":[{"status":"401","code":"authentication_failed","detail":"bad"}]}`
)

// FuzzDecode feeds arbitrary bytes through the decoder, the typed accessors and
// the mapper: nothing may panic, and whatever maps must make a valid request.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{seedFindings, seedProvider, seedScan, seedToken, seedErrors,
		`{}`, `[]`, `null`, `{"data":null}`, `{"data":[{}]}`, `{"data":[{"type":"findings","relationships":{"resources":{"data":[null]}}}]}`,
		`{"data":{"type":"findings","id":"x","attributes":{"check_metadata":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{}}}}}}}}}}}`} {
		f.Add([]byte(s))
	}
	provider := Provider{ID: "p", Type: "aws", UID: "123456789012", Connected: true}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := Decode(data)
		if err != nil {
			return
		}
		_ = doc.Links.Next
		ix := doc.IndexIncluded()
		mc := MapContext{Provider: provider, ScanID: "s", Resource: func(r Ref) (RawResource, bool) {
			res, ok := ix[r]
			if !ok {
				return RawResource{}, false
			}
			rr, err := AsResource(res)
			return rr, err == nil
		}}
		var mapped []ingest.Finding
		for _, r := range append(append([]Resource(nil), doc.Data...), doc.Included...) {
			_, _ = AsProvider(r)
			_, _ = AsScan(r)
			rf, err := AsFinding(r)
			if err != nil || !Wanted(rf, model.SeverityInfo, true) {
				continue
			}
			mapped = append(mapped, MapFinding(mc, rf).Findings...)
		}
		out, _ := Merge(mapped)
		obs := time.Date(2026, 10, 3, 7, 0, 0, 0, time.UTC)
		req := &ingest.Request{Tool: Tool, Scope: Scope(provider), Complete: true, ObservedAt: &obs, Findings: append([]ingest.Finding{}, out...)}
		if p := ingest.Validate(req, ingest.Options{MaxFindings: 1 << 30}); len(p) > 0 {
			t.Fatalf("mapped findings are not a valid request: %s", ingest.Summary(p))
		}
	})
}

// FuzzScope: whatever a provider is called, its scope is a valid ingest scope.
func FuzzScope(f *testing.F) {
	f.Add("aws", "123456789012")
	f.Add("", "")
	f.Add("g\x00cp", strings.Repeat("é", 300))
	f.Fuzz(func(t *testing.T, typ, uid string) {
		req := &ingest.Request{Tool: Tool, Scope: Scope(Provider{Type: typ, UID: uid}), Findings: []ingest.Finding{}}
		obs := time.Now()
		req.ObservedAt = &obs
		for _, p := range ingest.Validate(req, ingest.Options{}) {
			if strings.Contains(p.Reason, "scope") {
				t.Fatalf("scope %q: %s", req.Scope, p.Reason)
			}
		}
	})
}

// FuzzNextURL: a links.next value can only ever lead to the configured origin,
// under the API root.
func FuzzNextURL(f *testing.F) {
	for _, s := range []string{"http://h/api/v1/findings/latest?page%5Bnumber%5D=2", "https://evil.example.net/api/v1/x", "/api/v1/x", "//evil/api/v1/x", "http://h/admin", "", "%zz", "http://u:p@evil/api/v1/x"} {
		f.Add(s)
	}
	c, err := NewClient(Config{BaseURL: "https://prowler.example.com", APIKey: "k"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := c.nextURL(raw)
		if err != nil {
			return
		}
		if u.Scheme != "https" || u.Host != "prowler.example.com" || u.User != nil || !strings.HasPrefix(u.Path, "/api/v1/") {
			t.Fatalf("%q led to %s", raw, u)
		}
		if _, err := url.Parse(u.String()); err != nil {
			t.Fatal(err)
		}
	})
}
