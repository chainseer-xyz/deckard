package prowlerapp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/ingesttest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

var awsProvider = Provider{ID: "p1", Type: "aws", UID: "123456789012", Connected: true}

func ctxWith(res ...RawResource) MapContext {
	return MapContext{Provider: awsProvider, ScanID: "scan-1", Resource: func(r Ref) (RawResource, bool) {
		for _, x := range res {
			if x.ID == r.ID {
				return x, true
			}
		}
		return RawResource{}, false
	}}
}

func rel(ids ...string) Relationship {
	r := Relationship{Known: true}
	for _, id := range ids {
		r.Refs = append(r.Refs, Ref{Type: "resources", ID: id})
	}
	return r
}

func baseFinding() RawFinding {
	return RawFinding{
		ID: "f1", UID: "prowler-aws-s3_bucket_public_access-123456789012-us-east-1-b", Status: "FAIL",
		StatusExtended: "S3 Bucket b allows public access.", Severity: "high", CheckID: "s3_bucket_public_access",
		Delta: "new", FirstSeenAt: "2026-10-01T00:00:00Z", Resources: rel("r1"),
		CheckMetadata: map[string]any{
			"checktitle": "Ensure S3 buckets are not public", "servicename": "s3", "resourcetype": "AwsS3Bucket",
			"risk": "Public buckets leak data.", "severity": "high",
			"remediation": map[string]any{"recommendation": map[string]any{"text": "Enable Block Public Access.", "url": "https://docs.example.com/s3?token=SECRET#frag"}},
		},
	}
}

var bucket = RawResource{ID: "r1", UID: "arn:aws:s3:::b", Name: "b", Region: "us-east-1", Service: "s3", Type: "AwsS3Bucket"}

func TestMapFindingFullMapping(t *testing.T) {
	m := MapFinding(ctxWith(bucket), baseFinding())
	if m.Incomplete != "" || len(m.Findings) != 1 {
		t.Fatalf("%+v", m)
	}
	got := ingest.Normalize(m.Findings[0])
	want := ingest.Finding{
		Key:         "s3_bucket_public_access:arn:aws:s3:::b",
		Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: "arn:aws:s3:::b"},
		Title:       "Ensure S3 buckets are not public",
		Description: "S3 Bucket b allows public access.\n\nRisk: Public buckets leak data.",
		Severity:    model.SeverityHigh,
		Remediation: "Enable Block Public Access.\n\nReference: https://docs.example.com/s3",
		Tags:        []string{"aws", "s3", "us-east-1", "s3_bucket_public_access", "prowler"},
		Evidence: map[string]any{"region": "us-east-1", "service": "s3", "resource_type": "AwsS3Bucket",
			"scan_id": "scan-1", "first_seen_at": "2026-10-01T00:00:00Z", "delta": "new"},
	}
	if !reflect.DeepEqual(got, want) {
		gj, _ := json.MarshalIndent(got, "", " ")
		wj, _ := json.MarshalIndent(want, "", " ")
		t.Fatalf("got\n%s\nwant\n%s", gj, wj)
	}
	ingesttest.Valid(t, Tool, []ingest.Finding{got})
}

func TestMapFindingFallbacks(t *testing.T) {
	f := baseFinding()
	f.CheckMetadata = nil
	f.StatusExtended = ""
	f.Severity = ""
	f.CheckID = ""
	f.Resources = rel()
	// No check id anywhere: the finding cannot be keyed.
	if m := MapFinding(ctxWith(), f); len(m.Findings) != 0 || !strings.Contains(m.Incomplete, "no check id") {
		t.Fatalf("%+v", m)
	}
	f.CheckMetadata = map[string]any{"checkid": "iam_root_mfa", "severity": "critical"}
	m := MapFinding(ctxWith(), f)
	if m.Incomplete != "" || len(m.Findings) != 1 {
		t.Fatalf("%+v", m)
	}
	g := ingest.Normalize(m.Findings[0])
	if g.Title != "iam_root_mfa" || g.Description != "iam_root_mfa" || g.Severity != model.SeverityCritical {
		t.Fatalf("title/description/severity fall back to the check id: %+v", g)
	}
	// A finding about no resource is keyed on a stable synthesized id.
	if g.Key != "iam_root_mfa:prowler:aws:123456789012:"+f.UID || g.Asset.Key != "prowler:aws:123456789012:"+f.UID {
		t.Fatalf("synthesized key %q asset %q", g.Key, g.Asset.Key)
	}
	again := ingest.Normalize(MapFinding(ctxWith(), f).Findings[0])
	if again.Key != g.Key {
		t.Fatal("synthesized id is not stable")
	}
	f.UID = ""
	if g := ingest.Normalize(MapFinding(ctxWith(), f).Findings[0]); g.Asset.Key != "prowler:aws:123456789012:iam_root_mfa" {
		t.Fatalf("no finding uid: %q", g.Asset.Key)
	}
}

func TestMapFindingDoubtfulLinkageIsFlagged(t *testing.T) {
	f := baseFinding()
	f.Resources = Relationship{} // the server gave no linkage
	m := MapFinding(ctxWith(), f)
	if len(m.Findings) != 1 || !strings.Contains(m.Incomplete, "no resources relationship") {
		t.Fatalf("a finding with unknown linkage is posted, but forbids a complete run: %+v", m)
	}
	f.Resources = rel("missing")
	m = MapFinding(ctxWith(bucket), f)
	if len(m.Findings) != 0 || !strings.Contains(m.Incomplete, "missing from the response") {
		t.Fatalf("a reference with no included resource is dropped and flagged: %+v", m)
	}
	f.Resources = rel("r1", "missing")
	m = MapFinding(ctxWith(bucket), f)
	if len(m.Findings) != 1 || m.Incomplete == "" {
		t.Fatalf("the resolvable resource still maps: %+v", m)
	}
}

func TestMapFindingOneFindingPerResource(t *testing.T) {
	f := baseFinding()
	f.Resources = rel("r1", "r2")
	m := MapFinding(ctxWith(bucket, RawResource{ID: "r2", UID: "arn:aws:s3:::c", Region: "eu-west-1"}), f)
	if m.Incomplete != "" || len(m.Findings) != 2 || m.Findings[0].Key == m.Findings[1].Key {
		t.Fatalf("%+v", m)
	}
}

func TestMapFindingResourceNameFallsBackWhenNoUID(t *testing.T) {
	f := baseFinding()
	m := MapFinding(ctxWith(RawResource{ID: "r1", Name: "my-bucket"}), f)
	if g := m.Findings[0]; m.Incomplete != "" || g.Asset.Key != "my-bucket" {
		t.Fatalf("%+v", m)
	}
}

func TestMapFindingCheckMetadataCasingVariants(t *testing.T) {
	for _, raw := range []string{
		`{"CheckTitle":"T","ServiceName":"s3","Risk":"R","Remediation":{"Recommendation":{"Text":"fix","Url":"https://x.example.com/d"}}}`,
		`{"check_title":"T","service_name":"s3","risk":"R","remediation":{"recommendation":{"text":"fix","url":"https://x.example.com/d"}}}`,
		`{"checktitle":"T","servicename":"s3","RISK":"R","REMEDIATION":{"RECOMMENDATION":{"TEXT":"fix","URL":"https://x.example.com/d"}}}`,
	} {
		doc, err := Decode([]byte(`{"data":[{"type":"findings","id":"f","attributes":{"check_id":"c","status":"FAIL","check_metadata":` + raw + `}}]}`))
		if err != nil {
			t.Fatal(err)
		}
		f, err := AsFinding(doc.Data[0])
		if err != nil {
			t.Fatal(err)
		}
		f.Resources = rel()
		g := ingest.Normalize(MapFinding(ctxWith(), f).Findings[0])
		if g.Title != "T" || !strings.Contains(g.Description, "Risk: R") || g.Remediation != "fix\n\nReference: https://x.example.com/d" || g.Tags[1] != "s3" {
			t.Errorf("%s -> %+v", raw, g)
		}
	}
}

func TestMapFindingOddMetadataIsHarmless(t *testing.T) {
	for name, md := range map[string]map[string]any{
		"lists":   {"checktitle": []any{"a"}, "remediation": []any{1}, "risk": 5.0},
		"nested":  {"remediation": map[string]any{"recommendation": "text"}},
		"nil":     nil,
		"strings": {"remediation": "fix it"},
	} {
		f := baseFinding()
		f.CheckMetadata = md
		m := MapFinding(ctxWith(bucket), f)
		if len(m.Findings) != 1 {
			t.Fatalf("%s: %+v", name, m)
		}
		ingesttest.Valid(t, Tool, []ingest.Finding{ingest.Normalize(m.Findings[0])})
	}
}

func TestMapFindingRespectsIngestLimits(t *testing.T) {
	f := baseFinding()
	f.CheckMetadata["checktitle"] = strings.Repeat("t\n", 1000)
	f.StatusExtended = strings.Repeat("é", 20000)
	f.CheckMetadata["risk"] = strings.Repeat("r", 20000)
	f.CheckMetadata["remediation"] = map[string]any{"recommendation": map[string]any{"text": strings.Repeat("x", 9000)}}
	f.UID = strings.Repeat("u", 2000)
	res := bucket
	res.UID = "arn:" + strings.Repeat("a", 2000)
	g := ingest.Normalize(MapFinding(ctxWith(res), f).Findings[0])
	ingesttest.Valid(t, Tool, []ingest.Finding{g})
	if len(g.Key) > ingest.MaxKeyLen || len(g.Asset.Key) > ingest.MaxAssetKeyLen {
		t.Fatalf("key lengths %d %d", len(g.Key), len(g.Asset.Key))
	}
}

// Raw results and resource tags or details are never read, so they cannot be
// in a request however they are shaped.
func TestNothingSensitiveSurvivesTheDecodeAndMapPath(t *testing.T) {
	doc, err := Decode([]byte(`{"data":[{"type":"findings","id":"f","attributes":{
	  "uid":"u","status":"FAIL","severity":"high","check_id":"c","status_extended":"s","muted":false,
	  "raw_result":{"password":"PLANTED-RAW"},"resource_groups":"PLANTED-GROUP","muted_reason":"PLANTED-REASON",
	  "check_metadata":{"checktitle":"T","notes":"PLANTED-NOTES","remediation":{"code":{"cli":"PLANTED-CLI"}}}},
	  "relationships":{"resources":{"data":[{"type":"resources","id":"r"}]}}}],
	  "included":[{"type":"resources","id":"r","attributes":{"uid":"arn:x","name":"n","region":"eu","service":"svc","type":"T",
	    "tags":{"k":"PLANTED-TAG"},"details":"PLANTED-DETAILS","metadata":"PLANTED-META","groups":["PLANTED-G"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	ix := doc.IndexIncluded()
	f, err := AsFinding(doc.Data[0])
	if err != nil {
		t.Fatal(err)
	}
	mc := MapContext{Provider: awsProvider, ScanID: "s", Resource: func(r Ref) (RawResource, bool) {
		res, ok := ix[r]
		if !ok {
			return RawResource{}, false
		}
		rr, err := AsResource(res)
		return rr, err == nil
	}}
	out, _ := Merge(MapFinding(mc, f).Findings)
	b, _ := json.Marshal(out)
	if len(out) != 1 || strings.Contains(string(b), "PLANTED") {
		t.Fatalf("leak or no output: %s", b)
	}
}

func TestWanted(t *testing.T) {
	f := func(status, sev string, muted bool) RawFinding {
		return RawFinding{Status: status, Severity: sev, Muted: muted}
	}
	for name, tc := range map[string]struct {
		f     RawFinding
		floor model.Severity
		muted bool
		want  bool
	}{
		"fail high":          {f("FAIL", "high", false), model.SeverityMedium, false, true},
		"pass":               {f("PASS", "high", false), model.SeverityMedium, false, false},
		"manual":             {f("MANUAL", "high", false), model.SeverityMedium, false, false},
		"unknown status":     {f("", "high", false), model.SeverityMedium, false, true},
		"muted excluded":     {f("FAIL", "high", true), model.SeverityMedium, false, false},
		"muted included":     {f("FAIL", "high", true), model.SeverityMedium, true, true},
		"below floor":        {f("FAIL", "low", false), model.SeverityMedium, false, false},
		"informational":      {f("FAIL", "informational", false), model.SeverityInfo, false, true},
		"unknown is medium":  {f("FAIL", "weird", false), model.SeverityMedium, false, true},
		"unknown below high": {f("FAIL", "weird", false), model.SeverityHigh, false, false},
	} {
		if got := Wanted(tc.f, tc.floor, tc.muted); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestMergeIsDeterministicAndKeepsTheMostSevere(t *testing.T) {
	mk := func(key string, sev model.Severity, title string) ingest.Finding {
		return ingest.Finding{Key: key, Asset: ingest.Asset{Kind: model.KindCloudResource, Key: "a"}, Title: title, Description: "d", Severity: sev}
	}
	in := []ingest.Finding{mk("b", model.SeverityLow, "x"), mk("a", model.SeverityLow, "low"), mk("a", model.SeverityHigh, "high"), mk("a", model.SeverityHigh, "another")}
	out, merged := Merge(in)
	if merged != 2 || len(out) != 2 || out[0].Key != "a" || out[0].Severity != model.SeverityHigh || out[0].Title != "another" || out[1].Key != "b" {
		t.Fatalf("%d %+v", merged, out)
	}
	rev := []ingest.Finding{in[3], in[2], in[1], in[0]}
	out2, _ := Merge(rev)
	if !reflect.DeepEqual(out, out2) {
		t.Fatal("the result depends on the input order")
	}
}

func TestSeverityHelpers(t *testing.T) {
	for in, want := range map[string]model.Severity{"info": "info", "Informational": "info", "LOW": "low", " medium ": "medium", "high": "high", "critical": "critical"} {
		if got, err := ParseSeverityFloor(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseSeverityFloor("severe"); err == nil {
		t.Error("unknown floor accepted")
	}
	if got := ProwlerSeverities(model.SeverityMedium); !reflect.DeepEqual(got, []string{"critical", "high", "medium"}) {
		t.Errorf("%v", got)
	}
	if got := ProwlerSeverities(model.SeverityInfo); len(got) != 5 || got[4] != "informational" {
		t.Errorf("%v", got)
	}
}

func TestScope(t *testing.T) {
	if got := Scope(Provider{Type: "gcp", UID: "my-project"}); got != "gcp:my-project" {
		t.Fatal(got)
	}
	long := Scope(Provider{Type: "github", UID: strings.Repeat("o", 500)})
	if len(long) > ingest.MaxScopeLen || Scope(Provider{Type: "github", UID: strings.Repeat("o", 500) + "x"}) == long {
		t.Fatalf("over-long scopes must stay valid and distinct: %d", len(long))
	}
}
