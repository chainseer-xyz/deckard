package prowlerapp

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDecodeListWithIncludedLinksAndMeta(t *testing.T) {
	doc, err := Decode([]byte(`{
	  "data": [{"type":"findings","id":"f1","attributes":{"uid":"u1"},
	            "relationships":{"resources":{"data":[{"type":"resources","id":"r1"},{"type":"resources","id":"r2"}]},
	                             "scan":{"data":{"type":"scans","id":"s1"}}}}],
	  "included": [{"type":"resources","id":"r1","attributes":{"uid":"arn:aws:s3:::b"}}],
	  "links": {"first":"x","next":"http://h/api/v1/findings/latest?page%5Bnumber%5D=2","prev":null},
	  "meta": {"pagination": {"page":1,"pages":2,"count":3}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Data) != 1 || doc.Meta.Count != 3 || !strings.HasSuffix(doc.Links.Next, "number%5D=2") {
		t.Fatalf("%+v", doc)
	}
	rel := doc.Data[0].Relationships
	if !reflect.DeepEqual(rel["resources"].Refs, []Ref{{"resources", "r1"}, {"resources", "r2"}}) || rel["scan"].Refs[0].ID != "s1" {
		t.Fatalf("relationships %+v", rel)
	}
	if r := doc.IndexIncluded()[Ref{"resources", "r1"}]; r.ID != "r1" {
		t.Fatalf("included %+v", r)
	}
}

func TestDecodeShapes(t *testing.T) {
	for name, tc := range map[string]struct {
		in    string
		items int
		count int
		err   bool
	}{
		"single object":   {`{"data":{"type":"tokens","id":null,"attributes":{"access":"a"}}}`, 1, -1, false},
		"null data":       {`{"data":null}`, 0, -1, false},
		"absent data":     {`{}`, 0, -1, false},
		"empty list":      {`{"data":[],"meta":{"pagination":{"count":0}}}`, 0, 0, false},
		"negative count":  {`{"data":[],"meta":{"pagination":{"count":-4}}}`, 0, -1, false},
		"bad meta":        {`{"data":[],"meta":"x"}`, 0, -1, false},
		"bad links":       {`{"data":[],"links":[1]}`, 0, -1, false},
		"scalar data":     {`{"data":7}`, 0, 0, true},
		"not an object":   {`[1]`, 0, 0, true},
		"not json":        {`<html>`, 0, 0, true},
		"bad item":        {`{"data":[{"type":5}]}`, 0, 0, true},
		"bad included":    {`{"data":[],"included":"x"}`, 0, 0, true},
		"errors document": {`{"errors":[{"status":"401","code":"authentication_failed","detail":"nope"}]}`, 0, -1, false},
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := Decode([]byte(tc.in))
			if (err != nil) != tc.err {
				t.Fatalf("err %v", err)
			}
			if err == nil && (len(doc.Data) != tc.items || doc.Meta.Count != tc.count) {
				t.Fatalf("%+v", doc)
			}
		})
	}
	doc, _ := Decode([]byte(`{"errors":[{"status":"401","code":"c","detail":"d"}]}`))
	if len(doc.Errors) != 1 || doc.Errors[0].Detail != "d" {
		t.Fatalf("%+v", doc.Errors)
	}
}

// A decoding error must not quote the response: it may carry sensitive data.
func TestDecodeErrorsDoNotQuoteInput(t *testing.T) {
	_, err := Decode([]byte(`{"data":[{"type":["SENSITIVE-VALUE"]}]}`))
	if err == nil || strings.Contains(err.Error(), "SENSITIVE-VALUE") {
		t.Fatalf("err %v", err)
	}
	_, err = Decode([]byte(`SENSITIVE-VALUE`))
	if err == nil || strings.Contains(err.Error(), "SENSITIVE-VALUE") {
		t.Fatalf("err %v", err)
	}
}

func TestRelationshipLinkage(t *testing.T) {
	doc, err := Decode([]byte(`{"data":[{"type":"findings","id":"f","relationships":{
	  "none":{"data":null}, "empty":{"data":[]}, "linksOnly":{"links":{"related":"x"}}, "one":{"data":{"type":"a","id":"1"}}, "junk":{"data":5}, "junk2":"x"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rel := doc.Data[0].Relationships
	for name, want := range map[string]Relationship{
		"none": {Known: true}, "empty": {Known: true}, "linksOnly": {}, "one": {Known: true, Refs: []Ref{{"a", "1"}}}, "junk": {}, "junk2": {},
	} {
		got := rel[name]
		if got.Known != want.Known || len(got.Refs) != len(want.Refs) {
			t.Errorf("%s: %+v want %+v", name, got, want)
		}
	}
}

func decodeOne(t *testing.T, in string) Resource {
	t.Helper()
	doc, err := Decode([]byte(in))
	if err != nil || len(doc.Data) != 1 {
		t.Fatalf("%v %+v", err, doc)
	}
	return doc.Data[0]
}

func TestAsProvider(t *testing.T) {
	p, err := AsProvider(decodeOne(t, `{"data":{"type":"providers","id":"p1","attributes":{"provider":"AWS","uid":" 123456789012 ","connection":{"connected":true}}}}`))
	if err != nil || p != (Provider{ID: "p1", Type: "aws", UID: "123456789012", Connected: true}) {
		t.Fatalf("%+v %v", p, err)
	}
	for name, in := range map[string]string{
		"null connection": `{"data":{"type":"providers","id":"p","attributes":{"provider":"gcp","uid":"x","connection":null}}}`,
		"no connection":   `{"data":{"type":"providers","id":"p","attributes":{"provider":"gcp","uid":"x"}}}`,
		"null connected":  `{"data":{"type":"providers","id":"p","attributes":{"provider":"gcp","uid":"x","connection":{"connected":null}}}}`,
	} {
		if p, err := AsProvider(decodeOne(t, in)); err != nil || p.Connected {
			t.Errorf("%s: connected %v err %v", name, p.Connected, err)
		}
	}
	for name, in := range map[string]string{
		"no uid":       `{"data":{"type":"providers","id":"p","attributes":{"provider":"gcp"}}}`,
		"no type":      `{"data":{"type":"providers","id":"p","attributes":{"uid":"x"}}}`,
		"no id":        `{"data":{"type":"providers","attributes":{"provider":"gcp","uid":"x"}}}`,
		"wrong type":   `{"data":{"type":"providers","id":"p","attributes":{"provider":"gcp","uid":5}}}`,
		"bad boolean":  `{"data":{"type":"providers","id":"p","attributes":{"provider":"gcp","uid":"x","connection":{"connected":"yes"}}}}`,
		"no attribute": `{"data":{"type":"providers","id":"p"}}`,
	} {
		if _, err := AsProvider(decodeOne(t, in)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestAsScan(t *testing.T) {
	s, err := AsScan(decodeOne(t, `{"data":{"type":"scans","id":"s1","attributes":{"state":"Completed","inserted_at":"2026-10-03T05:00:00Z","started_at":"2026-10-03T05:01:00.123456Z","completed_at":"2026-10-03T06:00:00+01:00"}}}`))
	if err != nil || s.State != "completed" || !s.CompletedAt.Equal(time.Date(2026, 10, 3, 5, 0, 0, 0, time.UTC)) ||
		!s.Sort.Equal(time.Date(2026, 10, 3, 5, 1, 0, 123456000, time.UTC)) {
		t.Fatalf("%+v %v", s, err)
	}
	s, _ = AsScan(decodeOne(t, `{"data":{"type":"scans","id":"s2","attributes":{"state":"scheduled","inserted_at":"2026-10-03T05:00:00Z","started_at":null,"completed_at":"garbage"}}}`))
	if !s.CompletedAt.IsZero() || !s.Sort.Equal(time.Date(2026, 10, 3, 5, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", s)
	}
}

func TestAsFindingKeepsOnlyAllowListedData(t *testing.T) {
	f, err := AsFinding(decodeOne(t, `{"data":{"type":"findings","id":"f1","attributes":{
	  "uid":"prowler-aws-x","status":"fail","status_extended":"bucket is public","severity":"high","check_id":" s3_public ","delta":"new",
	  "first_seen_at":"2026-10-01T00:00:00Z","muted":false,"raw_result":{"password":"SECRET"},
	  "check_metadata":{"CheckTitle":"Public bucket","Service_Name":"s3","Remediation":{"Recommendation":{"Text":"fix","Url":"https://docs"}}}},
	  "relationships":{"scan":{"data":{"type":"scans","id":"s1"}},"resources":{"data":[]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != "FAIL" || f.CheckID != "s3_public" || f.Delta != "new" || f.Muted || !f.Resources.Known || f.Scan.Refs[0].ID != "s1" {
		t.Fatalf("%+v", f)
	}
	if f.CheckMetadata["checktitle"] != "Public bucket" || f.CheckMetadata["servicename"] != "s3" {
		t.Fatalf("metadata keys not normalised: %+v", f.CheckMetadata)
	}
	// A missing muted flag is not muted; an explicit true is.
	if g, _ := AsFinding(decodeOne(t, `{"data":{"type":"findings","id":"f","attributes":{"check_id":"c"}}}`)); g.Muted {
		t.Fatal("missing muted flag must not hide the finding")
	}
	if g, _ := AsFinding(decodeOne(t, `{"data":{"type":"findings","id":"f","attributes":{"muted":true}}}`)); !g.Muted {
		t.Fatal("muted lost")
	}
	if _, err := AsFinding(decodeOne(t, `{"data":{"type":"findings","id":"f","attributes":{"severity":["high"]}}}`)); err == nil {
		t.Fatal("wrong attribute type accepted")
	}
	// Odd check_metadata shapes are tolerated.
	for _, md := range []string{`null`, `"text"`, `[1]`, `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}`} {
		if _, err := AsFinding(decodeOne(t, `{"data":{"type":"findings","id":"f","attributes":{"check_metadata":`+md+`}}}`)); err != nil {
			t.Errorf("check_metadata %s: %v", md, err)
		}
	}
}

func TestAsResourceIgnoresTagsAndDetails(t *testing.T) {
	r, err := AsResource(decodeOne(t, `{"data":{"type":"resources","id":"r1","attributes":{"uid":"arn:aws:s3:::b","name":"b","region":"us-east-1","service":"s3","type":"AwsS3Bucket","tags":{"k":"SECRET"},"details":"SECRET","metadata":"SECRET"}}}`))
	if err != nil || r != (RawResource{ID: "r1", UID: "arn:aws:s3:::b", Name: "b", Region: "us-east-1", Service: "s3", Type: "AwsS3Bucket"}) {
		t.Fatalf("%+v %v", r, err)
	}
}
