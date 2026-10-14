package assessmentresult

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

func completion(tool assessmentjob.Tool, raw string) assessmentjob.Completion {
	return assessmentjob.Completion{Session: assessmentjob.Session{ID: "run-1", Tool: tool, AssetIDs: []int64{7}}, Targets: []assessmentjob.Target{{AssetID: 7, Origin: "https://app.example.com", Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.7")}, Port: 443}}, Data: []byte(raw), Complete: true}
}

func TestZAPBindsAlertsWithoutRawSecrets(t *testing.T) {
	raw := `{"@version":"2.17.0","site":[{"@name":"https://app.example.com","alerts":[{"pluginid":"10020","alert":"Missing header","riskcode":"2","desc":"SECRET","solution":"Set the policy","instances":[{"uri":"https://app.example.com/admin?token=SECRET","method":"GET","evidence":"SECRET","requestHeader":"SECRET"}]}]}]}`
	r, err := Parse(completion(assessmentjob.ToolZAP, raw))
	if err != nil || r.Complete || len(r.Findings) != 1 || r.Findings[0].AssetID != 7 {
		t.Fatalf("result%+v %v", r, err)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "SECRET") {
		t.Fatal("raw scanner evidence leaked")
	}
	if _, err := Parse(completion(assessmentjob.ToolZAP, strings.ReplaceAll(raw, "app.example.com/admin", "outside.example.com/admin"))); err == nil {
		t.Fatal("out-of-grant result accepted")
	}
	if partial, err := Parse(completion(assessmentjob.ToolZAP, `{"site":[]}`)); err != nil || partial.Complete {
		t.Fatalf("empty target coverage becameclean: %+v %v", partial, err)
	}
}

func TestZGrabObservationsAreExactAndFailuresNeverClean(t *testing.T) {
	raw := `{"ip":"203.0.113.7","domain":"app.example.com","port":443,"data":{"http":{"status":"success","result":{"response":{"status_code":200,"body":"SECRET","headers":{"set_cookie":["SECRET"]}}}}}}`
	r, err := Parse(completion(assessmentjob.ToolZGrab2, raw))
	if err != nil || !r.Complete || len(r.Findings) != 0 || len(r.Observations[7]) != 1 {
		t.Fatalf("result%+v %v", r, err)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "SECRET") {
		t.Fatal("raw HTTP retained")
	}
	for _, bad := range []string{strings.Replace(raw, "203.0.113.7", "203.0.113.8", 1), raw + "\n" + raw, raw + "\ninvalid"} {
		if _, err := Parse(completion(assessmentjob.ToolZGrab2, bad)); err == nil {
			t.Fatal("extra or malformed probe accepted")
		}
	}
	failed := strings.Replace(raw, `"success"`, `"connection-timeout"`, 1)
	r, err = Parse(completion(assessmentjob.ToolZGrab2, failed))
	if err != nil || r.Complete {
		t.Fatalf("failed probe wasclean %+v %v", r, err)
	}
}

func TestStrixAlwaysAdditiveAndSessionBound(t *testing.T) {
	raw := `{"schema_version":1,"session_id":"run-1","tool":"strix","upstream_source_sha":"55bc07991aacb1c26a81b43e7ca53148730d2019","completed":true,"complete":false,"findings":[{"key":"issue-1","asset":{"kind":"url","key":"https://app.example.com"},"title":"Authentication missing","severity":"high","description":"Reviewed path","evidence":{"endpoint":"/admin"}}]}`
	r, err := Parse(completion(assessmentjob.ToolStrix, raw))
	if err != nil || r.Complete || len(r.Findings) != 1 || r.Findings[0].AssetID != 7 {
		t.Fatalf("result%+v %v", r, err)
	}
	if _, err := Parse(completion(assessmentjob.ToolStrix, strings.Replace(raw, "run-1", "other", 1))); err == nil {
		t.Fatal("foreign session report accepted")
	}
}

func TestZGrabRetainsEveryAddressInOneAssetObservation(t *testing.T) {
	c := completion(assessmentjob.ToolZGrab2, `{"ip":"203.0.113.7","domain":"app.example.com","port":443,"data":{"http":{"status":"success","result":{"response":{"status_code":200}}}}}`+"\n"+`{"ip":"203.0.113.8","domain":"app.example.com","port":443,"data":{"http":{"status":"success","result":{"response":{"status_code":503}}}}}`)
	c.Targets[0].Addresses = append(c.Targets[0].Addresses, netip.MustParseAddr("203.0.113.8"))
	r, err := Parse(c)
	if err != nil || len(r.Observations[7]) != 1 {
		t.Fatalf("address observations would overwrite one another: %+v %v", r, err)
	}
	encoded, _ := json.Marshal(r.Observations[7][0].Data)
	for _, want := range []string{"203.0.113.7", "203.0.113.8", "200", "503"} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("missing endpoint %s: %s", want, encoded)
		}
	}
}
