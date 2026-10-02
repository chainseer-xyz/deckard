package nuclei

import (
	"strings"
	"testing"
)

// Shape taken from a real nuclei v3.11.1 -jsonl run against two local targets.
const realEvents = `{"template-id":"my-test-vuln","info":{"name":"My test vuln","author":["me"],"tags":["cve","test"],"severity":"high","classification":{"cve-id":["cve-2099-0001"],"cwe-id":null}},"type":"http","host":"127.0.0.1","port":"18765","scheme":"http","url":"http://127.0.0.1:18765","matched-at":"http://127.0.0.1:18765/vuln","ip":"127.0.0.1"}
{"template-id":"my-test-vuln","info":{"name":"My test vuln","severity":"high"},"type":"http","host":"localhost","port":"18765","scheme":"http","url":"http://localhost:18765","matched-at":"http://localhost:18765/vuln"}
{"template-id":"ssl-weak","info":{"name":"weak","severity":"low"},"type":"ssl","host":"example.com","port":"443","matched-at":"example.com:443"}
{"template-id":"dns-x","info":{"name":"d","severity":"info"},"type":"dns","host":"example.com","matched-at":"example.com"}
`

func TestParseMatchesKeepsPerTargetEvents(t *testing.T) {
	ms, err := ParseMatches(strings.NewReader(realEvents))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 4 {
		t.Fatalf("matches = %d, want one per event (no cross-target merging)", len(ms))
	}
	m := ms[0]
	if m.Key != "my-test-vuln" || m.Host != "127.0.0.1" || m.Port != "18765" || m.Scheme != "http" || m.URL != "http://127.0.0.1:18765" {
		t.Errorf("match = %+v", m)
	}
	if ms[1].Host != "localhost" {
		t.Errorf("second target lost: %+v", ms[1])
	}
	if ms[2].Scheme != "" || ms[2].Port != "443" || ms[3].Port != "" {
		t.Errorf("non-http events: %+v %+v", ms[2], ms[3])
	}
	// The same events through the legacy merging parser still collapse by template id.
	fs, err := ParseJSONL(strings.NewReader(realEvents))
	if err != nil || len(fs) != 3 {
		t.Fatalf("ParseJSONL = %d findings err %v, want 3", len(fs), err)
	}
}

func TestMatchOrigin(t *testing.T) {
	for _, tc := range []struct {
		m    Match
		want string
	}{
		{Match{URL: "http://127.0.0.1:18765", Host: "127.0.0.1", Port: "18765", Scheme: "http"}, "http://127.0.0.1:18765"},
		{Match{Host: "App.Example.com", Port: "443", Scheme: "https"}, "https://app.example.com:443"},
		{Match{URL: "https://app.example.com/path?q=1"}, "https://app.example.com:443"},
		{Match{URL: "http://app.example.com"}, "http://app.example.com:80"},
		{Match{Host: "::1", Port: "8080", Scheme: "http"}, "http://[::1]:8080"},
		{Match{Host: "example.com", Port: "443"}, "example.com:443"},
		{Match{Host: "Example.com"}, "example.com"},
	} {
		if got := tc.m.Origin(); got != tc.want {
			t.Errorf("Origin(%+v) = %q, want %q", tc.m, got, tc.want)
		}
	}
}
