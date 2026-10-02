package takeover

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/community_fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func byProvider(fps []Fingerprint, name string) *Fingerprint {
	for i := range fps {
		if fps[i].Provider == name {
			return &fps[i]
		}
	}
	return nil
}

func TestConvertCommunityFixture(t *testing.T) {
	fps, err := ConvertCommunity(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(fps) < 15 {
		t.Fatalf("converted only %d entries", len(fps))
	}
	s3 := byProvider(fps, "AWS/S3")
	if s3 == nil || s3.Status != "vulnerable" || s3.NXDomain || len(s3.Fingerprint) != 1 ||
		s3.Fingerprint[0] != "The specified bucket does not exist" {
		t.Fatalf("S3: %+v", s3)
	}
	if got := MatchCNAME(fps, "my-bucket.s3.amazonaws.com"); got == nil || got.Provider != "AWS/S3" {
		t.Errorf("suffix match: %+v", got)
	}
	if MatchCNAME(fps, "evils3.amazonaws.com.attacker.net") != nil || MatchCNAME(fps, "nots3.amazonaws.com") != nil {
		t.Error("suffix must be label aligned and anchored")
	}
	eb := byProvider(fps, "AWS/Elastic Beanstalk")
	if eb == nil || !eb.NXDomain || len(eb.Fingerprint) != 0 {
		t.Errorf("NXDOMAIN flag: %+v", eb)
	}
	if az := byProvider(fps, "Microsoft Azure"); az == nil || !az.NXDomain || len(az.CNAME) < 10 {
		t.Errorf("azure: %+v", az)
	}
	if bb := byProvider(fps, "Bitbucket"); bb == nil || bb.Fingerprint[0] != "Repository not found" {
		t.Errorf("bitbucket: %+v", bb)
	}
	if byProvider(fps, "Discourse") == nil {
		t.Error("Discourse (NXDOMAIN, has cname) missing")
	}
	// Skipped on purpose: not vulnerable, no cname, regex/status-code style
	// fingerprints, URL/IP "cnames", empty fingerprints.
	for _, name := range []string{"AWS/Load Balancer (ELB)", "Heroku", "Github", "Smugsmug", "Vercel", "Helprace", "LaunchRock", "Ngrok", "Wordpress", "SmartJobBoard"} {
		if p := byProvider(fps, name); p != nil {
			t.Errorf("%s must be skipped: %+v", name, p)
		}
	}
	for _, f := range fps {
		if f.Status != "vulnerable" && f.Status != "edge-case" {
			t.Errorf("%s: status %q", f.Provider, f.Status)
		}
		if len(f.res) != len(f.CNAME) {
			t.Errorf("%s: patterns not compiled", f.Provider)
		}
	}
}

func TestConvertCommunityGarbage(t *testing.T) {
	for _, in := range []string{"", "{", "null", "[]", "{}", `"x"`, "[1,2]", `[{}]`, `[null]`, `[{"cname":"x"}]`,
		`[{"service":"X","status":"Vulnerable","cname":["a.b"],"fingerprint":""}]`,
		`[{"service":"X","status":"Vulnerable","cname":["(("],"fingerprint":"abcdefghijk"}]`,
		`[{"service":"","status":"Vulnerable","cname":["a.b"],"fingerprint":"abcdefghijk"}]`,
		"\xff\xfe", strings.Repeat("[", 1000)} {
		fps, err := ConvertCommunity([]byte(in))
		if err == nil && len(fps) != 0 {
			t.Errorf("%q produced %d entries", in, len(fps))
		}
	}
	// Regex metacharacters in a cname must be quoted, not interpreted.
	fps, err := ConvertCommunity([]byte(`[{"service":"X","status":"Edge case","cname":["a.b"],"fingerprint":"abcdefghijk"}]`))
	if err != nil || len(fps) != 1 {
		t.Fatalf("%v %v", fps, err)
	}
	if MatchCNAME(fps, "xaxb") != nil || MatchCNAME(fps, "foo.a.b") == nil {
		t.Error("dot must be literal")
	}
	if fps[0].Status != "edge-case" {
		t.Errorf("status %q", fps[0].Status)
	}
}

func TestMergeCuratedWins(t *testing.T) {
	cur := []Fingerprint{{Provider: "Heroku", CNAME: []string{`x$`}, Fingerprint: []string{"a"}, DefaultCert: []string{"herokuapp.com"}, Status: "edge-case"}}
	extra := []Fingerprint{
		{Provider: "heroku", CNAME: []string{`y$`}, Fingerprint: []string{"b"}, Status: "vulnerable"},
		{Provider: "NewCo", CNAME: []string{`z$`}, Fingerprint: []string{"c"}, Status: "vulnerable"},
	}
	m := Merge(cur, extra)
	if len(m) != 2 || m[0].Provider != "Heroku" || len(m[0].DefaultCert) != 1 || m[1].Provider != "NewCo" {
		t.Fatalf("%+v", m)
	}
	if len(cur) != 1 {
		t.Error("input modified")
	}
}

func TestEmbeddedSnapshotsLoad(t *testing.T) {
	if len(Curated()) < 20 {
		t.Error("curated DB too small")
	}
	merged := Default()
	seen := map[string]bool{}
	for _, f := range merged {
		k := strings.ToLower(f.Provider)
		if seen[k] {
			t.Errorf("duplicate provider %q in merged default", f.Provider)
		}
		seen[k] = true
	}
	if _, err := Marshal(merged); err != nil {
		t.Fatal(err)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	fps, err := ConvertCommunity(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(fps)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Load(b)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if len(back) != len(fps) {
		t.Fatalf("round trip %d != %d", len(back), len(fps))
	}
	for i := range fps {
		if back[i].Provider != fps[i].Provider || len(back[i].CNAME) != len(fps[i].CNAME) {
			t.Errorf("entry %d differs", i)
		}
	}
}

// A refreshed provider entry takes effect on an already-built check, with no
// restart; the curated precision rules still apply to it.
func TestSetFingerprintsTakesEffectWithoutRestart(t *testing.T) {
	t.Cleanup(func() { liveDB.Store(nil) })
	srv := server("<h1>Shiny Widgets: no such site registered here</h1>", 404)
	defer srv.Close()
	r := &checktest.Resolver{CNAMEs: map[string]string{"w.example.com": "acme.widgets-saas.example.net"}}
	tg := checktest.NewTarget(checktest.Hostname("w.example.com", "example.com"),
		checktest.WithResolver(r),
		checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{"w.example.com:80": srv})))
	c := New(nil)

	res, err := c.Run(context.Background(), tg)
	if err != nil || len(res.Findings) != 0 {
		t.Fatalf("before refresh: %v %+v", err, res.Findings)
	}
	refreshed, err := ConvertCommunity([]byte(`[{"service":"Widgets SaaS","status":"Edge case","cname":["widgets-saas.example.net"],"fingerprint":"no such site registered here"}]`))
	if err != nil {
		t.Fatal(err)
	}
	SetFingerprints(Merge(Default(), refreshed))
	res, err = c.Run(context.Background(), tg)
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("after refresh: %v %+v", err, res.Findings)
	}
	if f := res.Findings[0]; f.Key != "takeover:widgets-saas" || f.Severity != model.SeverityMedium {
		t.Errorf("unconfirmed edge-case from a refreshed entry must be medium: %+v", f)
	}
	// A check pinned with NewWithFingerprints is unaffected by the live DB.
	pinned := NewWithFingerprints(nil, Default())
	if res, _ := pinned.Run(context.Background(), tg); len(res.Findings) != 0 {
		t.Errorf("pinned DB must not see live swaps: %+v", res.Findings)
	}
	SetFingerprints(nil) // ignored: never leave the check without providers
	if len(Fingerprints()) == 0 {
		t.Error("empty set must be ignored")
	}
}
