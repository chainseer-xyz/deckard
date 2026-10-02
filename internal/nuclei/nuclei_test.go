package nuclei

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestParseJSONLFixture(t *testing.T) {
	f, err := os.Open("testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := ParseJSONL(f)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(got))
	by := map[string]model.FindingInput{}
	for _, g := range got {
		keys = append(keys, g.Key)
		by[g.Key] = g
	}
	want := []string{"git-config", "CVE-2021-99999", "tech-detect:nginx", "weird"}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys=%v want %v", keys, want)
	}
	g := by["git-config"]
	if g.Severity != model.SeverityMedium || g.Title != "Git Config Exposure" || g.Remediation != "Block access to .git." ||
		g.Evidence["matched_at"] != "https://app.example.com/.git/config" {
		t.Errorf("git-config: %+v", g)
	}
	cve := by["CVE-2021-99999"]
	if cve.Severity != model.SeverityCritical {
		t.Errorf("sev %v", cve.Severity)
	}
	for _, tag := range []string{"cve", "CVE-2021-99999", "CWE-94", "rce"} {
		if !slices.Contains(cve.Tags, tag) {
			t.Errorf("missing tag %s in %v", tag, cve.Tags)
		}
	}
	if all := cve.Evidence["matched_at_all"].([]string); len(all) != 2 {
		t.Errorf("merge: %v", all)
	}
	if by["weird"].Severity != model.SeverityInfo || by["weird"].Remediation == "" {
		t.Errorf("weird: %+v", by["weird"])
	}
	if by["tech-detect:nginx"].Evidence["matcher"] != "nginx" {
		t.Error("matcher")
	}
}

func TestParseJSONLEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"empty", "", 0},
		{"blank lines", "\n\n  \n", 0},
		{"garbage only", "hello\n{bad\n", 0},
		{"no trailing newline", `{"template-id":"a","info":{"severity":"low"}}`, 1},
		{"overlong line skipped", strings.Repeat("x", 3<<20) + "\n" + `{"template-id":"b","info":{}}` + "\n", 1},
		{"extracted truncated", `{"template-id":"c","info":{},"extracted-results":["` + strings.Repeat("s", 500) + `"]}`, 1},
	}
	for _, tc := range tests {
		got, err := ParseJSONL(strings.NewReader(tc.in))
		if err != nil || len(got) != tc.want {
			t.Errorf("%s: n=%d err=%v", tc.name, len(got), err)
		}
		if tc.name == "extracted truncated" && len(got) == 1 {
			if ex := got[0].Evidence["extracted_results"].([]string); len(ex[0]) > maxExtractedLen+3 {
				t.Errorf("not truncated: %d", len(ex[0]))
			}
		}
	}
}

type fakeRunner struct {
	calls  [][]string
	bins   []string
	output []byte
	err    error
}

func (f *fakeRunner) Run(ctx context.Context, bin string, args []string) ([]byte, error) {
	f.bins = append(f.bins, bin)
	f.calls = append(f.calls, slices.Clone(args))
	return f.output, f.err
}

func verifyOnly(hosts ...string) ScopeVerifier {
	return func(_ context.Context, h string) bool { return slices.Contains(hosts, h) }
}

func urlAsset(key string, tech ...any) model.Asset {
	a := model.Asset{Kind: model.KindURL, Key: key, Scope: model.ScopeOwned}
	if len(tech) > 0 {
		a.Attrs = map[string]any{"tech": tech}
	}
	return a
}

func fixture(t *testing.T) []byte {
	b, err := os.ReadFile("testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func argAfter(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

func TestRunBuildsArgvAndParses(t *testing.T) {
	fr := &fakeRunner{output: fixture(t)}
	cfg := config.NucleiConfig{Enabled: true, TemplatesDir: "/etc/deckard/nuclei", SeverityMin: "medium", TagsExclude: []string{"fuzz"}, ExtraTags: []string{"custom"}}
	c := New(cfg, verifyOnly("app.example.com"), fr, false, nil)
	res, err := c.Run(context.Background(), check.Target{
		Asset:  urlAsset("https://app.example.com/", "WordPress:6.2", "nginx"),
		Config: map[string]any{"rate_limit": 20, "concurrency": 5, "timeout": "7s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || fr.bins[0] != "nuclei" {
		t.Fatalf("calls=%v bins=%v", fr.calls, fr.bins)
	}
	a := fr.calls[0]
	checks := map[string]string{
		"-u": "https://app.example.com/", "-t": "/etc/deckard/nuclei", "-severity": "medium,high,critical",
		"-tags": "wordpress,wp,nginx,custom", "-etags": "fuzz,dos,intrusive", "-rate-limit": "20", "-c": "5", "-timeout": "7",
	}
	for flag, want := range checks {
		if got := argAfter(a, flag); got != want {
			t.Errorf("%s = %q want %q (args=%v)", flag, got, want, a)
		}
	}
	for _, f := range []string{"-jsonl", "-silent", "-no-color", "-duc", "-no-interactsh"} {
		if !slices.Contains(a, f) {
			t.Errorf("missing %s", f)
		}
	}
	if len(res.Findings) != 4 || res.Findings[0].Check != "cve.nuclei" {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestInteractshToggleAndFallbackTags(t *testing.T) {
	fr := &fakeRunner{}
	c := New(config.NucleiConfig{}, verifyOnly("app.example.com"), fr, false, map[string]any{"interactsh": true})
	if _, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com")}); err != nil {
		t.Fatal(err)
	}
	a := fr.calls[0]
	if slices.Contains(a, "-no-interactsh") {
		t.Error("interactsh toggle ignored")
	}
	if argAfter(a, "-tags") != "exposure,misconfig,cve" || argAfter(a, "-severity") != "low,medium,high,critical" || slices.Contains(a, "-t") {
		t.Errorf("defaults: %v", a)
	}
}

func TestOutOfScopeNeverReachesBinary(t *testing.T) {
	tests := []struct {
		name  string
		asset model.Asset
	}{
		{"unowned host", urlAsset("https://evil.example.net/")},
		{"shared scope", model.Asset{Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeShared}},
		{"external scope", model.Asset{Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeExternal}},
		{"leading dash", urlAsset("-u https://app.example.com")},
		{"dash host", urlAsset("https://-oX.example.com")},
		{"whitespace", urlAsset("https://app.example.com/ -t /etc")},
		{"userinfo trick", urlAsset("https://app.example.com@evil.example.net/")},
		{"file scheme", urlAsset("file:///etc/passwd")},
		{"service ip out of scope", model.Asset{Kind: model.KindService, Key: "203.0.113.9:443/tcp", Scope: model.ScopeOwned, Attrs: map[string]any{"tls": true}}},
		{"hostname kind", model.Asset{Kind: model.KindHostname, Key: "app.example.com", Scope: model.ScopeOwned}},
	}
	for _, intr := range []bool{false, true} {
		for _, tc := range tests {
			fr := &fakeRunner{output: fixture(t)}
			c := New(config.NucleiConfig{}, verifyOnly("app.example.com", "198.51.100.7"), fr, intr, nil)
			_, err := c.Run(context.Background(), check.Target{Asset: tc.asset})
			if err == nil {
				t.Errorf("%s: expected error", tc.name)
			}
			if len(fr.calls) != 0 {
				t.Errorf("%s: binary invoked with %v", tc.name, fr.calls)
			}
		}
	}
	// nil verifier fails closed
	fr := &fakeRunner{}
	if _, err := New(config.NucleiConfig{}, nil, fr, false, nil).Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com")}); !errors.Is(err, ErrOutOfScope) || len(fr.calls) != 0 {
		t.Errorf("nil verifier: %v", err)
	}
}

func TestServiceTargets(t *testing.T) {
	fr := &fakeRunner{}
	c := New(config.NucleiConfig{}, verifyOnly("198.51.100.7"), fr, false, nil)
	a := model.Asset{Kind: model.KindService, Key: "198.51.100.7:8443/tcp", Scope: model.ScopeOwned, Attrs: map[string]any{"ip": "198.51.100.7", "port": 8443, "tls": true}}
	if !c.Applies(a) {
		t.Fatal("should apply")
	}
	if _, err := c.Run(context.Background(), check.Target{Asset: a}); err != nil {
		t.Fatal(err)
	}
	if got := argAfter(fr.calls[0], "-u"); got != "https://198.51.100.7:8443" {
		t.Errorf("target %q", got)
	}
	ssh := model.Asset{Kind: model.KindService, Key: "198.51.100.7:22/tcp", Scope: model.ScopeOwned}
	if c.Applies(ssh) {
		t.Error("ssh service should not apply")
	}
}

func TestIntrusiveVariant(t *testing.T) {
	cfg := config.NucleiConfig{TagsExclude: []string{"dos", "intrusive"}}
	tests := []struct {
		name     string
		cfg      map[string]any
		wantEtag string
	}{
		{"default lifts intrusive, keeps dos", nil, "dos"},
		{"explicitly lifting dos", map[string]any{"lift_exclusions": []any{"intrusive", "dos"}}, ""},
		{"lifting nothing", map[string]any{"lift_exclusions": []any{}}, "dos,intrusive"},
	}
	for _, tc := range tests {
		fr := &fakeRunner{}
		c := New(cfg, verifyOnly("app.example.com"), fr, true, nil)
		if c.Name() != "nuclei.intrusive" || c.Tier() != model.TierIntrusive {
			t.Fatal("identity")
		}
		if _, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com"), Config: tc.cfg}); err != nil {
			t.Fatal(err)
		}
		a := fr.calls[0]
		if got := argAfter(a, "-etags"); got != tc.wantEtag {
			t.Errorf("%s: etags=%q want %q", tc.name, got, tc.wantEtag)
		}
		if !strings.Contains(argAfter(a, "-tags"), "intrusive") {
			t.Errorf("%s: intrusive tag not selected: %v", tc.name, a)
		}
	}
	// active variant always excludes dos and intrusive
	fr := &fakeRunner{}
	New(config.NucleiConfig{}, verifyOnly("app.example.com"), fr, false, nil).Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com")})
	if got := argAfter(fr.calls[0], "-etags"); got != "dos,intrusive" {
		t.Errorf("active etags=%q", got)
	}
}

func TestRunnerErrorHandling(t *testing.T) {
	boom := errors.New("exit status 2")
	c := New(config.NucleiConfig{}, verifyOnly("app.example.com"), &fakeRunner{err: boom}, false, nil)
	if _, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com")}); !errors.Is(err, boom) {
		t.Errorf("no-output failure should error, got %v", err)
	}
	c = New(config.NucleiConfig{}, verifyOnly("app.example.com"), &fakeRunner{err: boom, output: fixture(t)}, false, nil)
	res, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com")})
	if err != nil || len(res.Findings) == 0 || res.Observations[0].Data["partial"] != true {
		t.Errorf("salvage: %v %+v", err, res)
	}
}

func TestInvalidSeverityMin(t *testing.T) {
	c := New(config.NucleiConfig{SeverityMin: "bogus"}, verifyOnly("app.example.com"), &fakeRunner{}, false, nil)
	if _, err := c.Run(context.Background(), check.Target{Asset: urlAsset("https://app.example.com")}); err == nil {
		t.Fatal("expected error")
	}
}

func TestChecksConstructor(t *testing.T) {
	if got := Checks(config.NucleiConfig{}, nil, nil); got != nil {
		t.Error("disabled should return nothing")
	}
	cs := Checks(config.NucleiConfig{Enabled: true}, nil, verifyOnly())
	if len(cs) != 2 || cs[0].Tier() != model.TierActive || cs[1].Tier() != model.TierIntrusive {
		t.Fatal("unexpected checks")
	}
}

func TestExecRunnerUsesArgvNotShell(t *testing.T) {
	echo, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("no echo binary")
	}
	dir := t.TempDir()
	payload := "$(touch " + dir + "/pwned);`id`;|"
	out, err := ExecRunner{}.Run(context.Background(), echo, []string{payload})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != payload {
		t.Errorf("argument was interpreted: %q", out)
	}
	if _, err := os.Stat(dir + "/pwned"); err == nil {
		t.Error("shell injection executed")
	}
}

func TestExecRunnerTimeoutKills(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (ExecRunner{}).Run(ctx, sleep, []string{"30"}); err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 10*time.Second {
		t.Error("process not killed promptly")
	}
}
