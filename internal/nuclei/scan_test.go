package nuclei

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
)

// recRunner records argv and the contents of the -l and -t list files at run
// time (they are removed afterwards).
type recRunner struct {
	calls   [][]string
	targets [][]string
	tpls    [][]string
	out     []byte
	err     error
}

func (r *recRunner) Run(_ context.Context, _ string, args []string) ([]byte, error) {
	r.calls = append(r.calls, slices.Clone(args))
	r.targets = append(r.targets, lines(argAfter(args, "-l")))
	r.tpls = append(r.tpls, lines(argAfter(args, "-t")))
	return r.out, r.err
}

func lines(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

// fixtureSet writes a template set and returns its root plus the absolute path
// of a template.
func fixtureSet(t *testing.T) (root string) {
	t.Helper()
	root = t.TempDir()
	fakenuclei.WriteTree(t, root,
		fakenuclei.Template{Path: "http/cves/2025/CVE-2025-55182.yaml", ID: "CVE-2025-55182", CVE: "CVE-2025-55182", Severity: "critical", Tags: []string{"cve", "react", "nextjs"}},
		fakenuclei.Template{Path: "http/cves/2025/CVE-2025-66478.yaml", ID: "CVE-2025-66478", CVE: "CVE-2025-66478", Severity: "critical", Tags: []string{"cve", "nextjs"}},
		fakenuclei.Template{Path: "http/vulnerabilities/react/rsc-rce.yaml", ID: "react-rsc-rce", CVE: "CVE-2025-55182,CVE-2025-66478", Severity: "critical", Tags: []string{"react"}},
		fakenuclei.Template{Path: "network/cves/2024/CVE-2024-6387.yaml", ID: "CVE-2024-6387", CVE: "CVE-2024-6387"},
		fakenuclei.Template{Path: "code/cves/2025/CVE-2025-55182.yaml", ID: "CVE-2025-55182-code", CVE: "CVE-2025-55182"},
		fakenuclei.Template{Path: "http/misc/other.yaml", ID: "other", Severity: "info"},
	)
	return root
}

func abs(root string, rel ...string) []string {
	var out []string
	for _, r := range rel {
		out = append(out, filepath.Join(root, filepath.FromSlash(r)))
	}
	return out
}

func newScanner(t *testing.T, r Runner, verify ScopeVerifier, cfg config.NucleiConfig, root string) *Scanner {
	t.Helper()
	cfg.TemplatesDir = root
	return NewScanner(cfg, verify, r, nil)
}

func TestScanArgvAndLists(t *testing.T) {
	root := fixtureSet(t)
	rr := &recRunner{}
	s := newScanner(t, rr, verifyOnly("a.example.com", "b.example.com"), config.NucleiConfig{SeverityMin: "medium", TagsExclude: []string{"fuzz"}}, root)
	res, err := s.Scan(context.Background(), ScanRequest{
		Targets:    []ScanTarget{{1, "https://a.example.com/"}, {2, "https://b.example.com:8443"}},
		Templates:  abs(root, "http/cves/2025/CVE-2025-55182.yaml", "http/misc/other.yaml"),
		RatePerSec: 4, Concurrency: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 2 || len(res.Refused) != 0 || len(rr.calls) != 1 {
		t.Fatalf("scanned=%d refused=%v calls=%d", res.Scanned, res.Refused, len(rr.calls))
	}
	a := rr.calls[0]
	for flag, want := range map[string]string{
		"-pt": "http,ssl,dns,tcp", "-severity": "medium,high,critical", "-etags": "fuzz,dos,intrusive",
		"-c": "3", "-bs": "2", "-rate-limit": "8", "-timeout": "10",
	} {
		if got := argAfter(a, flag); got != want {
			t.Errorf("%s = %q, want %q (args %v)", flag, got, want, a)
		}
	}
	// -dr keeps nuclei's own HTTP stack from following cross-host redirects
	// to hosts the scope guard never verified.
	for _, f := range []string{"-jsonl", "-silent", "-no-color", "-duc", "-no-interactsh", "-dr"} {
		if !slices.Contains(a, f) {
			t.Errorf("missing %s", f)
		}
	}
	for _, bad := range []string{"-tags", "-u", "-code", "-headless", "-file", "-dast", "-id", "-w"} {
		if slices.Contains(a, bad) {
			t.Errorf("unexpected %s in %v", bad, a)
		}
	}
	if !slices.Equal(rr.targets[0], []string{"https://a.example.com/", "https://b.example.com:8443"}) {
		t.Errorf("targets = %v", rr.targets[0])
	}
	want := abs(root, "http/cves/2025/CVE-2025-55182.yaml", "http/misc/other.yaml")
	for i := range want {
		want[i], _ = filepath.EvalSymlinks(want[i])
	}
	slices.Sort(want)
	if !slices.Equal(rr.tpls[0], want) {
		t.Errorf("template list = %v, want %v", rr.tpls[0], want)
	}
}

func TestScanNeverPassesRefusedTargets(t *testing.T) {
	root := fixtureSet(t)
	tpl := abs(root, "http/misc/other.yaml")
	for name, url := range map[string]string{
		"unowned host": "https://evil.example.net/", "leading dash": "-u https://a.example.com", "dash host": "https://-oX.example.com",
		"whitespace": "https://a.example.com/ -t /etc", "userinfo": "https://a.example.com@evil.example.net/", "file scheme": "file:///etc/passwd",
		"empty": "", "ftp": "ftp://a.example.com/", "newline": "https://a.example.com/\nhttps://evil.example.net/",
	} {
		rr := &recRunner{}
		s := newScanner(t, rr, verifyOnly("a.example.com"), config.NucleiConfig{}, root)
		res, err := s.Scan(context.Background(), ScanRequest{Targets: []ScanTarget{{1, url}}, Templates: tpl})
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if len(rr.calls) != 0 || res.Scanned != 0 || len(res.Refused) != 1 {
			t.Errorf("%s: binary invoked or target not refused (calls=%d scanned=%d refused=%v)", name, len(rr.calls), res.Scanned, res.Refused)
		}
	}

	// Mixed batch: only the owned target is written to the list.
	rr := &recRunner{}
	s := newScanner(t, rr, verifyOnly("a.example.com"), config.NucleiConfig{}, root)
	res, err := s.Scan(context.Background(), ScanRequest{
		Targets:   []ScanTarget{{1, "https://a.example.com"}, {2, "https://evil.example.net"}, {3, "http://203.0.113.9:8080"}},
		Templates: tpl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rr.targets[0], []string{"https://a.example.com"}) || len(res.Refused) != 2 || res.Scanned != 1 {
		t.Errorf("targets=%v refused=%v scanned=%d", rr.targets, res.Refused, res.Scanned)
	}

	// nil verifier fails closed.
	rr = &recRunner{}
	res, err = newScanner(t, rr, nil, config.NucleiConfig{}, root).Scan(context.Background(), ScanRequest{Targets: []ScanTarget{{1, "https://a.example.com"}}, Templates: tpl})
	if err != nil || len(rr.calls) != 0 || len(res.Refused) != 1 {
		t.Errorf("nil verifier: err=%v calls=%d", err, len(rr.calls))
	}
}

func TestScanTemplateValidation(t *testing.T) {
	root := fixtureSet(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "evil.yaml"), []byte("id: evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the set that points outside it.
	if err := os.Symlink(filepath.Join(outside, "evil.yaml"), filepath.Join(root, "http", "misc", "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "http", "misc", "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := abs(root, "http/misc/other.yaml")[0]
	for name, bad := range map[string]string{
		"outside the set": filepath.Join(outside, "evil.yaml"), "symlink escape": filepath.Join(root, "http", "misc", "link.yaml"),
		"not yaml": filepath.Join(root, "http", "misc", "notes.txt"), "relative": "http/misc/other.yaml",
		"missing": filepath.Join(root, "http", "gone.yaml"), "newline": good + "\n" + filepath.Join(outside, "evil.yaml"),
		"dotdot": filepath.Join(root, "http", "..", "..", "etc", "passwd"),
	} {
		rr := &recRunner{}
		s := newScanner(t, rr, verifyOnly("a.example.com"), config.NucleiConfig{}, root)
		_, err := s.Scan(context.Background(), ScanRequest{Targets: []ScanTarget{{1, "https://a.example.com"}}, Templates: []string{bad}})
		if !errors.Is(err, ErrNoTemplates) || len(rr.calls) != 0 {
			t.Errorf("%s: err=%v calls=%d, want ErrNoTemplates and no run", name, err, len(rr.calls))
		}
		// Mixed with a good one: the bad one is dropped, the good one runs.
		rr = &recRunner{}
		s = newScanner(t, rr, verifyOnly("a.example.com"), config.NucleiConfig{}, root)
		if _, err := s.Scan(context.Background(), ScanRequest{Targets: []ScanTarget{{1, "https://a.example.com"}}, Templates: []string{bad, good}}); err != nil {
			t.Fatal(err)
		}
		if len(rr.tpls) != 1 || len(rr.tpls[0]) != 1 || !strings.HasSuffix(rr.tpls[0][0], "other.yaml") {
			t.Errorf("%s: template list = %v", name, rr.tpls)
		}
	}
}

func TestScanAttributesMatchesToTargets(t *testing.T) {
	root := fixtureSet(t)
	out := []byte(`{"template-id":"CVE-2025-55182","info":{"name":"RSC RCE","severity":"critical","tags":["cve","react"],"classification":{"cve-id":["cve-2025-55182"]}},"type":"http","host":"a.example.com","port":"443","scheme":"https","url":"https://a.example.com","matched-at":"https://a.example.com/"}
{"template-id":"CVE-2025-55182","info":{"name":"RSC RCE","severity":"critical"},"type":"http","host":"a.example.com","port":"443","scheme":"https","url":"https://a.example.com","matched-at":"https://a.example.com/_next"}
{"template-id":"other","info":{"name":"Other","severity":"info"},"type":"http","host":"b.example.com","port":"8443","scheme":"https","url":"https://b.example.com:8443","matched-at":"https://b.example.com:8443/x"}
{"template-id":"CVE-2025-55182","info":{"severity":"critical"},"type":"http","host":"stranger.example.net","port":"443","scheme":"https","url":"https://stranger.example.net","matched-at":"https://stranger.example.net/"}
`)
	rr := &recRunner{out: out}
	s := newScanner(t, rr, verifyOnly("a.example.com", "b.example.com"), config.NucleiConfig{}, root)
	res, err := s.Scan(context.Background(), ScanRequest{
		// 11 and 12 share an origin (two URL assets of one service): both get the finding.
		Targets:   []ScanTarget{{11, "https://a.example.com/"}, {12, "https://a.example.com/app/"}, {2, "https://b.example.com:8443"}},
		Templates: abs(root, "http/cves/2025/CVE-2025-55182.yaml", "http/misc/other.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{11, 12} {
		fs := res.Findings[id]
		if len(fs) != 1 || fs[0].Key != "CVE-2025-55182" || fs[0].Check != "cve.nuclei" || fs[0].Severity != model.SeverityCritical {
			t.Fatalf("asset %d findings = %+v", id, fs)
		}
		if all := fs[0].Evidence["matched_at_all"].([]string); len(all) != 2 {
			t.Errorf("asset %d matched_at_all = %v (matches of one template merge)", id, all)
		}
	}
	// No shared evidence state between the two assets.
	res.Findings[11][0].Evidence["matched_at_all"] = []string{"mutated"}
	if all := res.Findings[12][0].Evidence["matched_at_all"].([]string); len(all) != 2 {
		t.Error("evidence is shared between assets")
	}
	if fs := res.Findings[2]; len(fs) != 1 || fs[0].Key != "other" {
		t.Errorf("asset 2 = %+v", fs)
	}
	if len(res.Findings) != 3 {
		t.Errorf("a result for a host that was never a target must be dropped: %v", res.Findings)
	}
}

func TestScanFindingsAreSurfacedWithRunError(t *testing.T) {
	root := fixtureSet(t)
	boom := errors.New("nuclei: exit status 2")
	out := []byte(`{"template-id":"other","info":{"severity":"low"},"type":"http","host":"a.example.com","port":"443","scheme":"https","url":"https://a.example.com","matched-at":"https://a.example.com/"}` + "\n")
	s := newScanner(t, &recRunner{out: out, err: boom}, verifyOnly("a.example.com"), config.NucleiConfig{}, root)
	res, err := s.Scan(context.Background(), ScanRequest{Targets: []ScanTarget{{1, "https://a.example.com"}}, Templates: abs(root, "http/misc/other.yaml")})
	if !errors.Is(err, boom) || len(res.Findings[1]) != 1 {
		t.Fatalf("err=%v findings=%v: partial output must be returned alongside the error", err, res.Findings)
	}
	s = newScanner(t, &recRunner{err: boom}, verifyOnly("a.example.com"), config.NucleiConfig{}, root)
	if _, err := s.Scan(context.Background(), ScanRequest{Targets: []ScanTarget{{1, "https://a.example.com"}}, Templates: abs(root, "http/misc/other.yaml")}); !errors.Is(err, boom) {
		t.Fatalf("a failed run with no output must error, got %v", err)
	}
}

func TestScanNoTemplatesYet(t *testing.T) {
	rr := &recRunner{}
	s := NewScanner(config.NucleiConfig{}, verifyOnly("a.example.com"), rr, nil,
		WithTemplateDir(func() (string, error) { return "", errors.New("no release") }))
	if _, err := s.Scan(context.Background(), ScanRequest{Targets: []ScanTarget{{1, "https://a.example.com"}}, Templates: []string{"/x/y.yaml"}}); !errors.Is(err, ErrNoTemplates) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.LookupCVEs([]string{"CVE-2025-55182"}); !errors.Is(err, ErrNoTemplates) {
		t.Fatalf("lookup err = %v", err)
	}
	if len(rr.calls) != 0 {
		t.Error("binary run without templates")
	}
}

func TestInteractshAndRunSettings(t *testing.T) {
	root := fixtureSet(t)
	rr := &recRunner{}
	s := NewScanner(config.NucleiConfig{TemplatesDir: root}, verifyOnly("a.example.com"), rr, map[string]any{"interactsh": true, "timeout": "20s", "rate_limit": 7})
	if _, err := s.Scan(context.Background(), ScanRequest{Targets: []ScanTarget{{1, "https://a.example.com"}}, Templates: abs(root, "http/misc/other.yaml")}); err != nil {
		t.Fatal(err)
	}
	a := rr.calls[0]
	if slices.Contains(a, "-no-interactsh") || argAfter(a, "-timeout") != "20" || argAfter(a, "-rate-limit") != "7" || argAfter(a, "-bs") != "1" {
		t.Errorf("args = %v", a)
	}
}

func TestNormalizeCVEs(t *testing.T) {
	got, err := NormalizeCVEs([]string{" cve-2025-55182", "CVE-2025-55182", "CVE-2024-12345678"})
	if err != nil || !slices.Equal(got, []string{"CVE-2025-55182", "CVE-2024-12345678"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range [][]string{{"CVE-25-1"}, {"2025-55182"}, {"CVE-2025-55182; rm"}, {""}, nil, {"CVE-2025-123"}} {
		if _, err := NormalizeCVEs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	var many []string
	for i := 0; i < 101; i++ {
		many = append(many, "CVE-2025-"+strings.Repeat("1", 4)+string(rune('0'+i%10))+string(rune('a'+0)))
	}
	if _, err := NormalizeCVEs(many); err == nil {
		t.Error("over-limit list accepted")
	}
}

func TestLookupCVEsAgainstFixtureTree(t *testing.T) {
	root := fixtureSet(t)
	s := NewScanner(config.NucleiConfig{TemplatesDir: root}, nil, &recRunner{}, nil)
	got, err := s.LookupCVEs([]string{"cve-2025-55182"})
	if err != nil {
		t.Fatal(err)
	}
	// By template id, and by classification.cve-id on a template with another
	// id; the code/ template is never returned.
	want := []string{"http/cves/2025/CVE-2025-55182.yaml", "http/vulnerabilities/react/rsc-rce.yaml"}
	if !slices.Equal(got, want) {
		t.Errorf("lookup = %v, want %v", got, want)
	}
	got, _ = s.LookupCVEs([]string{"CVE-2025-55182", "CVE-2025-66478", "CVE-2024-6387", "CVE-1999-0001"})
	want = []string{"http/cves/2025/CVE-2025-55182.yaml", "http/cves/2025/CVE-2025-66478.yaml", "http/vulnerabilities/react/rsc-rce.yaml", "network/cves/2024/CVE-2024-6387.yaml"}
	if !slices.Equal(got, want) {
		t.Errorf("multi lookup = %v, want %v", got, want)
	}
	if got, err := s.LookupCVEs([]string{"CVE-1999-0001"}); err != nil || len(got) != 0 {
		t.Errorf("unknown CVE = %v, %v", got, err)
	}
	if _, err := s.LookupCVEs([]string{"nope"}); err == nil {
		t.Error("invalid CVE accepted")
	}
	// Resolve drops what no longer exists and keeps only scannable templates.
	abs, err := s.Resolve([]string{"http/cves/2025/CVE-2025-55182.yaml", "http/gone.yaml", "code/cves/2025/CVE-2025-55182.yaml", "../escape.yaml"})
	if err != nil || len(abs) != 1 || !strings.HasSuffix(abs[0], "CVE-2025-55182.yaml") || !strings.Contains(abs[0], "/http/") {
		t.Errorf("resolve = %v err %v", abs, err)
	}
}

// End to end with the real ExecRunner and a compiled fake nuclei: the fake
// issues a real HTTP request, so a match proves the target reached the binary.
func TestScanWithFakeBinary(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_rsc" {
			_, _ = w.Write([]byte("uid=0(root) rce-confirmed"))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()
	clean := httptest.NewServer(http.NotFoundHandler())
	defer clean.Close()

	root := fixtureSet(t)
	bin := fakenuclei.Install(t, fakenuclei.Conf{Probes: []fakenuclei.Probe{{TemplateID: "CVE-2025-55182", Path: "/_rsc", Contains: "rce-confirmed"}}})
	cfg := config.NucleiConfig{TemplatesDir: root, Binary: bin.Path}
	s := NewScanner(cfg, func(context.Context, string) bool { return true }, ExecRunner{Policy: fixturePolicy}, nil)
	res, err := s.Scan(context.Background(), ScanRequest{
		Targets:   []ScanTarget{{1, vuln.URL}, {2, clean.URL}},
		Templates: abs(root, "http/cves/2025/CVE-2025-55182.yaml", "http/misc/other.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if fs := res.Findings[1]; len(fs) != 1 || fs[0].Key != "CVE-2025-55182" || fs[0].Severity != model.SeverityCritical {
		t.Fatalf("vulnerable target findings = %+v", fs)
	}
	if len(res.Findings[2]) != 0 {
		t.Errorf("clean target got findings: %+v", res.Findings[2])
	}
	calls := bin.ScanCalls()
	if len(calls) != 1 || len(calls[0].Targets) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestProcessTimeoutGrowsWithBatch(t *testing.T) {
	if got := ProcessTimeout(map[string]any{"run_timeout": "10s"}, 1); got != 10*time.Second {
		t.Errorf("one target timeout = %s", got)
	}
	if got := ProcessTimeout(map[string]any{"run_timeout": "10s"}, 20); got != 10*time.Second+19*30*time.Second {
		t.Errorf("twenty target timeout = %s, want %s", got, 10*time.Second+19*30*time.Second)
	}
}
