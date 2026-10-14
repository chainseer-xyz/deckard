package trivy

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func fixture(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/image.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func changed(t testing.TB, edit func(map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(fixture(t), &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseImageReport(t *testing.T) {
	r, err := ParseReport(fixture(t), ingest.ParseOptions{Scope: "image:web"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || len(r.Artifacts) != 2 || len(r.Relations) != 1 {
		t.Fatalf("unexpected counts: findings=%d artifacts=%d relations=%d", len(r.Findings), len(r.Artifacts), len(r.Relations))
	}
	f := r.Findings[0]
	if f.Asset.Kind != model.KindContainerImage || f.Asset.Key != digest || f.Severity != model.SeverityHigh || f.Evidence["cve_id"] != "CVE-2026-12345" {
		t.Fatalf("unexpected image finding: %+v", f)
	}
	if r.Relations[0].FromKey != digest || r.Relations[0].ToKey != "pkg:golang/example.org/library@1.0.0" || r.Relations[0].Type != model.RelContains {
		t.Fatalf("unexpected package correlation: %+v", r.Relations)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "DO-NOT-RETAIN-TEST-MARKER") || strings.Contains(string(b), "bbbbbbbb") {
		t.Fatal("raw config, URL secret, or config digest escaped into normalized report")
	}
}

func TestRejectInvalidOrUnsupportedReports(t *testing.T) {
	cases := map[string][]byte{
		"empty": nil, "empty object": []byte(`{}`), "null": []byte(`null`),
		"truncated":          []byte(`{"SchemaVersion":2,"password":"DO-NOT-RETAIN-TEST-MARKER"`),
		"trailing":           append(fixture(t), []byte(`{}`)...),
		"schema":             changed(t, func(d map[string]any) { d["SchemaVersion"] = 99 }),
		"filesystem":         changed(t, func(d map[string]any) { d["ArtifactType"] = "filesystem" }),
		"missing results":    changed(t, func(d map[string]any) { delete(d, "Results") }),
		"config digest only": changed(t, func(d map[string]any) { delete(d["Metadata"].(map[string]any), "RepoDigests") }),
		"ambiguous digest": changed(t, func(d map[string]any) {
			d["Metadata"].(map[string]any)["RepoDigests"] = []string{digest, "sha256:" + strings.Repeat("c", 64)}
		}),
		"tag not digest": changed(t, func(d map[string]any) {
			d["Metadata"].(map[string]any)["RepoDigests"] = []string{"registry.example/web:latest"}
		}),
		"secret": changed(t, func(d map[string]any) {
			d["Results"].([]any)[0].(map[string]any)["Secrets"] = []any{map[string]any{"Match": "DO-NOT-RETAIN-TEST-MARKER"}}
		}),
		"misconfiguration": changed(t, func(d map[string]any) {
			d["Results"].([]any)[0].(map[string]any)["Misconfigurations"] = []any{map[string]any{"ID": "AVD-TEST-1"}}
		}),
		"invalid purl": changed(t, func(d map[string]any) {
			d["Results"].([]any)[0].(map[string]any)["Packages"].([]any)[0].(map[string]any)["Identifier"] = map[string]any{"PURL": "not-a-package"}
		}),
		"invalid vulnerability": changed(t, func(d map[string]any) {
			d["Results"].([]any)[0].(map[string]any)["Vulnerabilities"].([]any)[0].(map[string]any)["VulnerabilityID"] = ""
		}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseReport(data, ingest.ParseOptions{})
			if err == nil {
				t.Fatal("unsafe or unsupported input accepted")
			}
			if strings.Contains(err.Error(), "DO-NOT-RETAIN-TEST-MARKER") {
				t.Fatal("input content leaked through parse error")
			}
		})
	}
}

func TestCleanMissingPURLAndDuplicateIdentity(t *testing.T) {
	t.Run("clean inventory survives", func(t *testing.T) {
		data := changed(t, func(d map[string]any) { d["Results"].([]any)[0].(map[string]any)["Vulnerabilities"] = []any{} })
		r, err := ParseReport(data, ingest.ParseOptions{})
		if err != nil || len(r.Findings) != 0 || len(r.Artifacts) != 2 || len(r.Relations) != 1 {
			t.Fatalf("clean inventory: %+v %v", r, err)
		}
	})
	t.Run("missing purl is image only", func(t *testing.T) {
		data := changed(t, func(d map[string]any) {
			r := d["Results"].([]any)[0].(map[string]any)
			delete(r, "Packages")
			delete(r["Vulnerabilities"].([]any)[0].(map[string]any), "PkgIdentifier")
		})
		r, err := ParseReport(data, ingest.ParseOptions{})
		if err != nil || len(r.Findings) != 1 || len(r.Artifacts) != 1 || len(r.Relations) != 0 {
			t.Fatalf("image-only finding: %+v %v", r, err)
		}
	})
	t.Run("same digest aliases and duplicate rows", func(t *testing.T) {
		data := changed(t, func(d map[string]any) {
			d["Metadata"].(map[string]any)["RepoDigests"] = []string{"registry.example/a@" + digest, "mirror.example/a@" + digest}
			r := d["Results"].([]any)[0].(map[string]any)
			r["Vulnerabilities"] = append(r["Vulnerabilities"].([]any), r["Vulnerabilities"].([]any)[0])
		})
		r, err := ParseReport(data, ingest.ParseOptions{})
		if err != nil || len(r.Findings) != 1 || len(r.Artifacts) != 2 || len(r.Relations) != 1 {
			t.Fatalf("duplicate handling: %+v %v", r, err)
		}
	})
	t.Run("distinct package paths do not collapse", func(t *testing.T) {
		data := changed(t, func(d map[string]any) {
			r := d["Results"].([]any)[0].(map[string]any)
			v := r["Vulnerabilities"].([]any)[0].(map[string]any)
			second := make(map[string]any, len(v))
			for k, value := range v {
				second[k] = value
			}
			second["PkgPath"] = "/another/install"
			r["Vulnerabilities"] = append(r["Vulnerabilities"].([]any), second)
		})
		r, err := ParseReport(data, ingest.ParseOptions{})
		if err != nil || len(r.Findings) != 2 || r.Findings[0].Key == r.Findings[1].Key {
			t.Fatalf("package path identity: %+v %v", r, err)
		}
	})
}

func TestDeterministicReport(t *testing.T) {
	a, err := ParseReport(fixture(t), ingest.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseReport(fixture(t), ingest.ParseOptions{})
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("same input changed report")
	}
}

func TestDuplicateRowsPreserveHighestSeverityRegardlessOfOrder(t *testing.T) {
	var reports [2]ingest.ArtifactReport
	for i := range reports {
		data := changed(t, func(d map[string]any) {
			r := d["Results"].([]any)[0].(map[string]any)
			original := r["Vulnerabilities"].([]any)[0].(map[string]any)
			duplicate := make(map[string]any, len(original))
			for k, value := range original {
				duplicate[k] = value
			}
			duplicate["Severity"] = "CRITICAL"
			if i == 0 {
				r["Vulnerabilities"] = []any{original, duplicate}
			} else {
				r["Vulnerabilities"] = []any{duplicate, original}
			}
		})
		var err error
		reports[i], err = ParseReport(data, ingest.ParseOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(reports[0], reports[1]) || len(reports[0].Findings) != 1 || reports[0].Findings[0].Severity != model.SeverityCritical {
		t.Fatal("duplicate ordering lowered severity or changed request identity")
	}
}

func TestOSPackageIdentityIgnoresImageTagAndRepositoryAlias(t *testing.T) {
	var reports [2]ingest.ArtifactReport
	for i := range reports {
		data := changed(t, func(d map[string]any) {
			refs := []string{"registry.example/team/web@" + digest, "mirror.example/team/web@" + digest}
			if i == 1 {
				refs[0], refs[1] = refs[1], refs[0]
			}
			d["Metadata"].(map[string]any)["RepoDigests"] = refs
			r := d["Results"].([]any)[0].(map[string]any)
			r["Class"], r["Type"] = "os-pkgs", "debian"
			r["Target"] = []string{"registry.example/team/web:v1 (debian 12)", "mirror.example/team/web:latest (debian 12)"}[i]
		})
		var err error
		reports[i], err = ParseReport(data, ingest.ParseOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if reports[0].Findings[0].Key != reports[1].Findings[0].Key || !reflect.DeepEqual(reports[0].Artifacts, reports[1].Artifacts) {
		t.Fatal("mutable image alias or manifest order changed immutable finding identity")
	}
}

// This projected fixture preserves the report fields from the verified
// v0.3.4 amd64 release scan. Its main Go module has no package version.
func TestRealReleaseImageKeepsOnlyVersionedPackages(t *testing.T) {
	data, err := os.ReadFile("testdata/release-image.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseReport(data, ingest.ParseOptions{})
	if err != nil || len(r.Findings) != 0 || len(r.Artifacts) != 3 || len(r.Relations) != 2 {
		t.Fatalf("real report: %+v %v", r, err)
	}
	for _, artifact := range r.Artifacts {
		if artifact.Key == "pkg:golang/github.com/chainseer-xyz/deckard" {
			t.Fatal("unversioned package gained fabricated identity")
		}
	}
}

func FuzzParseReport(f *testing.F) {
	f.Add(fixture(f))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseReport(data, ingest.ParseOptions{}) })
}

func TestOversizedInputIsRejectedBeforeDecoding(t *testing.T) {
	data := make([]byte, (64<<20)+1)
	copy(data, `{"password":"DO-NOT-RETAIN-TEST-MARKER"}`)
	_, err := ParseReport(data, ingest.ParseOptions{})
	if err == nil || !strings.Contains(err.Error(), "64 MiB") || strings.Contains(err.Error(), "DO-NOT-RETAIN-TEST-MARKER") {
		t.Fatal("oversized input lacked bounded, non-echoing rejection")
	}
}
