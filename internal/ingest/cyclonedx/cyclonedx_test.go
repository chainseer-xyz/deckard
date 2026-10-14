package cyclonedx

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

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

func TestParseImageSBOM(t *testing.T) {
	r, err := ParseReport(fixture(t), ingest.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.Artifacts) != 3 || len(r.Relations) != 2 {
		t.Fatalf("SBOM must retain inventory, not manufacture findings: %+v", r)
	}
	for _, relation := range r.Relations {
		if relation.FromKind != model.KindContainerImage || relation.Type != model.RelContains || relation.ToKind != model.KindPackage {
			t.Fatalf("unexpected edge: %+v", relation)
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "DO-NOT-RETAIN-TEST-MARKER") || strings.Contains(string(b), "local-package-id") {
		t.Fatal("arbitrary properties, evidence or document-local identity escaped")
	}
}

func TestRejectUnsafeOrUnboundSBOM(t *testing.T) {
	cases := map[string][]byte{
		"empty": nil, "object": []byte(`{}`), "null": []byte(`null`),
		"malformed":   []byte(`{"password":"DO-NOT-RETAIN-TEST-MARKER"`),
		"trailing":    append(fixture(t), []byte(`{}`)...),
		"format":      changed(t, func(d map[string]any) { d["bomFormat"] = "other" }),
		"version":     changed(t, func(d map[string]any) { d["specVersion"] = "9.0" }),
		"no metadata": changed(t, func(d map[string]any) { delete(d, "metadata") }),
		"not container": changed(t, func(d map[string]any) {
			d["metadata"].(map[string]any)["component"].(map[string]any)["type"] = "application"
		}),
		"hash only": changed(t, func(d map[string]any) {
			c := d["metadata"].(map[string]any)["component"].(map[string]any)
			delete(c, "purl")
			c["hashes"] = []any{map[string]any{"alg": "SHA-256", "content": strings.Repeat("a", 64)}}
		}),
		"mutable tag": changed(t, func(d map[string]any) {
			d["metadata"].(map[string]any)["component"].(map[string]any)["purl"] = "pkg:oci/web@latest"
		}),
		"invalid package": changed(t, func(d map[string]any) { d["components"].([]any)[0].(map[string]any)["purl"] = "not-a-package" }),
		"unversioned with credentials": changed(t, func(d map[string]any) {
			d["components"].([]any)[0].(map[string]any)["purl"] = "pkg:golang/example.org/library?repository_url=https%3A%2F%2Fuser%3ADO-NOT-RETAIN-TEST-MARKER%40example.org"
		}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseReport(data, ingest.ParseOptions{})
			if err == nil {
				t.Fatal("unsafe or unbound input accepted")
			}
			if strings.Contains(err.Error(), "DO-NOT-RETAIN-TEST-MARKER") {
				t.Fatal("raw input leaked through error")
			}
		})
	}
}

func TestEmptyAndDuplicateSBOMInventory(t *testing.T) {
	t.Run("empty bound inventory", func(t *testing.T) {
		data := changed(t, func(d map[string]any) { d["components"] = []any{} })
		r, err := ParseReport(data, ingest.ParseOptions{})
		if err != nil || len(r.Artifacts) != 1 || len(r.Findings) != 0 {
			t.Fatalf("%+v %v", r, err)
		}
	})
	t.Run("duplicates collapse by purl", func(t *testing.T) {
		data := changed(t, func(d map[string]any) { d["components"] = append(d["components"].([]any), d["components"].([]any)[0]) })
		r, err := ParseReport(data, ingest.ParseOptions{})
		if err != nil || len(r.Artifacts) != 3 || len(r.Relations) != 2 {
			t.Fatalf("%+v %v", r, err)
		}
	})
	t.Run("unidentified component is not fabricated", func(t *testing.T) {
		data := changed(t, func(d map[string]any) { delete(d["components"].([]any)[0].(map[string]any), "purl") })
		r, err := ParseReport(data, ingest.ParseOptions{})
		if err != nil || len(r.Artifacts) != 2 {
			t.Fatalf("%+v %v", r, err)
		}
	})
	t.Run("unversioned component is not fabricated", func(t *testing.T) {
		data := changed(t, func(d map[string]any) {
			d["components"].([]any)[0].(map[string]any)["purl"] = "pkg:golang/example.org/library"
		})
		r, err := ParseReport(data, ingest.ParseOptions{})
		if err != nil || len(r.Artifacts) != 2 {
			t.Fatalf("%+v %v", r, err)
		}
	})
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
