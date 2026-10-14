package ingest

import (
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestArtifactContract(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	purl := "pkg:apk/alpine/openssl@3.5.1-r0?arch=aarch64"
	now := time.Now()
	valid := func() *Request {
		return &Request{Tool: "trivy", Scope: digest, ObservedAt: &now, Findings: []Finding{}, Artifacts: []Artifact{
			{Kind: model.KindContainerImage, Key: digest, Attrs: map[string]any{"digest": digest}},
			{Kind: model.KindPackage, Key: purl, Attrs: map[string]any{"purl": purl}},
		}, Relations: []model.RelationInput{{FromKind: model.KindContainerImage, FromKey: digest, ToKind: model.KindPackage, ToKey: purl, Type: model.RelContains}}}
	}
	if problems := Validate(valid(), Options{}); len(problems) != 0 {
		t.Fatal(problems)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Request)
	}{
		{"network node", func(r *Request) { r.Artifacts[0].Kind = model.KindIP }},
		{"tag identity", func(r *Request) { r.Artifacts[0].Key = "repo:latest" }},
		{"unversioned package", func(r *Request) { r.Artifacts[1].Key = "pkg:apk/alpine/openssl" }},
		{"ownership claim", func(r *Request) { r.Artifacts[0].Attrs["owned"] = true }},
		{"raw secrets", func(r *Request) { r.Artifacts[0].Attrs["config"] = "secret" }},
		{"dangling edge", func(r *Request) { r.Relations[0].ToKey = "pkg:apk/alpine/other@1" }},
		{"wrong edge", func(r *Request) { r.Relations[0].Type = model.RelResolvesTo }},
		{"duplicate node", func(r *Request) { r.Artifacts = append(r.Artifacts, r.Artifacts[0]) }},
		{"oversized inventory", func(r *Request) { r.Artifacts = make([]Artifact, MaxArtifacts+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid()
			tc.mutate(r)
			if len(Validate(r, Options{})) == 0 {
				t.Fatal("accepted unsafe artifact graph")
			}
		})
	}
}
