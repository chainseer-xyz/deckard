package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestArtifactIngestAPIAndGraph(t *testing.T) {
	e := newIngestEnv(t)
	digest := "sha256:" + strings.Repeat("d", 64)
	purl := "pkg:golang/example.com/library@v1.0.0"
	req := ingest.Request{Tool: "trivy", Scope: digest, ObservedAt: &t0, Complete: true, Findings: []ingest.Finding{},
		Artifacts: []ingest.Artifact{{Kind: model.KindContainerImage, Key: digest, Attrs: map[string]any{"digest": digest}},
			{Kind: model.KindPackage, Key: purl, Attrs: map[string]any{"purl": purl}}},
		Relations: []model.RelationInput{{FromKind: model.KindContainerImage, FromKey: digest, ToKind: model.KindPackage, ToKey: purl, Type: model.RelContains}}}
	raw, _ := json.Marshal(req)
	r, result := e.post(string(raw))
	if r.Code != http.StatusOK || result.Accepted != 0 || !result.Complete {
		t.Fatalf("clean inventory: %d %s %+v", r.Code, r.Body, result)
	}
	image, err := e.store.GetAssetByKey(context.Background(), model.KindContainerImage, digest)
	if err != nil || image.Scope != model.ScopeExternal {
		t.Fatalf("missing non-probeable image: %+v %v", image, err)
	}
	edges, err := e.store.Edges(context.Background(), image.ID)
	if err != nil || len(edges) != 1 || edges[0].Type != model.RelContains || edges[0].Other.Key != purl {
		t.Fatalf("graph: %+v %v", edges, err)
	}
	r = e.do("GET", "/api/v1/assets?kind=container_image", "")
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), digest) {
		t.Fatalf("new kind filter: %d %s", r.Code, r.Body)
	}
	r = e.do("POST", "/api/v1/assets/"+jsonNumber(image.ID)+"/rescan", "")
	if r.Code != http.StatusConflict {
		t.Fatalf("metadata rescan accepted: %d %s", r.Code, r.Body)
	}
	r, result = e.post(string(raw))
	if r.Code != http.StatusOK || !result.Replay {
		t.Fatalf("API replay: %d %+v", r.Code, result)
	}
	req.Artifacts[0].Attrs["owned"] = true
	raw, _ = json.Marshal(req)
	r, _ = e.post(string(raw))
	if r.Code != http.StatusUnprocessableEntity {
		t.Fatalf("ownership claim accepted: %d", r.Code)
	}
}

func jsonNumber(id int64) string {
	raw, _ := json.Marshal(id)
	return string(raw)
}
