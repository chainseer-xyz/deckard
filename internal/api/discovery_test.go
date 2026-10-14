package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/discoveryimport"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type discoveryInventory struct{ names []string }

func (d *discoveryInventory) Sync(ctx context.Context, src source.Source) (store.InventoryDiff, error) {
	d.names = append(d.names, src.Name())
	_, err := src.Discover(ctx)
	return store.InventoryDiff{Added: []model.Asset{{Attrs: map[string]any{"private": "NATIVE_METADATA"}}}}, err
}

func TestRemoteDiscoveryNativeReportAdmission(t *testing.T) {
	inv := &discoveryInventory{}
	service, err := discoveryimport.New(inv, []string{"recon"})
	if err != nil {
		t.Fatal(err)
	}
	e := newIngestEnv(t, func(d *api.Deps) { d.Discovery = service })
	for _, tc := range []struct {
		name, raw string
		want      int
	}{
		{"recon", `{"type":"DNS_NAME","data":"www.example.com"}`, 200},
		{"cloudflare", `{"type":"DNS_NAME","data":"www.example.com"}`, 404},
		{"recon", `{"type":"DNS_NAME","data":"valid.example.com"}` + "\nSECRET", 422},
		{"recon", strings.Repeat(" ", (10<<20)+1), 413},
	} {
		r := e.do(http.MethodPost, "/api/v1/discovery/"+tc.name, tc.raw, "Content-Type", "application/x-ndjson")
		if r.Code != tc.want {
			t.Fatalf("%s got%d want%d: %s", tc.name, r.Code, tc.want, r.Body)
		}
		if strings.Contains(r.Body.String(), "SECRET") {
			t.Fatal("raw discovery leaked")
		}
		if strings.Contains(r.Body.String(), "NATIVE_METADATA") {
			t.Fatal("producer receipt disclosed canonical inventory metadata")
		}
	}
}
