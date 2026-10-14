package api_test

import (
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/config"
)

func TestRemoteSourceHealthUsesProducerCadenceAndIncludesNeverSeen(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Sources = []config.SourceConfig{{Name: "recon", Type: "bbot", RemoteOnly: true, ReportInterval: 6 * time.Hour}}
		d.SyncInterval = 10 * time.Minute
	})
	r := e.get("/api/v1/sources")
	var out listOut
	r.json(t, &out)
	if r.Code != 200 || out.Total != 1 || out.Items[0]["source"] != "recon" || out.Items[0]["remote_only"] != true || out.Items[0]["expected_interval_seconds"] != float64(21600) {
		t.Fatalf("source state%d %s", r.Code, r.Body)
	}
	if r := e.do("POST", "/api/v1/sources/recon/sync", `{}`); r.Code != 409 {
		t.Fatalf("remote discovery polled like a file: %d %s", r.Code, r.Body)
	}
}
