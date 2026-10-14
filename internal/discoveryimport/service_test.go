package discoveryimport

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type observingInventory struct {
	discovery *source.Discovery
	name, typ string
	calls     int
}

func TestAdmissionRejectsUnknownSourcesAndOversizedBodies(t *testing.T) {
	inv := &observingInventory{}
	svc, err := New(inv, []string{"remote-recon"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cloudflare", "ingest:bbot", "remote-recon ", ""} {
		if diff, err := svc.Import(context.Background(), name, []byte(`{"type":"DNS_NAME","data":"web.example.com"}`)); err == nil || !diff.Empty() {
			t.Fatalf("unconfigured identity accepted: %+v %v", diff, err)
		}
	}
	if diff, err := svc.Import(context.Background(), "remote-recon", bytes.Repeat([]byte(" "), (10<<20)+1)); err == nil || !diff.Empty() {
		t.Fatalf("oversized body accepted: %+v %v", diff, err)
	}
	if inv.calls != 0 {
		t.Fatalf("rejected requests touched inventory %d times", inv.calls)
	}
}

func TestInvalidNativeReportFailsWholeImportWithoutEchoingInput(t *testing.T) {
	inv := &observingInventory{}
	svc, err := New(inv, []string{"remote-recon"})
	if err != nil {
		t.Fatal(err)
	}
	diff, err := svc.Import(context.Background(), "remote-recon", []byte("{\"type\":\"DNS_NAME\",\"data\":\"valid.example.com\"}\n{\"type\":\"IP_ADDRESS\",\"data\":\"SECRET\"}"))
	if err == nil || !diff.Empty() || inv.discovery != nil || inv.calls != 1 {
		t.Fatalf("invalid input returned partial success: %+v %v", diff, err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatal("error echoed raw event")
	}
}

func TestConstructorRejectsInvalidSourceIdentities(t *testing.T) {
	if _, err := New(nil, []string{"remote-recon"}); err == nil {
		t.Fatal("nil inventory accepted")
	}
	for _, names := range [][]string{{""}, {"a\nb"}, {" ingest"}, {"ingest:bbot"}, {strings.Repeat("a", 201)}, {"same", "same"}} {
		if _, err := New(&observingInventory{}, names); err == nil {
			t.Fatalf("invalid source list accepted: %q", names)
		}
	}
}

func TestCancellationAndNilServiceFailClosed(t *testing.T) {
	inv := &observingInventory{}
	svc, err := New(inv, []string{"remote-recon"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.Import(ctx, "remote-recon", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if inv.calls != 0 {
		t.Fatal("canceled request touched inventory")
	}
	var unavailable *Service
	if _, err := unavailable.Import(context.Background(), "remote-recon", nil); err == nil {
		t.Fatal("nil service accepted import")
	}
}

func TestAllowedIdentitiesAreCopiedAtConstruction(t *testing.T) {
	names := []string{"remote-recon"}
	inv := &observingInventory{}
	svc, err := New(inv, names)
	if err != nil {
		t.Fatal(err)
	}
	names[0] = "cloudflare"
	if _, err := svc.Import(context.Background(), "cloudflare", nil); err == nil {
		t.Fatal("caller mutated source allowlist")
	}
	if _, err := svc.Import(context.Background(), "remote-recon", nil); err != nil {
		t.Fatalf("original configured source was lost: %v", err)
	}
}

func (i *observingInventory) Sync(ctx context.Context, src source.Source) (store.InventoryDiff, error) {
	i.calls++
	i.name, i.typ = src.Name(), src.Type()
	d, err := src.Discover(ctx)
	i.discovery = d
	if err != nil {
		return store.InventoryDiff{}, err
	}
	diff := store.InventoryDiff{}
	for _, a := range d.Assets {
		diff.Added = append(diff.Added, model.Asset{Kind: a.Kind, Key: a.Key, Source: a.Source, Zone: a.Zone, Attrs: a.Attrs})
	}
	return diff, nil
}

func TestImportUsesConfiguredIdentityAndNativeBBOTParser(t *testing.T) {
	inv := &observingInventory{}
	svc, err := New(inv, []string{"remote-recon"})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("{\"type\":\"DNS_NAME\",\"data\":\"Web.Example.com.\",\"source\":\"cloudflare\",\"zone\":\"example.com\",\"attrs\":{\"owned\":true}}\n{\"type\":\"IP_ADDRESS\",\"data\":\"192.0.2.1\",\"owned\":true}")
	diff, err := svc.Import(context.Background(), "remote-recon", raw)
	if err != nil || len(diff.Added) != 2 {
		t.Fatalf("import failed: %+v %v", diff, err)
	}
	if inv.name != "remote-recon" || inv.typ != "bbot" || !inv.discovery.Partial || len(inv.discovery.Zones) != 0 {
		t.Fatalf("wrong source authority: %+v", inv)
	}
	for _, a := range diff.Added {
		if a.Source != "remote-recon" || a.Zone != "" || a.Attrs["owned"] != nil {
			t.Fatalf("raw authority retained: %+v", a)
		}
	}
}
