package runtimeevent

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/tetragon"
)

func TestCollectionReportsTheActualByteBudget(t *testing.T) {
	for _, aggregate := range []bool{false, true} {
		name, want := "per sensor", "per-pod log bound exceeded"
		if aggregate {
			name, want = "all sensors", "aggregate log bound exceeded"
		}
		t.Run(name, func(t *testing.T) {
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/pods") {
					writePods(w, sensorPod("a"), sensorPod("b"))
					return
				}
				_, _ = w.Write([]byte(nativeEvent + "\n" + nativeEvent))
			})
			settings := validSettings()
			if aggregate {
				settings.MaxTotalBytes = int64(len(nativeEvent) + 1)
			} else {
				settings.MaxPodBytes = int64(len(nativeEvent) + 1)
			}
			collector, err := New(client, settings)
			if err != nil {
				t.Fatal(err)
			}
			report, err := collector.Collect(context.Background())
			if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("byte budget failure lost its safe classification: %v", err)
			}
			if report.ObservedAt != nil || report.Findings != nil || report.Tool != "" {
				t.Fatal("failed collection returned an accepted envelope")
			}
		})
	}
}

func TestBusySensorDoesNotRelaxOtherHardCaps(t *testing.T) {
	if MaxReadBytes != 32<<20 || MaxTotalReadBytes != 256<<20 ||
		tetragon.MaxEventBytes != 1<<20 || ingest.MaxBodyBytes != 10<<20 ||
		ingest.MaxFindings != 5000 || MaxConcurrency != 4 || MaxPods != 64 {
		t.Fatal("busy-sensor recovery changed an independent safety bound")
	}
}

func TestCollectionStillRejectsThePerSensorHardCap(t *testing.T) {
	telemetry := []byte(`{"process_exec":{"process":{"arguments":"SECRET-` + strings.Repeat("x", 8192) + `"}}}` + "\n")
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			writePods(w, sensorPod("a"))
			return
		}
		_, _ = w.Write([]byte(nativeEvent + "\n"))
		for range 4500 { // More than 32 MiB, with individually valid bounded records.
			if _, err := w.Write(telemetry); err != nil {
				return
			}
		}
	})
	collector, err := New(client, validSettings())
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "per-pod log bound exceeded (33554432 bytes)") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("per-sensor hard cap was lost: %v", err)
	}
	if report.Findings != nil || report.ObservedAt != nil || report.Tool != "" {
		t.Fatal("overflow returned prefix evidence")
	}
}
