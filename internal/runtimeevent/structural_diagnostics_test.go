package runtimeevent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest/tetragon"
)

func TestMalformedSensorReportsItsRecordAndDiscardsOtherSensorFindings(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/tetragon/pods":
			writePods(w, sensorPod("sensor-a"), sensorPod("sensor-b"))
		case "/api/v1/namespaces/tetragon/pods/sensor-a/log":
			_, _ = w.Write([]byte(nativeEvent + "\n"))
		case "/api/v1/namespaces/tetragon/pods/sensor-b/log":
			_, _ = w.Write([]byte("\n{\"SECRET\":\n"))
		default:
			t.Error("unexpected Kubernetes request")
			http.NotFound(w, r)
		}
	})
	settings := validSettings()
	settings.Concurrency = 1 // Finish sensor-a before the malformed sensor starts.
	collector, err := New(client, settings, WithClock(func() time.Time {
		return time.Date(2026, 10, 14, 12, 5, 0, 0, time.UTC)
	}))
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	var source *tetragon.SourceError
	var syntax *json.SyntaxError
	if !errors.As(err, &source) || source.Source != "namespace=tetragon pod=sensor-b container=export-stdout" || !errors.As(err, &syntax) || syntax.Offset != 10 {
		t.Fatalf("collector lost the failing sensor or typed syntax position: %v", err)
	}
	if !strings.Contains(err.Error(), "tetragon event 2:") || !strings.Contains(err.Error(), "bytes=10 offset=10 start=object_open end=other stream_line=2 stream_record=1 newline=true") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("collector lost redacted stream framing: %v", err)
	}
	if report.Tool != "" || report.ObservedAt != nil || report.Findings != nil {
		t.Fatal("malformed sensor permitted an upload of the other sensor's findings")
	}
}
