package runtimeevent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

const nativeEvent = `{"process_kprobe":{"process":{"exec_id":"process-1","arguments":"SECRET-COMMAND","pod":{"namespace":"apps","name":"web-1","uid":"pod-123"}},"policy_name":"sensitive-file-write","function_name":"security_file_permission","action":"KPROBE_ACTION_POST","args":[{"string_arg":"SECRET-REQUEST"}]},"node_name":"worker-1","time":"2026-10-14T12:04:00Z"}`

func sensorPod(name string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tetragon", UID: types.UID("uid-" + name)}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "export-stdout"}}}}
}

func fixtureClient(t *testing.T, handler http.HandlerFunc) kubernetes.Interface {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writePods(w http.ResponseWriter, pods ...corev1.Pod) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, Items: pods})
}

func validSettings() Settings {
	return Settings{Namespace: "tetragon", Selector: "app=tetragon", Container: "export-stdout", ClusterScope: "k8s:uid:cluster-123"}
}

func TestCollectReturnsSanitizedIncompleteBatchFromNamespaceLogs(t *testing.T) {
	end := time.Date(2026, 10, 14, 12, 5, 0, 0, time.UTC)
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("collector attempted mutation: %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/tetragon/pods":
			if r.URL.Query().Get("labelSelector") != "app=tetragon" {
				t.Error("missing narrow pod selector")
			}
			writePods(w, sensorPod("sensor-a"), sensorPod("sensor-b"))
		case "/api/v1/namespaces/tetragon/pods/sensor-a/log", "/api/v1/namespaces/tetragon/pods/sensor-b/log":
			query := r.URL.Query()
			if query.Get("container") != "export-stdout" || query.Get("sinceTime") != "2026-10-14T11:59:00Z" {
				t.Errorf("wrong log scope/window: %v", query)
			}
			if query.Has("tailLines") || query.Has("limitBytes") || query.Get("follow") == "true" {
				t.Error("collector silently truncated or followed logs")
			}
			body := nativeEvent
			if strings.Contains(r.URL.Path, "sensor-b") {
				body = strings.ReplaceAll(body, "12:04:00Z", "12:04:30Z")
			}
			_, _ = w.Write([]byte(body))
		default:
			t.Errorf("collector accessed unexpected API: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	collector, err := New(client, validSettings(), WithClock(func() time.Time { return end }))
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Tool != "tetragon" || report.Scope != "k8s:uid:cluster-123" || report.Complete || report.ObservedAt == nil || !report.ObservedAt.Equal(end) || len(report.Findings) != 1 {
		t.Fatalf("wrong envelope: %+v", report)
	}
	if report.Findings[0].Evidence["runtime_batch_count"] != int64(2) {
		t.Fatalf("cross-pod events lost: %+v", report.Findings)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "SECRET") {
		t.Fatalf("raw log contents retained: %s", encoded)
	}
	if problems := ingest.Validate(&report, ingest.Options{Now: end}); len(problems) != 0 {
		t.Fatalf("invalid envelope: %+v", problems)
	}
}
