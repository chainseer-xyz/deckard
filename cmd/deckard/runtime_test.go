package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestRuntimeCollectorCLIUsesNativeSensorAndIncompleteEnvelope(t *testing.T) {
	t.Setenv("RUNTIME_TEST_TOKEN", testIngestToken)
	kube := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/pods") {
			_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"PodList","items":[{"metadata":{"name":"sensor","namespace":"tetragon","uid":"sensor-uid"},"spec":{"containers":[{"name":"export-stdout"}]},"status":{"phase":"Running"}}]}`)
			return
		}
		_, _ = io.WriteString(w, "")
	}))
	defer kube.Close()
	old := runtimeKubeClient
	defer func() { runtimeKubeClient = old }()
	runtimeKubeClient = func(string) (kubernetes.Interface, error) {
		return kubernetes.NewForConfig(&rest.Config{Host: kube.URL})
	}
	var posted ingest.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Error(err)
		}
		if r.Header.Get("Authorization") != "Bearer "+testIngestToken {
			t.Error("missing producer credential")
		}
		_, _ = io.WriteString(w, `{"accepted":0,"complete":false,"rejected":[]}`)
	}))
	defer server.Close()
	var out, errw bytes.Buffer
	code := run([]string{"runtime", "collect", "--provider", "tetragon", "--namespace", "tetragon", "--selector", "app=tetragon", "--container", "export-stdout", "--cluster-scope", "k8s:uid:cluster-a", "--url", server.URL, "--token-env", "RUNTIME_TEST_TOKEN"}, &out, &errw)
	if code != 0 || posted.Complete || posted.Tool != "tetragon" || posted.Scope != "k8s:uid:cluster-a" {
		t.Fatalf("exit%d envelope%+v: %s", code, posted, errw.String())
	}
	file := filepath.Join(t.TempDir(), "request.json")
	collect := []string{"runtime", "collect", "--namespace", "tetragon", "--selector", "app=tetragon", "--cluster-scope", "k8s:uid:cluster-a", "--output", file}
	if code := run(collect, &out, &errw); code != 0 {
		t.Fatalf("credentialless collection exit%d: %s", code, errw.String())
	}
	if code := run(collect, &out, &errw); code == 0 {
		t.Fatal("collector overwrote a prior report")
	}
	upload := []string{"runtime", "upload", "--file", file, "--cluster-scope", "k8s:uid:cluster-a", "--url", server.URL, "--token-env", "RUNTIME_TEST_TOKEN"}
	if code := run(upload, &out, &errw); code != 0 {
		t.Fatalf("upload exit%d: %s", code, errw.String())
	}
	if err := os.WriteFile(file, []byte(`{"tool":"tetragon","scope":"k8s:uid:other","complete":false,"findings":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if code := run(upload, &out, &errw); code == 0 {
		t.Fatal("uploader accepted a foreign scope")
	}
}

func TestRuntimeCLIRejectsMissingCommandAndFile(t *testing.T) {
	t.Setenv("RUNTIME_TEST_TOKEN", testIngestToken)
	for _, args := range [][]string{nil, {"other"}, {"upload", "--url", "https://deckard.example.com", "--token-env", "RUNTIME_TEST_TOKEN", "--cluster-scope", "k8s:uid:cluster-a"}} {
		var out, errw bytes.Buffer
		if runRuntime(args, &out, &errw) == 0 {
			t.Fatalf("accepted missing command/file: %v", args)
		}
	}
}
