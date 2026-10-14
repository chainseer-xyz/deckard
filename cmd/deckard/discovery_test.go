package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryCLIValidatesAndPostsNativeReport(t *testing.T) {
	t.Setenv("DISCOVERY_TEST_TOKEN", testIngestToken)
	file := filepath.Join(t.TempDir(), "bbot.json")
	raw := `{"type":"DNS_NAME","data":"www.example.com"}`
	if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		data, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/api/v1/discovery/recon" || string(data) != raw || r.Header.Get("Authorization") != "Bearer "+testIngestToken {
			t.Error("wrong discovery request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"source":"recon","partial":true,"status":"accepted","added":0,"changed":0,"revived":0,"ignored":0}`)
	}))
	defer server.Close()
	var out, errw bytes.Buffer
	code := run([]string{"discovery", "ingest", "--source", "recon", "--file", file, "--url", server.URL, "--token-env", "DISCOVERY_TEST_TOKEN"}, &out, &errw)
	if code != 0 || hits != 1 {
		t.Fatalf("exit%d hits%d: %s", code, hits, errw.String())
	}
	if strings.Contains(out.String()+errw.String(), testIngestToken) {
		t.Fatal("token leaked")
	}
	if err := os.WriteFile(file, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	code = run([]string{"discovery", "ingest", "--source", "recon", "--file", file, "--url", server.URL, "--token-env", "DISCOVERY_TEST_TOKEN"}, &out, &errw)
	if code == 0 || hits != 1 {
		t.Fatal("invalid discovery posted")
	}
}

func TestDiscoveryCLIDoesNotTreatSPAOrUnboundReceiptAsDelivery(t *testing.T) {
	t.Setenv("DISCOVERY_TEST_TOKEN", testIngestToken)
	file := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(file, []byte(`{"type":"DNS_NAME","data":"www.example.com"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, receipt := range []string{"<html>Deckard</html>", `{}`, `{"source":"other","partial":true,"status":"accepted"}`, `{"source":"recon","partial":false,"status":"accepted"}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, receipt) }))
		var out, errw bytes.Buffer
		code := runDiscovery([]string{"ingest", "--source", "recon", "--file", file, "--url", server.URL, "--token-env", "DISCOVERY_TEST_TOKEN"}, &out, &errw)
		server.Close()
		if code == 0 || strings.Contains(out.String(), "(accepted)") {
			t.Fatalf("false delivery receipt %q: %s", receipt, out.String())
		}
	}
}
