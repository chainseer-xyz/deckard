package bbot

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func reportFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.jsonl")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoveryIsSanitizedAndNeverAuthoritative(t *testing.T) {
	path := reportFile(t, strings.Join([]string{
		`{"type":"DNS_NAME","data":"WWW.Example.com.","id":"DNS_NAME:abc123","module":"dnsresolve","scan":"SCAN:123","parent_uuid":"123-456","timestamp":1688526222.723366,"scope_distance":0,"tags":["in-scope","target"],"owned":true,"secret":"do-not-retain"}`,
		`{"type":"IP_ADDRESS","data":"::ffff:192.0.2.1"}`,
		`{"type":"URL","data":"https://user:credential@WWW.Example.com:8443/login?token=do-not-retain#secret"}`,
		`{"type":"OPEN_TCP_PORT","data":"[2001:db8::1]:443"}`,
		`{"type":"DNS_NAME","data":"www.example.com"}`,
		`{"type":"HTTP_RESPONSE","data":{"body":"do-not-retain"}}`,
	}, "\n"))
	s, err := New(config.SourceConfig{Name: "recon", DiscoveryFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "recon" || s.Type() != "bbot" {
		t.Fatal("wrong source identity")
	}
	d, err := s.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !d.Partial || len(d.PartialReasons) == 0 || len(d.Zones) != 0 || len(d.Relations) != 0 || len(d.Assets) != 4 {
		t.Fatalf("unexpected discovery shape: %+v", d)
	}
	want := map[model.AssetKind]string{model.KindHostname: "www.example.com", model.KindIP: "192.0.2.1",
		model.KindURL: "https://www.example.com:8443/login", model.KindService: "[2001:db8::1]:443/tcp"}
	for _, a := range d.Assets {
		if a.Key != want[a.Kind] || a.Source != "recon" || a.Zone != "" || a.Attrs["owned"] != nil {
			t.Fatalf("unexpected asset: %+v", a)
		}
		if a.Kind == model.KindHostname && (a.Attrs["module"] != "dnsresolve" || a.Attrs["event_id"] != "DNS_NAME:abc123" || a.Attrs["timestamp"] == nil) {
			t.Fatalf("lost allowlisted provenance: %+v", a.Attrs)
		}
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"credential", "do-not-retain", "scope_distance", "in-scope"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("retained prohibited content %q", secret)
		}
	}
}

func TestInvalidEventsFailTheWholeReportWithoutEchoingInput(t *testing.T) {
	for _, line := range []string{
		`{"type":"DNS_NAME","data":"bad host.SECRET.example"}`,
		`{"type":"DNS_NAME","data":"-SECRET.example"}`,
		`{"type":"IP_ADDRESS","data":"SECRET"}`,
		`{"type":"IP_ADDRESS","data":"fe80::1%SECRET"}`,
		`{"type":"URL","data":"file:///SECRET"}`,
		`{"type":"URL","data":"https://example.com:SECRET/"}`,
		`{"type":"OPEN_TCP_PORT","data":"example.com:0","secret":"SECRET"}`,
		`{"type":"OPEN_TCP_PORT","data":"2001:db8::1:443","secret":"SECRET"}`,
		`{"type":"DNS_NAME","data":{"secret":"SECRET"}}`,
		`{"type":"DNS_NAME","data":"SECRET`,
		`["SECRET"]`, `null`,
	} {
		t.Run(line, func(t *testing.T) {
			s, err := New(config.SourceConfig{Name: "recon", DiscoveryFile: reportFile(t, "{\"type\":\"DNS_NAME\",\"data\":\"valid.example\"}\n"+line)})
			if err != nil {
				t.Fatal(err)
			}
			d, err := s.Discover(context.Background())
			if err == nil || d != nil {
				t.Fatal("malformed report returned a partial success")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("error echoed raw event data")
			}
		})
	}
}

func TestLocalFileBoundsAndCancellation(t *testing.T) {
	if _, err := New(config.SourceConfig{Name: "recon"}); err == nil {
		t.Fatal("accepted a missing discovery_file")
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		s, err := New(config.SourceConfig{Name: "recon", DiscoveryFile: path})
		if err != nil {
			t.Fatal(err)
		}
		if d, err := s.Discover(context.Background()); err == nil || d != nil {
			t.Fatal("accepted a missing or non-regular file")
		}
	}
	path := reportFile(t, "")
	if err := os.Truncate(path, maxReportBytes+1); err != nil {
		t.Fatal(err)
	}
	s, err := New(config.SourceConfig{Name: "recon", DiscoveryFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := s.Discover(context.Background()); err == nil || d != nil {
		t.Fatal("accepted an oversized report")
	}
	path = reportFile(t, strings.Repeat("{\"type\":\"SCAN\"}\n", maxEvents+1))
	s, err = New(config.SourceConfig{Name: "recon", DiscoveryFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := s.Discover(context.Background()); err == nil || d != nil {
		t.Fatal("accepted too many events")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d, err := s.Discover(ctx); err == nil || d != nil {
		t.Fatal("ignored cancellation")
	}
}

func TestEmptyReportRemainsPartialAndIsReread(t *testing.T) {
	path := reportFile(t, "\n")
	s, err := New(config.SourceConfig{Name: "recon", DiscoveryFile: path})
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Discover(context.Background())
	if err != nil || !d.Partial || len(d.Assets) != 0 {
		t.Fatalf("empty report = %+v, %v", d, err)
	}
	if err := os.WriteFile(path, []byte(`{"type":"DNS_NAME","data":"changed.example","module":"http://user:SECRET@example.com","timestamp":"2026-10-14T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err = s.Discover(context.Background())
	if err != nil || len(d.Assets) != 1 || d.Assets[0].Attrs["module"] != nil || d.Assets[0].Attrs["timestamp"] == nil {
		t.Fatalf("updated report was not sanitized or reread: %+v, %v", d, err)
	}
}

func TestCanonicalKeysAndInvalidBoundaries(t *testing.T) {
	for i, tc := range []struct {
		kind model.AssetKind
		raw  string
		want string
	}{
		{model.KindHostname, "XN--EXAMPLE-9D0B.COM.", "xn--example-9d0b.com"},
		{model.KindIP, "2001:0db8::1", "2001:db8::1"},
		{model.KindService, "Example.com:00443", "example.com:443/tcp"},
		{model.KindURL, "http://[2001:0db8::1]:00080/x?SECRET=value", "http://[2001:db8::1]:80/x"},
		{model.KindHostname, "127.0.0.1", ""},
		{model.KindHostname, "999.999.999.999", ""},
		{model.KindHostname, "*.example.com", ""},
		{model.KindHostname, "a..example.com", ""},
		{model.KindHostname, strings.Repeat("a", 64) + ".com", ""},
		{model.KindService, "example.com:+443", ""},
		{model.KindService, "example.com:65536", ""},
		{model.KindURL, "https://example.com:", ""},
		{model.KindURL, "https://[fe80::1%25eth0]/", ""},
		{model.KindURL, "https://example.com/" + strings.Repeat("x", 4096), ""},
	} {
		t.Run(string(tc.kind)+"/"+strconv.Itoa(i), func(t *testing.T) {
			got, ok := eventKey(tc.kind, tc.raw)
			if ok != (tc.want != "") || ok && got != tc.want {
				t.Fatalf("key = %q, %v; want %q", got, ok, tc.want)
			}
		})
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("SECRET read failure") }

type blankReader struct{}

func (blankReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	if len(p) > 0 {
		p[len(p)-1] = '\n'
	}
	return len(p), nil
}

func TestReadFailureAndGrowingReportReturnNoDiscovery(t *testing.T) {
	good := "{\"type\":\"DNS_NAME\",\"data\":\"valid.example\"}\n"
	for _, input := range []io.Reader{
		io.MultiReader(strings.NewReader(good), failedReader{}),
		io.MultiReader(strings.NewReader(good), io.LimitReader(blankReader{}, maxReportBytes)),
	} {
		d, err := readReport(context.Background(), input, "recon")
		if err == nil || d != nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("read failure was not atomic or sanitized: %v", err)
		}
	}
}

func TestProvenanceRejectsNonIdentifiersAndInvalidTimestamps(t *testing.T) {
	for _, raw := range []string{`null`, `true`, `"SECRET"`, `1e999`, `-1`, `253402300800`} {
		if got := timestamp(json.RawMessage(raw)); got != nil {
			t.Fatalf("accepted invalid timestamp: %v", got)
		}
	}
	for _, value := range []string{"", strings.Repeat("x", 257), "bad name", "https://user:SECRET@example.com"} {
		if identifier(value) {
			t.Fatal("accepted unbounded or freeform provenance")
		}
	}
}

func TestSyntheticWildcardMarkersAreIgnoredWithoutHidingMalformedNames(t *testing.T) {
	for _, tc := range []struct {
		marker string
		valid  bool
	}{
		{"_wildcard.example.com", true},
		{"_wildcard.invalid..example", false},
		{"_wildcard.", false},
		{"_wildcard.-invalid.example", false},
	} {
		t.Run(tc.marker, func(t *testing.T) {
			data := "{\"type\":\"DNS_NAME\",\"data\":\"valid.example\"}\n" +
				"{\"type\":\"DNS_NAME\",\"data\":\"" + tc.marker + "\"}"
			s, err := New(config.SourceConfig{Name: "recon", DiscoveryFile: reportFile(t, data)})
			if err != nil {
				t.Fatal(err)
			}
			d, err := s.Discover(context.Background())
			if !tc.valid {
				if err == nil || d != nil {
					t.Fatal("malformed marker hid an invalid parent domain")
				}
				return
			}
			if err != nil || len(d.Assets) != 1 || d.Assets[0].Key != "valid.example" || len(d.Relations) != 0 || !d.Partial {
				t.Fatalf("synthetic marker poisoned or polluted valid discovery: %+v, %v", d, err)
			}
		})
	}
}
