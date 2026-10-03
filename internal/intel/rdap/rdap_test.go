package rdap

import (
	"errors"
	"os"
	"slices"
	"testing"
	"time"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func date(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

func TestParseDomainFixtures(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		file, domain string
		want         Domain
	}{
		{"verisign_example_com.json", "example.com.", Domain{
			Name: "example.com", Registrar: "Example Registrar, Inc.", RegistrarIANAID: "376",
			Nameservers: []string{"a.iana-servers.net", "b.iana-servers.net"},
			Statuses: []string{StatusClientDeleteProhibited, StatusClientTransferProhibited, "client update prohibited",
				StatusServerDeleteProhibited, StatusServerTransferProhibited, "server update prohibited"},
			Registered:  date("1995-08-14T04:00:00Z"),
			Expires:     date("2027-08-13T04:00:00Z"),
			LastChanged: date("2026-08-14T07:01:44Z"),
			DNSSEC:      &yes,
		}},
		{"cctld_example_eu.json", "EXAMPLE.EU", Domain{
			Name: "example.eu", Registrar: "Example Domains SA",
			Nameservers: []string{"ns1.dns.example.net", "ns2.dns.example.net"},
			Statuses:    []string{"active", StatusAutoRenewPeriod, StatusClientDeleteProhibited, StatusClientTransferProhibited},
			Registered:  date("2006-04-07T00:00:00Z"),
			Expires:     date("2027-04-30T00:00:00Z"), // registrar expiration as the fallback
			LastChanged: date("2026-03-02T09:15:30.123Z"),
			DNSSEC:      &no,
		}},
		{"noevents_example_org.json", "example.org", Domain{
			Name: "example.org", Registrar: "9999", Nameservers: []string{"ns.example.org"}, Statuses: []string{"ok"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got, err := ParseDomain(load(t, tc.file), tc.domain)
			if err != nil {
				t.Fatal(err)
			}
			w := tc.want
			if got.Name != w.Name || got.Registrar != w.Registrar || got.RegistrarIANAID != w.RegistrarIANAID {
				t.Errorf("identity = %q %q %q", got.Name, got.Registrar, got.RegistrarIANAID)
			}
			if !slices.Equal(got.Nameservers, w.Nameservers) {
				t.Errorf("nameservers = %v", got.Nameservers)
			}
			if !slices.Equal(got.Statuses, w.Statuses) {
				t.Errorf("statuses = %q", got.Statuses)
			}
			if !got.Registered.Equal(w.Registered) || !got.Expires.Equal(w.Expires) || !got.LastChanged.Equal(w.LastChanged) {
				t.Errorf("events = %s %s %s", got.Registered, got.Expires, got.LastChanged)
			}
			if (got.DNSSEC == nil) != (w.DNSSEC == nil) || (got.DNSSEC != nil && *got.DNSSEC != *w.DNSSEC) {
				t.Errorf("dnssec = %v", got.DNSSEC)
			}
		})
	}
}

func TestParseDomainRejects(t *testing.T) {
	for name, tc := range map[string]struct{ body, domain string }{
		"invalid json":   {`{"ldhName":`, "example.com"},
		"other domain":   {`{"objectClassName":"domain","ldhName":"example.net"}`, "example.com"},
		"no name":        {`{"objectClassName":"domain"}`, "example.com"},
		"entity object":  {`{"objectClassName":"entity","ldhName":"example.com"}`, "example.com"},
		"error object":   {`{"errorCode":404,"title":"Not Found","ldhName":"example.com"}`, "example.com"},
		"array response": {`[]`, "example.com"},
	} {
		if _, err := ParseDomain([]byte(tc.body), tc.domain); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name != "invalid json" && name != "array response" && !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: err = %v, want ErrMismatch", name, err)
		}
	}
}

func TestNormalizeStatus(t *testing.T) {
	for in, want := range map[string]string{
		"clientTransferProhibited":   StatusClientTransferProhibited,
		"client_transfer_prohibited": StatusClientTransferProhibited,
		"Client Transfer Prohibited": StatusClientTransferProhibited,
		" server-delete-prohibited ": StatusServerDeleteProhibited,
		"redemptionPeriod":           StatusRedemptionPeriod,
		"pending delete":             StatusPendingDelete,
		"pendingTransfer":            StatusPendingTransfer,
		"autoRenewPeriod":            StatusAutoRenewPeriod,
		"ok":                         "ok",
		"":                           "",
		"lastUpdateOfRDAPDatabase":   "last update of rdapdatabase",
		"addPeriod \tgracePeriod":    "add period grace period",
	} {
		if got := NormalizeStatus(in); got != want {
			t.Errorf("NormalizeStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistrarTextIsSanitised(t *testing.T) {
	body := `{"objectClassName":"domain","ldhName":"example.com","entities":[{"roles":["registrar"],
	"vcardArray":["vcard",[["fn",{},"text","Evil\u0000 Registrar\n\tLtd"]]]}]}`
	d, err := ParseDomain([]byte(body), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Registrar != "Evil Registrar Ltd" {
		t.Errorf("registrar = %q", d.Registrar)
	}
	if d.Has(StatusClientTransferProhibited) || d.Statuses != nil || d.DNSSEC != nil {
		t.Errorf("empty domain = %+v", d)
	}
}
