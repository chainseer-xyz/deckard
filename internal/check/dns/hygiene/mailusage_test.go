package hygiene

import (
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func find(fs []model.FindingInput, key string) *model.FindingInput {
	for i := range fs {
		if fs[i].Key == key {
			return &fs[i]
		}
	}
	return nil
}

func TestSeverityByMailUsage(t *testing.T) {
	noAXFR := map[string]any{"check_axfr": false}
	// No MX (parked zone): DMARC and SPF missing are low, with null-sender advice.
	q := checktest.NewDNS().Add("nothing.example.com. 60 IN MX 0 .")
	got, _ := runDNSZone(t, "nothing.example.com", q, noAXFR)
	for _, k := range []string{"dmarc-missing", "spf-missing"} {
		if got.keys[k] != model.SeverityLow {
			t.Errorf("no-MX %s = %q want low (%v)", k, got.keys[k], got.keys)
		}
	}
	d := find(got.all, "dmarc-missing")
	if d == nil || !strings.Contains(d.Remediation, "v=DMARC1; p=reject;") || !strings.Contains(d.Description, "spoofed") {
		t.Errorf("dmarc advice: %+v", d)
	}
	s := find(got.all, "spf-missing")
	if s == nil || !strings.Contains(s.Remediation, "v=spf1 -all") || !strings.Contains(s.Description, "spoofed") {
		t.Errorf("spf advice: %+v", s)
	}

	// MX present: DMARC missing medium, SPF missing medium (mx-without-spf).
	q = checktest.NewDNS().Add("nothing.example.com. 60 IN MX 10 mail.example.net.")
	got, _ = runDNSZone(t, "nothing.example.com", q, noAXFR)
	if got.keys["dmarc-missing"] != model.SeverityMedium || got.keys["mx-without-spf"] != model.SeverityMedium {
		t.Errorf("MX zone: %v", got.keys)
	}

	// expects_mail override forces mail treatment even when MX says none.
	q = checktest.NewDNS().Add("nothing.example.com. 60 IN MX 0 .")
	got, _ = runDNSZone(t, "nothing.example.com", q, map[string]any{"check_axfr": false, "expects_mail": true})
	if got.keys["dmarc-missing"] != model.SeverityMedium || got.keys["spf-missing"] != model.SeverityMedium {
		t.Errorf("expects_mail: %v", got.keys)
	}

	// p=none stays low; No CAA stays info.
	q = checktest.NewDNS().Add("open.example.com. 60 IN MX 10 mail.example.net.")
	got, _ = runDNSZone(t, "open.example.com", q, noAXFR)
	if got.keys["dmarc-p-none"] != model.SeverityLow || got.keys["caa-missing"] != model.SeverityInfo {
		t.Errorf("%v", got.keys)
	}
}
