package model

import (
	"strings"
	"testing"
)

func TestSeverityOrdering(t *testing.T) {
	tests := []struct {
		name string
		a, b Severity
		want bool
	}{
		{"critical beats high", SeverityCritical, SeverityHigh, true},
		{"equal is at least", SeverityMedium, SeverityMedium, true},
		{"low below medium", SeverityLow, SeverityMedium, false},
		{"unknown below info", Severity("bogus"), SeverityInfo, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.AtLeast(tc.b); got != tc.want {
				t.Fatalf("%s.AtLeast(%s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestSeverityAndTierValid(t *testing.T) {
	if !SeverityHigh.Valid() || Severity("x").Valid() {
		t.Fatal("severity validity wrong")
	}
	if !TierActive.Valid() || Tier("x").Valid() {
		t.Fatal("tier validity wrong")
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := Fingerprint("dns.dangling", "a.example.com", "")
	if a != Fingerprint("dns.dangling", "a.example.com", "") {
		t.Fatal("fingerprint not deterministic")
	}
	if a == Fingerprint("dns.dangling", "b.example.com", "") {
		t.Fatal("different assets must differ")
	}
	if a == Fingerprint("dns.dangling", "a.example.com", "x") {
		t.Fatal("different finding keys must differ")
	}
	// separator must prevent ("ab","c") colliding with ("a","bc")
	if Fingerprint("ab", "c", "") == Fingerprint("a", "bc", "") {
		t.Fatal("field boundary collision")
	}
}

func TestValidIngestTool(t *testing.T) {
	for _, ok := range []string{"prowler", "e2e-selftest", "s3scanner", "a1", "0x", strings.Repeat("a", 32)} {
		if !ValidIngestTool(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "a", "-x", "Prowler", "pro_wler", "pro.wler", "pro wler", "prowl\u00e9r", strings.Repeat("a", 33), "x|y"} {
		if ValidIngestTool(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
	if IngestCheck("prowler") != "ext.prowler" || IngestSource("prowler") != "ingest:prowler" || !IsIngestSource("ingest:x") || IsIngestSource("cf") {
		t.Fatal("ingest naming helpers wrong")
	}
}
