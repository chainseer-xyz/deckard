package finding

import "testing"

func certObs(days int, fp string) map[string]any {
	return map[string]any{"fingerprint": fp, "days_remaining": days, "not_after": "2027-01-01"}
}

func TestVolatileDaysRemainingNeverDrifts(t *testing.T) {
	seq := []map[string]any{}
	for i := 0; i < 10; i++ {
		seq = append(seq, certObs(90-i, "aa"))
	}
	for i, r := range run(2, seq...) {
		if len(r.Drift) != 0 {
			t.Fatalf("run %d produced drift: %+v", i, r.Drift)
		}
	}
}

func TestRealCertChangeProducesExactlyOneFinding(t *testing.T) {
	rs := run(3, certObs(90, "aa"), certObs(89, "aa"), certObs(88, "aa"), certObs(87, "bb"))
	if len(rs[3].Drift) != 1 {
		t.Fatalf("%+v", rs[3].Drift)
	}
	if fs := DriftFindings("tls.cert", rs[3].Drift); len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
}

func TestScalarDriftKeyIgnoresValue(t *testing.T) {
	a := DriftFindings("c", []Drift{{Field: "build", Change: "changed", Old: "1", New: "2"}})[0]
	b := DriftFindings("c", []Drift{{Field: "build", Change: "changed", Old: "2", New: "3"}})[0]
	if a.Key != b.Key {
		t.Fatalf("scalar key must not depend on value: %q vs %q", a.Key, b.Key)
	}
	if a.Evidence["new"] != "2" || b.Evidence["new"] != "3" {
		t.Fatal("value must be in evidence")
	}
}

func TestProcessorIgnoreFor(t *testing.T) {
	p := NewProcessor(nil, ProcessorConfig{IgnoreKeys: map[string][]string{"*": {"a"}, "c": {"b"}, "other": {"z"}}}, nil)
	got := p.ignoreFor("c")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("%v", got)
	}
}
