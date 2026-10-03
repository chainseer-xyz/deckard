package lookalike

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func names(cs []Candidate, t Technique) []string {
	var out []string
	for _, c := range cs {
		if c.Technique == t {
			out = append(out, c.Domain)
		}
	}
	return out
}

func render(cs []Candidate) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString(string(c.Technique) + "\t" + c.Domain + "\n")
	}
	return b.String()
}

func golden(t *testing.T, file string, cs []Candidate) {
	t.Helper()
	path := filepath.Join("testdata", file)
	got := render(cs)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- fixed test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs from the golden file (review the change, then run go test ./internal/lookalike -update)\ngot:\n%s", file, got)
	}
}

func TestGoldenSets(t *testing.T) {
	golden(t, "abcde.com.golden", Generate("abcde", "com", Options{TLDs: []string{"net", "org"}}))
	// A label with a hyphen and a digit under a two-label suffix: hyphen
	// insertions that would put "--" in the third and fourth position are gone.
	golden(t, "my-app1.co.uk.golden", Generate("my-app1", "co.uk", Options{TLDs: []string{"com", "co.uk", "org.uk"}, MaxUnicode: 6}))
}

func TestTechniques(t *testing.T) {
	cs := Generate("abcde", "com", Options{TLDs: []string{"net", "org"}})
	for _, tc := range []struct {
		tech Technique
		want []string
	}{
		{Omission, []string{"abcd.com", "abce.com", "abde.com", "acde.com", "bcde.com"}},
		{Repetition, []string{"aabcde.com", "abbcde.com", "abccde.com", "abcdde.com", "abcdee.com"}},
		{Transposition, []string{"abced.com", "abdce.com", "acbde.com", "bacde.com"}},
		{VowelSwap, []string{"abcda.com", "abcdi.com", "abcdo.com", "abcdu.com", "ebcde.com", "ibcde.com", "obcde.com", "ubcde.com"}},
		{Hyphen, []string{"a-bcde.com", "ab-cde.com", "abc-de.com", "abcd-e.com"}},
		{Dot, []string{"a.bcde.com", "ab.cde.com", "abc.de.com", "abcd.e.com"}},
		{Homoglyph, []string{"a6cde.com", "abccle.com"}},
		{TLDSwap, []string{"abcde.net", "abcde.org"}},
	} {
		if got := names(cs, tc.tech); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.tech, got, tc.want)
		}
	}
}

func TestReplacementAndInsertionUseKeyboardNeighbours(t *testing.T) {
	cs := Generate("sound", "com", Options{})
	// 's' sits next to a, w, e, d, x, z; 'u' next to y, i, 7, 8, h, j.
	rep := names(cs, Replacement)
	for _, want := range []string{"aound.com", "xound.com", "soind.com", "so7nd.com", "sojnd.com"} {
		if !slices.Contains(rep, want) {
			t.Errorf("replacement lacks %q", want)
		}
	}
	if slices.Contains(rep, "pound.com") {
		t.Error("replacement used a key that is not adjacent")
	}
	ins := names(cs, Insertion)
	for _, want := range []string{"asound.com", "saound.com", "souind.com", "soiund.com"} {
		if !slices.Contains(ins, want) {
			t.Errorf("insertion lacks %q", want)
		}
	}
}

func TestBitFlipStaysInTheHostnameAlphabet(t *testing.T) {
	flips := names(Generate("abcde", "com", Options{}), BitFlip)
	if !slices.Contains(flips, "cbcde.com") || !slices.Contains(flips, "abcdg.com") {
		t.Fatalf("bitflip lacks the expected flips: %v", flips)
	}
	// Flipping bit 5 of a letter gives its uppercase form (the same domain, so
	// never emitted); flipping bit 4 of "p" gives "`", not a hostname byte.
	for _, f := range flips {
		if !ValidName(f) {
			t.Errorf("bitflip emitted an invalid name %q", f)
		}
		if f == "abcde.com" || strings.ContainsAny(f, "ABCDEFGHIJKLMNOPQRSTUVWXYZ`") {
			t.Errorf("bitflip emitted %q", f)
		}
	}
}

func TestHomoglyphs(t *testing.T) {
	got := names(Generate("modem", "com", Options{}), Homoglyph)
	// m0dem.com is also a keyboard neighbour: the earlier technique claims it.
	for _, want := range []string{"rnodem.com", "modern.com", "moclem.com"} {
		if !slices.Contains(got, want) {
			t.Errorf("homoglyph lacks %q in %v", want, got)
		}
	}
	if got := names(Generate("corner", "com", Options{}), Homoglyph); !slices.Contains(got, "comer.com") {
		t.Errorf("rn -> m missing: %v", got)
	}
	got = names(Generate("wavve", "com", Options{}), Homoglyph)
	if !slices.Contains(got, "vvavve.com") || !slices.Contains(got, "wawe.com") {
		t.Errorf("w <-> vv missing: %v", got)
	}
	if got := names(Generate("level", "com", Options{}), Homoglyph); !slices.Contains(got, "1evel.com") || !slices.Contains(got, "ievel.com") {
		t.Errorf("l -> 1 / i missing: %v", got)
	}
}

func TestUnicodeVariantsArePunycodeAndCapped(t *testing.T) {
	all := names(Generate("seasonal", "com", Options{MaxUnicode: 1000}), Unicode)
	if len(all) < 20 {
		t.Fatalf("expected many unicode variants, got %d", len(all))
	}
	for _, n := range all {
		if !strings.HasPrefix(n, "xn--") || !strings.HasSuffix(n, ".com") || !ValidName(n) {
			t.Errorf("not a valid punycode candidate: %q", n)
		}
	}
	capped := names(Generate("seasonal", "com", Options{MaxUnicode: 5}), Unicode)
	if len(capped) != 5 {
		t.Fatalf("cap not applied: %d", len(capped))
	}
	for _, c := range capped {
		if !slices.Contains(all, c) {
			t.Errorf("capped variant %q is not among the uncapped ones", c)
		}
	}
	if !slices.Equal(capped, names(Generate("seasonal", "com", Options{MaxUnicode: 5}), Unicode)) {
		t.Error("the cap is not deterministic")
	}
	if def := names(Generate("internationalisation", "com", Options{}), Unicode); len(def) != DefaultMaxUnicode {
		t.Errorf("default cap = %d, want %d", len(def), DefaultMaxUnicode)
	}
	if off := names(Generate("seasonal", "com", Options{MaxUnicode: -1}), Unicode); len(off) != 0 {
		t.Errorf("a negative cap should disable the technique, got %d", len(off))
	}
	// The cap spreads over the label: it is not just the first few variants.
	if slices.Equal(capped, all[:5]) {
		t.Error("capped variants are the first five: the cap should spread over the label")
	}
}

func TestDeterministicUniqueAndNeverTheOriginal(t *testing.T) {
	a, b := Generate("example", "com", Options{}), Generate("example", "com", Options{})
	if !reflect.DeepEqual(a, b) {
		t.Fatal("Generate is not deterministic")
	}
	rank := map[Technique]int{}
	for i, tc := range Techniques {
		rank[tc] = i
	}
	seen := map[string]bool{}
	last := -1
	for _, c := range a {
		if seen[c.Domain] {
			t.Errorf("duplicate %q", c.Domain)
		}
		seen[c.Domain] = true
		if c.Domain == "example.com" {
			t.Error("the original was emitted")
		}
		if rank[c.Technique] < last {
			t.Errorf("techniques out of order at %q", c.Domain)
		}
		last = rank[c.Technique]
	}
	if len(a) < 150 {
		t.Errorf("only %d candidates for a 7-letter label", len(a))
	}
}

func TestEveryCandidateIsAValidName(t *testing.T) {
	for _, in := range [][2]string{{"example", "com"}, {"my-app1", "co.uk"}, {"a1b2c3d4", "io"}, {strings.Repeat("a", 60), "com"}, {strings.Repeat("a", 63), "com"}} {
		for _, c := range Generate(in[0], in[1], Options{}) {
			if !ValidName(c.Domain) {
				t.Errorf("%s: invalid candidate %q (%s)", in[0], c.Domain, c.Technique)
			}
			if c.Domain != strings.ToLower(c.Domain) || strings.ContainsAny(c.Domain, " _/") {
				t.Errorf("%s: bad characters in %q", in[0], c.Domain)
			}
		}
	}
}

func TestValidLabelAndName(t *testing.T) {
	for _, l := range []string{"a", "a-b", "a1", "1a", "a--b", "xn--abc", strings.Repeat("a", 63)} {
		if !ValidLabel(l) {
			t.Errorf("ValidLabel(%q) = false", l)
		}
	}
	for _, l := range []string{"", "-a", "a-", "ab--c", "A", "a_b", "a b", "é", strings.Repeat("a", 64)} {
		if ValidLabel(l) {
			t.Errorf("ValidLabel(%q) = true", l)
		}
	}
	if ValidName("") || ValidName("a..b") || ValidName("a.b.") || ValidName(strings.Repeat("a.", 130)+"com") {
		t.Error("ValidName accepted an invalid name")
	}
	if !ValidName("ex.ample.co.uk") {
		t.Error("ValidName rejected a valid name")
	}
}

func TestOwnedAndIgnoredNamesAreNeverEmitted(t *testing.T) {
	skip := []string{"example.net", "ample.com", "Partner.example.org."}
	opts := Options{TLDs: []string{"net", "org", "io"}}
	// Control: without the skip list the names are generated.
	control := map[string]bool{}
	for _, c := range Generate("example", "com", opts) {
		control[c.Domain] = true
	}
	for _, n := range []string{"example.net", "ex.ample.com", "example.io"} {
		if !control[n] {
			t.Fatalf("control run lacks %q", n)
		}
	}
	opts.Skip = skip
	got := map[string]bool{}
	for _, c := range Generate("example", "com", opts) {
		got[c.Domain] = true
		for _, s := range []string{"example.net", "ample.com", "partner.example.org"} {
			if c.Domain == s || strings.HasSuffix(c.Domain, "."+s) {
				t.Errorf("%q is inside the skipped zone %q", c.Domain, s)
			}
		}
	}
	// ex.ample.com is the dot-split of example.com but lives under the owned
	// zone ample.com; example.io is unrelated and stays.
	if got["ex.ample.com"] || got["example.net"] {
		t.Error("an owned zone leaked into the candidates")
	}
	if !got["example.io"] || !got["example.org"] {
		t.Error("an unrelated name was dropped")
	}
}

func TestOtherOwnedApexesAreExcludedFromTLDSwap(t *testing.T) {
	// The estate owns example.net and example.org: they are not lookalikes.
	cs := Generate("example", "com", Options{TLDs: []string{"net", "org", "dev"}, Skip: []string{"example.net", "example.org"}})
	if got := names(cs, TLDSwap); !reflect.DeepEqual(got, []string{"example.dev"}) {
		t.Errorf("tld-swap = %v, want only example.dev", got)
	}
}

func TestShortInvalidAndInternationalisedLabelsProduceNothing(t *testing.T) {
	for _, l := range []string{"abcd", "ab", "", "-abcde", "abcde-", "ab--cde", "xn--abcde", "ABC_DE", "abcdé"} {
		if cs := Generate(l, "com", Options{}); cs != nil {
			t.Errorf("Generate(%q) = %d candidates, want none", l, len(cs))
		}
	}
	if Generate("abcde", "", Options{}) != nil || Generate("abcde", "co..uk", Options{}) != nil {
		t.Error("an empty or invalid suffix produced candidates")
	}
	if len(Generate("abcd", "com", Options{MinLabelLength: 4})) == 0 {
		t.Error("min label length 4 should allow a 4-letter label")
	}
	if Generate("abcdefgh", "com", Options{MinLabelLength: 9}) != nil {
		t.Error("min label length 9 should skip an 8-letter label")
	}
	// Upper case input is normalised, not rejected.
	if len(Generate("ABCDE", "COM", Options{})) == 0 {
		t.Error("upper case input produced nothing")
	}
}

func TestTLDOptions(t *testing.T) {
	// "com" is the original and is never emitted.
	if got := names(Generate("example", "com", Options{}), TLDSwap); len(got) != len(DefaultTLDs)-1 {
		t.Errorf("default tld-swap emitted %d names, want %d", len(got), len(DefaultTLDs)-1)
	}
	if got := names(Generate("example", "com", Options{TLDs: []string{}}), TLDSwap); len(got) != 0 {
		t.Errorf("an empty non-nil list should disable tld-swap, got %v", got)
	}
	got := names(Generate("example", "com", Options{TLDs: []string{" .NET ", "co.uk", "", "bad_tld", "-x"}}), TLDSwap)
	if !reflect.DeepEqual(got, []string{"example.co.uk", "example.net"}) {
		t.Errorf("tld normalisation and validation: %v", got)
	}
}

func TestLimitRoundRobinsAcrossTechniques(t *testing.T) {
	cs := Generate("example", "com", Options{})
	got := Limit(cs, 24)
	if len(got) != 24 {
		t.Fatalf("len = %d", len(got))
	}
	count := map[Technique]int{}
	for _, c := range got {
		count[c.Technique]++
	}
	for _, tc := range Techniques {
		if count[tc] != 2 {
			t.Errorf("technique %s kept %d candidates, want 2 (12 techniques, 24 slots)", tc, count[tc])
		}
	}
	if !reflect.DeepEqual(got, Limit(cs, 24)) {
		t.Error("Limit is not deterministic")
	}
	var om []string
	for _, c := range got {
		if c.Technique == Omission {
			om = append(om, c.Domain)
		}
	}
	if !slices.IsSorted(om) || len(om) != 2 {
		t.Errorf("omission picks: %v", om)
	}
	if all := Limit(cs, 0); len(all) != len(cs) {
		t.Errorf("Limit(0) = %d, want all %d", len(all), len(cs))
	}
	if all := Limit(cs, len(cs)+100); len(all) != len(cs) {
		t.Errorf("Limit(over) = %d, want all %d", len(all), len(cs))
	}
	if len(Limit(nil, 5)) != 0 {
		t.Error("Limit(nil) should be empty")
	}
	// A technique with fewer names than its share does not starve the others,
	// and nothing is lost or duplicated.
	few := Generate("abcde", "com", Options{TLDs: []string{"net"}})
	seen := map[string]bool{}
	for _, c := range Limit(few, 0) {
		if seen[c.Domain] {
			t.Errorf("Limit duplicated %q", c.Domain)
		}
		seen[c.Domain] = true
	}
	if len(seen) != len(few) {
		t.Errorf("Limit lost candidates: %d of %d", len(seen), len(few))
	}
}

func TestQwertyTable(t *testing.T) {
	for k, want := range map[byte]string{'g': "fhtyvb", 'q': "12wa", 'm': "nkj", 'p': "o0l"} {
		got := qwerty[k]
		for _, c := range []byte(want) {
			if !strings.ContainsRune(got, rune(c)) {
				t.Errorf("neighbours of %q = %q, lacks %q", k, got, c)
			}
		}
	}
	if strings.ContainsRune(qwerty['g'], 'g') {
		t.Error("a key is its own neighbour")
	}
}

// TestCandidateVolume pins the order of magnitude documented for operators
// (docs/operations.md): with the default TLD list, a brand label of 5 to 12
// letters yields a few hundred candidates, and the default cap of 600 only
// bites for long labels.
func TestCandidateVolume(t *testing.T) {
	for _, tc := range []struct {
		label    string
		min, max int
	}{
		{"acme1", 100, 200},
		{"example", 150, 250},
		{"northwind", 200, 350},
		{"contosofinance", 300, 500},
		{"internationalisationltd", 500, 800},
	} {
		n := len(Generate(tc.label, "com", Options{}))
		t.Logf("%-24s %4d candidates", tc.label, n)
		if n < tc.min || n > tc.max {
			t.Errorf("%s: %d candidates, documented range %d..%d", tc.label, n, tc.min, tc.max)
		}
	}
}
