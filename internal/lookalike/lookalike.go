// Package lookalike generates the domain names an attacker might register to
// imitate a brand domain: typos, confusable characters, extra separators and
// other top-level domains. It is pure: it performs no lookups and holds no
// state, so its output is a deterministic function of its input.
//
// The input is the registrable domain split into its label and its public
// suffix ("example" and "com", "example" and "co.uk"). Every candidate is a
// syntactically valid, lowercase, de-duplicated hostname that differs from the
// original and from every name the caller says it owns or ignores.
//
// Techniques, in the order they claim a name when two produce the same one:
//
//	omission        one character removed                 exmple.com
//	repetition      one character doubled                 exaample.com
//	transposition   two adjacent characters swapped       exmaple.com
//	replacement     a character replaced by a QWERTY      ecample.com
//	                neighbour
//	insertion       a QWERTY neighbour inserted next to   exsample.com
//	                a character
//	homoglyph       look-alike ASCII sequences            examp1e.com, exarnple.com
//	unicode         confusable Unicode letters, as        xn--exmple-...
//	                punycode (capped)
//	vowel-swap      a vowel replaced by another vowel     exomple.com
//	hyphen          a hyphen inserted                     ex-ample.com
//	dot             the label split into a subdomain      ex.ample.com
//	bitflip         one bit of one character flipped,     eyample.com
//	                when the result is still a valid
//	                hostname character
//	tld-swap        the public suffix replaced            example.net
package lookalike

import (
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

// Technique names how a candidate was derived.
type Technique string

// The techniques, in claim order (see the package comment).
const (
	Omission      Technique = "omission"
	Repetition    Technique = "repetition"
	Transposition Technique = "transposition"
	Replacement   Technique = "replacement"
	Insertion     Technique = "insertion"
	Homoglyph     Technique = "homoglyph"
	Unicode       Technique = "unicode"
	VowelSwap     Technique = "vowel-swap"
	Hyphen        Technique = "hyphen"
	Dot           Technique = "dot"
	BitFlip       Technique = "bitflip"
	TLDSwap       Technique = "tld-swap"
)

// Techniques lists every technique in claim order.
var Techniques = []Technique{
	Omission, Repetition, Transposition, Replacement, Insertion, Homoglyph,
	Unicode, VowelSwap, Hyphen, Dot, BitFlip, TLDSwap,
}

// Defaults.
const (
	// DefaultMinLabelLength is the shortest brand label that is permuted.
	DefaultMinLabelLength = 5
	// DefaultMaxUnicode caps the confusable-Unicode candidates per domain.
	DefaultMaxUnicode = 40
)

// DefaultTLDs is the list of suffixes tried by the tld-swap technique when
// the caller gives none: common generic and country-code registries that are
// open to anyone.
var DefaultTLDs = []string{
	"com", "net", "org", "info", "biz", "io", "co", "app", "dev", "xyz",
	"online", "site", "shop", "store", "tech", "cloud", "ai", "us", "uk",
	"eu", "de", "fr", "nl", "ru", "cn",
}

// Candidate is one generated name and the technique that produced it.
type Candidate struct {
	Domain    string
	Technique Technique
}

// Options tunes Generate. The zero value uses the defaults.
type Options struct {
	// TLDs are the suffixes the tld-swap technique tries. Nil uses
	// DefaultTLDs; an empty non-nil slice disables the technique.
	TLDs []string
	// MinLabelLength skips labels shorter than this (zero uses
	// DefaultMinLabelLength). Short labels yield mostly meaningless noise.
	MinLabelLength int
	// MaxUnicode caps the unicode technique (zero uses DefaultMaxUnicode,
	// negative disables it).
	MaxUnicode int
	// Skip lists names that are never emitted: a candidate equal to, or under,
	// any entry is dropped. Callers pass every owned zone (the estate
	// legitimately owns many variants of its own names) and the names the
	// operator ignores.
	Skip []string
}

// Generate returns the lookalikes of label.suffix, ordered by technique and
// then by name. It returns nil for a label that is not a plain LDH label, for
// an internationalised label (xn--...), and for labels shorter than
// o.MinLabelLength.
func Generate(label, suffix string, o Options) []Candidate {
	label, suffix = strings.ToLower(label), strings.Trim(strings.ToLower(suffix), ".")
	minLen := o.MinLabelLength
	if minLen <= 0 {
		minLen = DefaultMinLabelLength
	}
	if !ValidLabel(label) || strings.HasPrefix(label, "xn--") || len(label) < minLen || !validSuffix(suffix) {
		return nil
	}
	skip := make([]string, 0, len(o.Skip)+1)
	skip = append(skip, label+"."+suffix)
	for _, s := range o.Skip {
		if s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), "."); s != "" {
			skip = append(skip, s)
		}
	}

	g := &gen{seen: map[string]bool{}, skip: skip}
	for _, t := range Techniques {
		var names []string
		switch t {
		case Omission:
			names = omission(label, suffix)
		case Repetition:
			names = repetition(label, suffix)
		case Transposition:
			names = transposition(label, suffix)
		case Replacement:
			names = replacement(label, suffix)
		case Insertion:
			names = insertion(label, suffix)
		case Homoglyph:
			names = homoglyphs(label, suffix)
		case Unicode:
			names = unicodeVariants(label, suffix, o.MaxUnicode)
		case VowelSwap:
			names = vowelSwap(label, suffix)
		case Hyphen:
			names = hyphen(label, suffix)
		case Dot:
			names = dot(label, suffix)
		case BitFlip:
			names = bitFlip(label, suffix)
		case TLDSwap:
			names = tldSwap(label, o.TLDs)
		}
		g.add(t, names)
	}
	return g.out
}

type gen struct {
	seen map[string]bool
	skip []string
	out  []Candidate
}

// add keeps the valid, new, unskipped names of one technique, sorted.
func (g *gen) add(t Technique, names []string) {
	sort.Strings(names)
	for _, n := range names {
		if g.seen[n] || !ValidName(n) || under(n, g.skip) {
			continue
		}
		g.seen[n] = true
		g.out = append(g.out, Candidate{Domain: n, Technique: t})
	}
}

// under reports whether name equals, or is a subdomain of, any zone.
func under(name string, zones []string) bool {
	for _, z := range zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return true
		}
	}
	return false
}

// Limit returns at most n candidates, taken round-robin across the techniques
// (each technique's names in their sorted order) so that a cap never removes a
// whole technique. The result is in that round-robin order, which is also a
// good order to query in: whatever is cut short by a budget is spread evenly.
// n <= 0 returns every candidate in round-robin order.
func Limit(cs []Candidate, n int) []Candidate {
	by := map[Technique][]Candidate{}
	for _, c := range cs {
		by[c.Technique] = append(by[c.Technique], c)
	}
	total := len(cs)
	if n <= 0 || n > total {
		n = total
	}
	out := make([]Candidate, 0, n)
	for i := 0; len(out) < n; i++ {
		for _, t := range Techniques {
			if l := by[t]; i < len(l) && len(out) < n {
				out = append(out, l[i])
			}
		}
	}
	return out
}

// ValidLabel reports whether l is a valid lowercase LDH hostname label: 1 to
// 63 characters of a-z, 0-9 and hyphen, with no leading or trailing hyphen and
// no hyphens in the third and fourth positions unless it is an "xn--" label
// (RFC 5891 reserves them).
func ValidLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	if len(l) >= 4 && l[2:4] == "--" && !strings.HasPrefix(l, "xn--") {
		return false
	}
	return true
}

// ValidName reports whether every label of name is valid and the whole name
// fits in 253 characters.
func ValidName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, l := range strings.Split(name, ".") {
		if !ValidLabel(l) {
			return false
		}
	}
	return true
}

func validSuffix(s string) bool { return s != "" && ValidName(s) }

// ---- techniques -------------------------------------------------------------

func omission(l, sfx string) []string {
	var out []string
	for i := range len(l) {
		out = append(out, l[:i]+l[i+1:]+"."+sfx)
	}
	return out
}

func repetition(l, sfx string) []string {
	var out []string
	for i := range len(l) {
		if l[i] == '-' {
			continue
		}
		out = append(out, l[:i+1]+l[i:]+"."+sfx)
	}
	return out
}

func transposition(l, sfx string) []string {
	var out []string
	for i := 0; i+1 < len(l); i++ {
		if l[i] == l[i+1] {
			continue
		}
		out = append(out, l[:i]+string(l[i+1])+string(l[i])+l[i+2:]+"."+sfx)
	}
	return out
}

// qwerty maps each key to its neighbours on a QWERTY keyboard (same row, and
// the keys diagonally above and below).
var qwerty = func() map[byte]string {
	rows := []string{"1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"}
	m := map[byte]string{}
	for r, row := range rows {
		for c := range len(row) {
			var n []byte
			add := func(rr, cc int) {
				if rr >= 0 && rr < len(rows) && cc >= 0 && cc < len(rows[rr]) {
					n = append(n, rows[rr][cc])
				}
			}
			add(r, c-1)
			add(r, c+1)
			// Rows are staggered: the key above/below sits between two keys.
			for _, rr := range []int{r - 1, r + 1} {
				add(rr, c)
				if rr > r {
					add(rr, c-1)
				} else {
					add(rr, c+1)
				}
			}
			m[row[c]] = string(n)
		}
	}
	return m
}()

func replacement(l, sfx string) []string {
	var out []string
	for i := range len(l) {
		for _, n := range []byte(qwerty[l[i]]) {
			out = append(out, l[:i]+string(n)+l[i+1:]+"."+sfx)
		}
	}
	return out
}

func insertion(l, sfx string) []string {
	var out []string
	for i := range len(l) {
		for _, n := range []byte(qwerty[l[i]]) {
			out = append(out, l[:i]+string(n)+l[i:]+"."+sfx, l[:i+1]+string(n)+l[i+1:]+"."+sfx)
		}
	}
	return out
}

func vowelSwap(l, sfx string) []string {
	const vowels = "aeiou"
	var out []string
	for i := range len(l) {
		if !strings.ContainsRune(vowels, rune(l[i])) {
			continue
		}
		for _, v := range []byte(vowels) {
			if v != l[i] {
				out = append(out, l[:i]+string(v)+l[i+1:]+"."+sfx)
			}
		}
	}
	return out
}

func hyphen(l, sfx string) []string {
	var out []string
	for i := 1; i < len(l); i++ {
		out = append(out, l[:i]+"-"+l[i:]+"."+sfx)
	}
	return out
}

func dot(l, sfx string) []string {
	var out []string
	for i := 1; i < len(l); i++ {
		out = append(out, l[:i]+"."+l[i:]+"."+sfx)
	}
	return out
}

func bitFlip(l, sfx string) []string {
	var out []string
	for i := range len(l) {
		for bit := range 8 {
			c := l[i] ^ (1 << bit)
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				out = append(out, l[:i]+string(c)+l[i+1:]+"."+sfx)
			}
		}
	}
	return out
}

func tldSwap(l string, tlds []string) []string {
	if tlds == nil {
		tlds = DefaultTLDs
	}
	var out []string
	for _, t := range tlds {
		if t = strings.Trim(strings.ToLower(strings.TrimSpace(t)), "."); t != "" {
			out = append(out, l+"."+t)
		}
	}
	return out
}

// homoglyphRules are ASCII sequences that look alike. Each rule is applied at
// every occurrence on its own; rules are not combined.
var homoglyphRules = [][2]string{
	{"m", "rn"}, {"rn", "m"}, {"w", "vv"}, {"vv", "w"},
	{"l", "1"}, {"1", "l"}, {"l", "i"}, {"i", "l"}, {"i", "1"}, {"1", "i"},
	{"o", "0"}, {"0", "o"}, {"d", "cl"}, {"cl", "d"}, {"s", "5"}, {"5", "s"},
	{"g", "q"}, {"q", "g"}, {"b", "6"}, {"6", "b"}, {"z", "2"}, {"2", "z"},
}

func homoglyphs(l, sfx string) []string {
	var out []string
	for _, r := range homoglyphRules {
		for from := 0; ; {
			i := strings.Index(l[from:], r[0])
			if i < 0 {
				break
			}
			i += from
			out = append(out, l[:i]+r[1]+l[i+len(r[0]):]+"."+sfx)
			from = i + 1
		}
	}
	return out
}

// confusables maps a Latin letter to Unicode letters that render like it:
// Cyrillic look-alikes and common diacritic forms.
var confusables = map[rune][]rune{
	'a': {'а', 'à', 'á', 'ä', 'â'}, // Cyrillic а, a-grave, a-acute, a-diaeresis, a-circumflex
	'c': {'с', 'ç', 'ċ'},
	'd': {'ԁ', 'ď'},
	'e': {'е', 'è', 'é', 'ë', 'ê'},
	'g': {'ġ', 'ğ'},
	'h': {'һ'},
	'i': {'і', 'í', 'ï', 'ì', 'î'},
	'j': {'ј'},
	'l': {'ӏ', 'ĺ', 'ł'},
	'n': {'ñ', 'ń', 'ո'},
	'o': {'о', 'ó', 'ö', 'ò', 'ô', 'ο'},
	'p': {'р'},
	's': {'ѕ', 'ś', 'š'},
	'u': {'ü', 'ú', 'ù', 'û', 'υ'},
	'x': {'х'},
	'y': {'у', 'ý', 'ÿ'},
	'z': {'ž', 'ź', 'ż'},
}

func unicodeVariants(l, sfx string, limit int) []string {
	if limit == 0 {
		limit = DefaultMaxUnicode
	}
	if limit < 0 {
		return nil
	}
	var out []string
	for i := range len(l) {
		for _, r := range confusables[rune(l[i])] {
			u := l[:i] + string(r) + l[i+1:]
			a, err := idna.Lookup.ToASCII(u)
			if err != nil || !strings.HasPrefix(a, "xn--") || !ValidLabel(a) {
				continue
			}
			out = append(out, a+"."+sfx)
		}
	}
	if len(out) <= limit {
		return out
	}
	// Take evenly spaced variants in generation order (left to right through the
	// label): deterministic, and the cap spreads over the whole label instead
	// of exhausting its first few letters.
	kept := make([]string, 0, limit)
	for k := range limit {
		kept = append(kept, out[k*len(out)/limit])
	}
	return kept
}
