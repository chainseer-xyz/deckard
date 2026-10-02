package hygiene

import (
	"context"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
)

// Mechanism is one SPF term.
type Mechanism struct {
	Qualifier string // "+", "-", "~", "?"
	Name      string // all, include, a, mx, ptr, exists, ip4, ip6, redirect
	Value     string
}

// SPF is a parsed v=spf1 record.
type SPF struct {
	Mechanisms []Mechanism
	// All is the qualifier of the `all` mechanism, "" when absent.
	All string
	// Redirect is the redirect= modifier target, if any.
	Redirect string
}

// IsSPFRecord reports whether txt is an SPF record.
func IsSPFRecord(txt string) bool {
	t := strings.ToLower(strings.TrimSpace(txt))
	return t == "v=spf1" || strings.HasPrefix(t, "v=spf1 ")
}

// ParseSPF parses an SPF record; ok is false when txt is not SPF.
func ParseSPF(txt string) (spf SPF, ok bool) {
	if !IsSPFRecord(txt) {
		return SPF{}, false
	}
	for _, term := range strings.Fields(txt)[1:] {
		term = strings.ToLower(term)
		if strings.HasPrefix(term, "redirect=") {
			spf.Redirect = strings.TrimPrefix(term, "redirect=")
			continue
		}
		if strings.Contains(term, "=") {
			continue // other modifier (exp=...); mechanisms never contain "="
		}
		q := "+"
		if strings.ContainsAny(term[:1], "+-~?") {
			q, term = term[:1], term[1:]
		}
		name, value := term, ""
		if i := strings.IndexAny(term, ":/"); i >= 0 {
			name, value = term[:i], strings.TrimPrefix(term[i:], ":")
		}
		if name == "all" {
			spf.All = q
		}
		spf.Mechanisms = append(spf.Mechanisms, Mechanism{Qualifier: q, Name: name, Value: value})
	}
	return spf, true
}

// lookupMechanisms are the terms that count toward the RFC 7208 10-lookup limit.
var lookupMechanisms = map[string]bool{"include": true, "a": true, "mx": true, "ptr": true, "exists": true}

// TXTLookup fetches TXT records for a name.
type TXTLookup func(ctx context.Context, name string) ([]string, error)

// maxLookupBudget bounds recursion so a hostile record chain cannot make the
// check issue unbounded queries.
const maxLookupBudget = 30

// CountLookups counts DNS-querying terms in spf and, recursively, in the
// records it includes/redirects to. Counting stops at maxLookupBudget.
func CountLookups(ctx context.Context, spf SPF, lookup TXTLookup) int {
	seen := map[string]bool{}
	var walk func(SPF, int) int
	walk = func(s SPF, depth int) int {
		n := 0
		visit := func(domain string) {
			domain = checkutil.Norm(domain)
			if domain == "" || seen[domain] || depth >= 10 || n >= maxLookupBudget {
				return
			}
			seen[domain] = true
			txts, err := lookup(ctx, domain)
			if err != nil {
				return
			}
			for _, txt := range txts {
				if sub, ok := ParseSPF(txt); ok {
					n += walk(sub, depth+1)
					break
				}
			}
		}
		for _, m := range s.Mechanisms {
			if lookupMechanisms[m.Name] {
				n++
				if m.Name == "include" {
					visit(m.Value)
				}
			}
		}
		if s.Redirect != "" {
			n++
			visit(s.Redirect)
		}
		return n
	}
	return walk(spf, 0)
}

// DMARC is a parsed DMARC policy record.
type DMARC struct {
	Policy          string // p=
	SubdomainPolicy string // sp=
	Pct             int    // pct=, default 100
	RUA             string
}

// IsDMARCRecord reports whether txt is a DMARC record.
func IsDMARCRecord(txt string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1")
}

// ParseDMARC parses a DMARC TXT record.
func ParseDMARC(txt string) (DMARC, bool) {
	if !IsDMARCRecord(txt) {
		return DMARC{}, false
	}
	d := DMARC{Pct: 100}
	for _, part := range strings.Split(txt, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "p":
			d.Policy = strings.ToLower(v)
		case "sp":
			d.SubdomainPolicy = strings.ToLower(v)
		case "pct":
			n := 0
			for _, ch := range v {
				if ch < '0' || ch > '9' {
					n = 100
					break
				}
				n = n*10 + int(ch-'0')
			}
			d.Pct = n
		case "rua":
			d.RUA = v
		}
	}
	return d, true
}
