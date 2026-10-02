package finding

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// ConfigNotePrefix marks a suppression note as owned by YAML config. The
// store's Finding has no actor column, so this prefix is how the processor
// tells config suppressions (which it may lift again) from operator ones made
// in the UI/API (which it never touches).
const ConfigNotePrefix = "[config] "

// ConfigActor is the actor recorded for suppressions applied from YAML.
const ConfigActor = "config"

// Suppression match grammar
//
// A match string is a space-separated list of key=value terms that are ANDed.
//
//	check=http.headers asset=blog.example.com
//	zone=example.com severity=info
//	asset=*.staging.example.com check=tls.*
//	title="Missing * header"          (values with spaces must be double-quoted)
//
// Keys: check, asset (the asset key), zone, source, severity, fingerprint,
// title. A key may repeat (all occurrences must match). Matching is
// case-insensitive. Values support glob wildcards: `*` matches any run of
// characters INCLUDING dots and slashes (unlike path.Match, whose `*` stops at
// '/'; asset keys are hostnames and URLs, so dots and slashes are ordinary
// characters here) and `?` matches exactly one character. There are no
// character classes or escapes. Note `*.example.com` does not match
// `example.com` itself; list both if you mean both.
//
// An empty match string, an empty term, an unknown key, an empty value or an
// unknown severity is a configuration error: a suppression must never match
// by accident.
var matchKeys = map[string]bool{
	"check": true, "asset": true, "zone": true, "source": true,
	"severity": true, "fingerprint": true, "title": true,
}

type term struct{ key, pattern string }

type rule struct {
	raw    string
	terms  []term
	reason string
	until  *time.Time
}

// parseMatch parses the match grammar.
func parseMatch(s string) ([]term, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, errors.New("empty match (a suppression must name at least one key=value term)")
	}
	terms := make([]term, 0, len(toks))
	for _, tok := range toks {
		k, v, ok := strings.Cut(tok, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok {
			return nil, fmt.Errorf("term %q is not key=value", tok)
		}
		if !matchKeys[k] {
			return nil, fmt.Errorf("unknown match key %q (valid: check, asset, zone, source, severity, fingerprint, title)", k)
		}
		if v == "" {
			return nil, fmt.Errorf("empty value for %q", k)
		}
		if k == "severity" && !strings.ContainsAny(v, "*?") && !model.Severity(strings.ToLower(v)).Valid() {
			return nil, fmt.Errorf("unknown severity %q", v)
		}
		terms = append(terms, term{key: k, pattern: strings.ToLower(v)})
	}
	return terms, nil
}

// tokenize splits on whitespace, keeping double-quoted runs together and
// dropping the quotes.
func tokenize(s string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	inQ, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			has = true
		case !inQ && (r == ' ' || r == '\t' || r == '\n'):
			if has {
				toks = append(toks, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if inQ {
		return nil, errors.New("unterminated quote in match")
	}
	if has {
		toks = append(toks, cur.String())
	}
	return toks, nil
}

// glob reports whether s matches pattern ('*' any run, '?' one char).
// Both are expected lower-cased.
func glob(pattern, s string) bool {
	p, t := []rune(pattern), []rune(s)
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]) && p[pi] != '*':
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func (r rule) matches(f model.Finding) bool {
	for _, t := range r.terms {
		var v string
		switch t.key {
		case "check":
			v = f.Check
		case "asset":
			v = f.AssetKey
		case "zone":
			v = f.Zone
		case "source":
			v = f.Source
		case "severity":
			v = string(f.Severity)
		case "fingerprint":
			v = f.Fingerprint
		case "title":
			v = f.Title
		}
		if !glob(t.pattern, strings.ToLower(v)) {
			return false
		}
	}
	return true
}

// ValidateSuppressions checks every configured suppression and reports all
// problems at once. Intended for `deckard config validate` and startup.
func ValidateSuppressions(sups []config.Suppression) error {
	_, err := compile(sups)
	return err
}

func compile(sups []config.Suppression) ([]rule, error) {
	var errs []error
	rules := make([]rule, 0, len(sups))
	for i, s := range sups {
		terms, err := parseMatch(s.Match)
		if err != nil {
			errs = append(errs, fmt.Errorf("suppressions[%d]: %w", i, err))
			continue
		}
		rules = append(rules, rule{raw: s.Match, terms: terms, reason: s.Reason, until: s.Until})
	}
	return rules, errors.Join(errs...)
}

// Suppressor evaluates YAML suppressions. It is immutable and goroutine-safe.
type Suppressor struct{ rules []rule }

// NewSuppressor compiles the suppressions; any invalid entry is an error.
func NewSuppressor(sups []config.Suppression) (*Suppressor, error) {
	rules, err := compile(sups)
	if err != nil {
		return nil, err
	}
	return &Suppressor{rules: rules}, nil
}

// Match returns the first suppression that matches f and has not lapsed at
// now. A suppression with until <= now no longer matches.
func (s *Suppressor) Match(f model.Finding, now time.Time) (reason string, until *time.Time, ok bool) {
	if s == nil {
		return "", nil, false
	}
	for _, r := range s.rules {
		if r.until != nil && !now.Before(*r.until) {
			continue
		}
		if r.matches(f) {
			return r.reason, r.until, true
		}
	}
	return "", nil, false
}

// ownedByConfig reports whether f is currently suppressed by YAML config.
func ownedByConfig(f model.Finding) bool {
	return f.Status == model.StatusSuppressed && strings.HasPrefix(f.SuppressionNote, ConfigNotePrefix)
}
