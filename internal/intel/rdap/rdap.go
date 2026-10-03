// Package rdap parses RDAP domain responses (RFC 9083) into the handful of
// facts deckard monitors: registration dates, status flags, the registrar,
// the delegated nameservers and the DNSSEC flag. It does no I/O; responses
// come through internal/intel.
//
// Registries differ in the details, so parsing is lenient where it is safe
// to be: event actions and statuses are normalised ("lastChanged",
// "last_changed" and "last changed" are the same event; "clientTransferProhibited"
// and "client transfer prohibited" the same status), unknown events are
// ignored and unparseable dates are dropped rather than failing the response.
// It is strict about identity: the response must describe the domain that was
// asked for.
package rdap

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Normalised EPP/RDAP status values (RFC 8056 mapping) deckard acts on.
const (
	StatusClientTransferProhibited = "client transfer prohibited"
	StatusServerTransferProhibited = "server transfer prohibited"
	StatusClientDeleteProhibited   = "client delete prohibited"
	StatusServerDeleteProhibited   = "server delete prohibited"
	StatusRedemptionPeriod         = "redemption period"
	StatusPendingDelete            = "pending delete"
	StatusPendingTransfer          = "pending transfer"
	StatusAutoRenewPeriod          = "auto renew period"
)

// Domain is the parsed subset of an RDAP domain object.
type Domain struct {
	Name string // ldhName, lowercase, no trailing dot
	// Registrar is the registrar entity's formatted name (vCard fn, else org,
	// else its handle). Empty when the registry does not publish one.
	Registrar string
	// RegistrarIANAID is the registrar's IANA ID when published.
	RegistrarIANAID string
	Nameservers     []string // lowercase, no trailing dot, sorted, unique
	Statuses        []string // normalised (see NormalizeStatus), sorted, unique
	Registered      time.Time
	Expires         time.Time
	LastChanged     time.Time
	// DNSSEC is secureDNS.delegationSigned; nil when not published.
	DNSSEC *bool
}

// Has reports whether the domain carries the normalised status s.
func (d *Domain) Has(s string) bool { return slices.Contains(d.Statuses, s) }

type rawDomain struct {
	ObjectClassName string      `json:"objectClassName"`
	LDHName         string      `json:"ldhName"`
	Status          []string    `json:"status"`
	Events          []rawEvent  `json:"events"`
	Entities        []rawEntity `json:"entities"`
	Nameservers     []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned *bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	ErrorCode *int `json:"errorCode"`
}

type rawEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rawEntity struct {
	Handle    string          `json:"handle"`
	Roles     []string        `json:"roles"`
	VCard     json.RawMessage `json:"vcardArray"`
	PublicIDs []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rawEntity `json:"entities"`
}

// ErrMismatch means the response describes another object than the one asked
// for (or is an RDAP error object).
var ErrMismatch = errors.New("rdap: response does not describe the requested domain")

// ParseDomain parses body as the RDAP domain object for domain.
func ParseDomain(body []byte, domain string) (*Domain, error) {
	var r rawDomain
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("rdap: invalid json: %w", err)
	}
	want := normName(domain)
	got := normName(r.LDHName)
	switch {
	case r.ErrorCode != nil:
		return nil, fmt.Errorf("%w: error object %d", ErrMismatch, *r.ErrorCode)
	case r.ObjectClassName != "" && !strings.EqualFold(r.ObjectClassName, "domain"):
		return nil, fmt.Errorf("%w: object class %q", ErrMismatch, r.ObjectClassName)
	case got == "" || got != want:
		return nil, fmt.Errorf("%w: ldhName %q", ErrMismatch, got)
	}
	d := &Domain{Name: got}
	for _, s := range r.Status {
		if n := NormalizeStatus(s); n != "" && !slices.Contains(d.Statuses, n) {
			d.Statuses = append(d.Statuses, n)
		}
	}
	slices.Sort(d.Statuses)
	for _, ns := range r.Nameservers {
		if n := normName(ns.LDHName); n != "" && !slices.Contains(d.Nameservers, n) {
			d.Nameservers = append(d.Nameservers, n)
		}
	}
	slices.Sort(d.Nameservers)
	d.events(r.Events)
	if reg, ok := findRegistrar(r.Entities, 2); ok {
		d.Registrar = registrarName(reg)
		for _, id := range reg.PublicIDs {
			if strings.EqualFold(strings.TrimSpace(id.Type), "IANA Registrar ID") {
				d.RegistrarIANAID = strings.TrimSpace(id.Identifier)
			}
		}
	}
	if r.SecureDNS != nil && r.SecureDNS.DelegationSigned != nil {
		v := *r.SecureDNS.DelegationSigned
		d.DNSSEC = &v
	}
	return d, nil
}

// events fills the dates. "expiration" beats the registrar-side
// "registrar expiration" some registries add; unknown actions (including
// "last update of RDAP database", which is about the database, not the
// domain) are ignored.
func (d *Domain) events(evs []rawEvent) {
	var regExp time.Time
	for _, e := range evs {
		t, ok := parseDate(e.Date)
		if !ok {
			continue
		}
		switch normalize(e.Action) {
		case "registration", "registered":
			d.Registered = t
		case "expiration", "expiry", "expiration date":
			d.Expires = t
		case "registrar expiration", "registration expiration":
			regExp = t
		case "last changed", "last change", "last update", "last modified":
			d.LastChanged = t
		}
	}
	if d.Expires.IsZero() {
		d.Expires = regExp
	}
}

var dateLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"}

// parseDate accepts RFC 3339 and the common zone-less variants (read as UTC).
func parseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// findRegistrar returns the first entity with the registrar role, searching
// nested entities up to depth levels.
func findRegistrar(es []rawEntity, depth int) (rawEntity, bool) {
	for _, e := range es {
		for _, r := range e.Roles {
			if strings.EqualFold(strings.TrimSpace(r), "registrar") {
				return e, true
			}
		}
	}
	if depth > 1 {
		for _, e := range es {
			if r, ok := findRegistrar(e.Entities, depth-1); ok {
				return r, true
			}
		}
	}
	return rawEntity{}, false
}

// registrarName reads the vCard (jCard, RFC 7095) fn, then org, then falls
// back to the entity handle.
func registrarName(e rawEntity) string {
	var card []json.RawMessage
	if json.Unmarshal(e.VCard, &card) == nil && len(card) == 2 {
		var props [][]json.RawMessage
		if json.Unmarshal(card[1], &props) == nil {
			byName := map[string]string{}
			for _, p := range props {
				if len(p) < 4 {
					continue
				}
				var name, val string
				if json.Unmarshal(p[0], &name) != nil {
					continue
				}
				if json.Unmarshal(p[3], &val) != nil {
					var parts []string // org may be structured: ["Example Inc.", "Unit"]
					if json.Unmarshal(p[3], &parts) != nil || len(parts) == 0 {
						continue
					}
					val = parts[0]
				}
				if n := strings.ToLower(name); byName[n] == "" {
					byName[n] = clean(val)
				}
			}
			for _, k := range []string{"fn", "org"} {
				if byName[k] != "" {
					return byName[k]
				}
			}
		}
	}
	return clean(e.Handle)
}

// clean collapses whitespace and drops control characters from
// registry-provided text before it reaches findings.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200])
	}
	return s
}

// NormalizeStatus maps the spellings registries use for one status onto the
// RFC 8056 form: "clientTransferProhibited", "client_transfer_prohibited" and
// "Client Transfer Prohibited" all become "client transfer prohibited".
func NormalizeStatus(s string) string { return normalize(s) }

func normalize(s string) string {
	var b strings.Builder
	prevLower := false
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == '_' || r == '-' || unicode.IsSpace(r):
			b.WriteByte(' ')
			prevLower = false
			continue
		case unicode.IsUpper(r) && prevLower:
			b.WriteByte(' ')
		}
		b.WriteRune(unicode.ToLower(r))
		prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func normName(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }
