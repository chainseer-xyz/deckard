// Package check defines the probe contract. Checks never open their own
// network connections: they use the scope-guarded clients in Target, and
// Target.Intel (a separate, allow-listed client) for third-party metadata about
// the operator's own domains and IPs.
package check

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Dialer is a scope-guarded dialer. It refuses out-of-scope addresses.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TimeoutDialer is implemented by dialers that can bound the connection
// attempt alone. The timeout starts after any wait for the per-host rate
// limiter, so a dial queued behind the limiter is not mistaken for an
// unresponsive port.
type TimeoutDialer interface {
	DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error)
}

// ErrRateLimited marks a dial that was never attempted because no rate-limit
// token could be had before the context ended. It says nothing about the
// destination.
var ErrRateLimited = errors.New("rate limit wait failed")

// Resolver is a scope-aware DNS resolver.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupNS(ctx context.Context, host string) ([]string, error)
}

// DNSQuerier is a scope-guarded, rcode-aware DNS client (see internal/dnsx).
// Unlike Resolver it exposes the rcode, the CNAME chain and DNSSEC data, and
// models SERVFAIL/timeouts as "unknown" (dnsx.StateUnknown or an error
// wrapping dnsx.ErrUnavailable), never as NXDOMAIN. Checks that need more than
// Resolver offers use it when Target.DNS is non-nil and fall back to Resolver
// otherwise.
type DNSQuerier interface {
	// Query asks the configured recursive resolvers for name/qtype.
	Query(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error)
	// ResolveChain follows name's CNAME chain, reporting where it ends.
	ResolveChain(ctx context.Context, name string) (dnsx.Chain, error)
	// AXFR attempts a zone transfer from the zone's nameservers. Attempts the
	// scope guard does not permit are reported as skipped, not as errors.
	AXFR(ctx context.Context, zone string) (dnsx.AXFRReport, error)
}

// Intel is the restricted client for third-party metadata services
// (internal/intel): RDAP registries and similar sources that answer questions
// about the operator's own domains and IPs. It is not a probe and does not go
// through the scope guard; it reaches only a fixed allow-list of hosts and
// never a URL derived from anything but the asset itself. Errors (including
// intel.ErrDisabled) are never evidence about the asset: a check that cannot
// get an answer records an observation and marks its run partial.
type Intel interface {
	// Get fetches rawURL from the named service (intel.ServiceRDAP, ...).
	Get(ctx context.Context, service, rawURL string) (intel.Response, error)
	// RDAPBase returns the RDAP base URL (ending in "/") for domain's TLD,
	// or intel.ErrUnsupported when the TLD publishes no RDAP service.
	RDAPBase(ctx context.Context, domain string) (string, error)
}

// Lookup is a DNS client for names the operator does NOT own (domain.lookalike
// asks whether a typosquat exists). It is deliberately not the scope guard's
// DNSQuerier, which rightly refuses such names: it is built from the configured
// recursive resolvers (scope.resolvers when set) behind one process-wide rate
// limit, it only ever sends DNS queries to those resolvers, and it is the only
// way a check may ask about a third party's name. Like DNSQuerier it is
// rcode-aware: SERVFAIL and timeouts are unknown, never "does not exist".
type Lookup interface {
	Query(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error)
}

// Neighbour is an asset connected to the target by a relation.
type Neighbour struct {
	Asset    model.Asset
	Relation model.RelationType
	Outbound bool
}

// Target is everything a check may use. Asset is always in scope for the
// check tier (the engine enforces this before calling Run).
type Target struct {
	Asset      model.Asset
	Neighbours []Neighbour
	Baseline   map[string]map[string]any // per-check learned baseline
	Dialer     Dialer
	Resolver   Resolver
	DNS        DNSQuerier // optional; nil means use Resolver only
	HTTP       *http.Client
	// Intel is the third-party metadata client. Nil means not available:
	// checks that need it treat the run as skipped (an observation, a partial
	// result, never an error or a finding).
	Intel Intel
	// Lookup is the client for third-party names (see Lookup). Nil means not
	// available: checks that need it record an observation and skip.
	Lookup Lookup
	Config map[string]any
	// OwnedZones are the names of every owned zone in the inventory, not only
	// the asset's own. The engine fills it only for checks that implement
	// WantsOwnedZones; it is nil for every other check.
	OwnedZones []string
	// OpenFindings are this asset's unresolved findings (open, acknowledged,
	// suppressed, false_positive) of the running check, newest severity first,
	// capped at MaxOpenFindings. The engine fills it only for checks that
	// implement WantsOpenFindings; it is nil for every other check.
	OpenFindings []OpenFinding
}

// MaxOpenFindings bounds Target.OpenFindings.
const MaxOpenFindings = 200

// OpenFinding is the minimal view of an unresolved finding a check may use to
// re-verify it (for example by re-running the template that produced it).
//
// The finding Key is not persisted (only its fingerprint is), so a check that
// needs it reads what it put into Evidence when it reported the finding.
type OpenFinding struct {
	Fingerprint string
	Severity    model.Severity
	Status      model.FindingStatus
	Evidence    map[string]any
}

// WantsOpenFindings is an optional Check interface. A check returning true
// receives Target.OpenFindings; the engine runs one indexed store query per
// scan for it and skips the query for every other check.
type WantsOpenFindings interface {
	WantsOpenFindings() bool
}

// WantsOwnedZones is an optional Check interface. A check returning true
// receives Target.OwnedZones; the engine lists the owned zone assets once per
// run for it and skips the query for every other check.
type WantsOwnedZones interface {
	WantsOwnedZones() bool
}

// DefaultTimeouter is an optional Check interface for checks whose runs
// legitimately take longer than the engine's 2m default (a rate-limited sweep
// of DNS names, for example). checks.<name>.timeout still overrides it. The
// engine's deadline also covers storing the result, so a check should finish
// its own work before it.
type DefaultTimeouter interface {
	DefaultTimeout() time.Duration
}

// WantsBaselines is an optional Check interface. A check returning check names
// receives those other checks' learned baselines for the same asset in
// Target.Baseline (keyed by check name, absent when none was learned yet), next
// to its own. The data is a check's last observation as the baseline machinery
// keeps it, so a check can compare what it sees with what another check
// observed, for example a third-party view of open ports against net.ports.
// Keys starting with "_" are bookkeeping and must be ignored.
type WantsBaselines interface {
	BaselineChecks() []string
}

// DefaultIntervaler is an optional Check interface for checks whose natural
// cadence differs from their tier's (slow-moving registry data, for
// example). The interval replaces the tier and asset-group interval;
// checks.<name>.interval still overrides it.
type DefaultIntervaler interface {
	DefaultInterval() time.Duration
}

// Result is what a check returns.
type Result struct {
	Observations []model.ObservationInput
	Findings     []model.FindingInput
	Discovered   []model.AssetInput
	Relations    []model.RelationInput
	// Partial marks a run that only observed a subset of what the check can
	// report (for example a delta scan with a handful of new nuclei templates).
	// Its findings are opened and refreshed as usual, but absence proves
	// nothing: no misses are counted, no finding is resolved and no derived
	// asset is garbage-collected (Discovered is not applied either).
	Partial bool
}

// Check is one probe.
type Check interface {
	Name() string
	Tier() model.Tier
	Applies(a model.Asset) bool
	Run(ctx context.Context, t Target) (*Result, error)
}
