// Package model holds deckard's domain types. It has no dependencies on other
// internal packages so every layer can import it.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Tier is how intrusive a check is. Higher tiers are opt-in and slower.
type Tier string

const (
	TierPassive   Tier = "passive"
	TierActive    Tier = "active"
	TierIntrusive Tier = "intrusive"
)

// Valid reports whether t is a known tier.
func (t Tier) Valid() bool {
	switch t {
	case TierPassive, TierActive, TierIntrusive:
		return true
	}
	return false
}

// Severity ranks a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInfo: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// Rank returns a sortable integer; unknown severities rank below info.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// AtLeast reports whether s is at or above min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// AssetKind is the type of an inventory node.
type AssetKind string

const (
	KindZone          AssetKind = "zone"
	KindHostname      AssetKind = "hostname"
	KindIP            AssetKind = "ip"
	KindService       AssetKind = "service"
	KindURL           AssetKind = "url"
	KindCertificate   AssetKind = "certificate"
	KindCloudResource AssetKind = "cloud_resource"
)

// ScopeClass says how deckard may treat an asset. See spec section 2.
type ScopeClass string

const (
	ScopeOwned    ScopeClass = "owned"
	ScopeShared   ScopeClass = "shared"
	ScopeExternal ScopeClass = "external"
	ScopeExcluded ScopeClass = "excluded"
)

// RelationType links two assets.
type RelationType string

const (
	RelResolvesTo RelationType = "resolves_to"
	RelCNAMETo    RelationType = "cname_to"
	RelAliasTo    RelationType = "alias_to"
	RelProxiedBy  RelationType = "proxied_by"
	RelOriginOf   RelationType = "origin_of"
	RelServes     RelationType = "serves"
	RelExposes    RelationType = "exposes"
	RelHasCert    RelationType = "has_cert"
	RelInZone     RelationType = "in_zone"
)

// SourceFact is the most recent metadata one inventory source reported.
// A missing entry means that source's metadata is unknown, not empty.
type SourceFact struct {
	Zone  string         `json:"zone,omitempty"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Asset is a node in the inventory graph. Source, Zone and Attrs project the
// canonical authority; SourceFacts retains each reporter's separate metadata.
type Asset struct {
	ID          int64                 `json:"id"`
	Kind        AssetKind             `json:"kind"`
	Key         string                `json:"key"`
	Source      string                `json:"source"`
	Scope       ScopeClass            `json:"scope"`
	Zone        string                `json:"zone,omitempty"`
	Attrs       map[string]any        `json:"attrs,omitempty"`
	Reporters   []string              `json:"reporters,omitempty"`
	SourceFacts map[string]SourceFact `json:"source_facts,omitempty"`
	FirstSeen   time.Time             `json:"first_seen"`
	LastSeen    time.Time             `json:"last_seen"`
	RemovedAt   *time.Time            `json:"removed_at,omitempty"`
}

// AssetInput is what sources and checks hand to the inventory.
type AssetInput struct {
	Kind   AssetKind      `json:"kind"`
	Key    string         `json:"key"`
	Source string         `json:"source"`
	Zone   string         `json:"zone,omitempty"`
	Attrs  map[string]any `json:"attrs,omitempty"`
}

// RelationInput links two assets by (kind, key).
type RelationInput struct {
	FromKind AssetKind    `json:"from_kind"`
	FromKey  string       `json:"from_key"`
	ToKind   AssetKind    `json:"to_kind"`
	ToKey    string       `json:"to_key"`
	Type     RelationType `json:"type"`
}

// Relation is a stored edge.
type Relation struct {
	FromID int64        `json:"from_id"`
	ToID   int64        `json:"to_id"`
	Type   RelationType `json:"type"`
}

// ObservationInput is raw check output for one asset.
type ObservationInput struct {
	Check string         `json:"check"`
	Data  map[string]any `json:"data"`
}

// Observation is a stored observation.
type Observation struct {
	AssetID    int64          `json:"asset_id"`
	Check      string         `json:"check"`
	Data       map[string]any `json:"data"`
	ObservedAt time.Time      `json:"observed_at"`
}

// FindingStatus is the lifecycle state of a finding.
type FindingStatus string

const (
	StatusOpen          FindingStatus = "open"
	StatusAcknowledged  FindingStatus = "acknowledged"
	StatusSuppressed    FindingStatus = "suppressed"
	StatusFalsePositive FindingStatus = "false_positive"
	StatusResolved      FindingStatus = "resolved"
)

// FindingInput is what a check reports. Key distinguishes multiple findings
// of the same check on the same asset (e.g. one per open port).
type FindingInput struct {
	Check       string         `json:"check"`
	Key         string         `json:"key"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
}

// Finding is a stored, deduplicated issue.
type Finding struct {
	ID              int64          `json:"id"`
	Fingerprint     string         `json:"fingerprint"`
	Check           string         `json:"check"`
	AssetID         int64          `json:"asset_id"`
	AssetKey        string         `json:"asset_key"`
	Zone            string         `json:"zone,omitempty"`
	Source          string         `json:"source,omitempty"`
	Severity        Severity       `json:"severity"`
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	Evidence        map[string]any `json:"evidence,omitempty"`
	Remediation     string         `json:"remediation,omitempty"`
	Tags            []string       `json:"tags,omitempty"`
	Status          FindingStatus  `json:"status"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
	MissedRuns      int            `json:"missed_runs"`
	ReopenedCount   int            `json:"reopened_count"`
	SuppressedUntil *time.Time     `json:"suppressed_until,omitempty"`
	SuppressionNote string         `json:"suppression_note,omitempty"`
	// IngestScope is the scanned scope (account, cluster, org) an ingested
	// finding was reported for; empty for findings of built-in checks.
	IngestScope string `json:"ingest_scope,omitempty"`
	// Context is derived, non-persisted enrichment (lineage, owner, previous/
	// current state, change times) filled just before notification.
	Context map[string]any `json:"context,omitempty"`
}

// Findings posted by external scanners (POST /api/v1/ingest) are stored under
// the check IngestCheckPrefix+tool, and assets the ingest creates carry the
// source IngestSourcePrefix+tool. No built-in check, plugin or inventory
// source may use either prefix (config validation enforces it), so the
// prefixes alone identify ingested data.
const (
	IngestCheckPrefix  = "ext."
	IngestSourcePrefix = "ingest:"
)

// IngestCheck is the check name findings of tool are stored under.
func IngestCheck(tool string) string { return IngestCheckPrefix + tool }

// IngestSource is the source label of assets created by tool's ingest.
func IngestSource(tool string) string { return IngestSourcePrefix + tool }

// ValidIngestTool reports whether name is a valid ingest tool name:
// ^[a-z0-9][a-z0-9-]{1,31}$ (it becomes part of a check name, a source label,
// an Alertmanager alertname and a metric label).
func ValidIngestTool(name string) bool {
	if len(name) < 2 || len(name) > 32 {
		return false
	}
	for i, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// IsIngestSource reports whether an asset source label marks an asset created
// by the ingest API. Such assets are never probed.
func IsIngestSource(source string) bool { return strings.HasPrefix(source, IngestSourcePrefix) }

// Fingerprint is the dedup key for a finding: stable across runs. It does
// not include the asset KIND, so a zone asset and a hostname asset sharing
// one key produce equal fingerprints for the same finding; uniqueness is
// therefore enforced per asset (see migration 00006), never globally.
func Fingerprint(check, assetKey, findingKey string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{check, assetKey, findingKey}, "\x00")))
	return hex.EncodeToString(sum[:])
}
