// Package assessmentjob plans and manages explicitly requested, isolated
// Kubernetes assessments. It does not infer scan ownership from network policy.
package assessmentjob

import (
	"context"
	"net/netip"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessment"
	"github.com/chainseer-xyz/deckard/internal/model"
)

type Tool string

const (
	ToolZGrab2            Tool = "zgrab2"
	ToolZAP               Tool = "zap"
	ToolStrix             Tool = "strix"
	ServiceAccountName         = "deckard-assessment-runner"
	DefaultDenyPolicyName      = "deckard-assessment-deny-all"
	SessionLabel               = "deckard.io/assessment-session"
	ComponentLabel             = "app.kubernetes.io/component"
	ManagedLabel               = "app.kubernetes.io/name"
	ManagedValue               = "deckard-assessment"
)

// Settings contains only explicit runtime grants. Image references must carry
// immutable sha256 digests. NetworkPolicyEnforced is an operator attestation,
// not proof: deployment must separately verify negative egress fixtures.
type Settings struct {
	Namespace             string
	BrokerIP              netip.Addr
	BrokerPort            int32
	Images                map[Tool]string
	UploaderImage         string
	StrixRuntimeImage     string
	NetworkPolicyEnforced bool
	MaxSessions           int
	MaxRunning            int
	SessionDuration       time.Duration
	Limits                assessment.Limits
	ModelGatewayURL       string
	ModelGatewayIP        netip.Addr
	ModelGatewayPort      int32
	Model                 string
	ModelSecretName       string
	ModelSecretKey        string
	ZAPAuthSecretName     string
	// RefreshOwnership reloads persisted authority before target selection and
	// every broker request. A failure refuses assessment traffic.
	RefreshOwnership func(context.Context) error
}

type Request struct {
	Tool     Tool    `json:"tool"`
	AssetIDs []int64 `json:"asset_ids"`
}

type Session struct {
	ID             string    `json:"id"`
	Tool           Tool      `json:"tool"`
	AssetIDs       []int64   `json:"asset_ids"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	JobName        string    `json:"job_name"`
	Reason         string    `json:"reason,omitempty"`
	CleanupPending bool      `json:"cleanup_pending,omitempty"`
}

// Completion is not an authorization to reconcile findings by itself. The
// native parser must also prove its own complete observation. Strix remains
// additive regardless of this transport completion bit.
// Session.Status separately reports unproven coverage as partial, even when
// Complete confirms successful Job execution and a drained network boundary.
type Completion struct {
	Session  Session
	Targets  []Target
	Format   string
	Data     []byte
	Complete bool
	Reason   string
}
type CompletionFunc func(context.Context, Completion) error

type AssetStore interface {
	GetAsset(context.Context, int64) (*model.Asset, error)
}

type Target struct {
	AssetID   int64        `json:"asset_id"`
	Origin    string       `json:"origin"`
	Addresses []netip.Addr `json:"addresses"`
	Port      uint16       `json:"port"`
}

// ExecutionRequest is the bounded file contract consumed by the trusted
// wrapper. Targets are explicit origins; FixedTargets never require DNS.
type ExecutionRequest struct {
	SchemaVersion  int      `json:"schema_version"`
	SessionID      string   `json:"session_id"`
	Tool           Tool     `json:"tool"`
	Targets        []string `json:"targets"`
	FixedTargets   []Target `json:"fixed_targets,omitempty"`
	MaxTurns       int      `json:"max_turns"`
	TimeoutSeconds int64    `json:"timeout_seconds"`
	MaxRequests    int      `json:"max_requests"`
	MaxOutputBytes int64    `json:"max_output_bytes"`
}
