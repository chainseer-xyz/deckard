package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

const (
	ScanTriggerTemplates = "templates"
	ScanTriggerKEV       = "kev"
)

// ScanTrigger retains a feed's scan work independently of local feed files.
type ScanTrigger struct {
	Key       string
	Kind      string
	Templates []string
	CVEs      []string
	Release   string
}

// NewScanTrigger identifies a delta by its normalized payload, so retrying a
// publication on any replica cannot recreate work already acknowledged.
func NewScanTrigger(kind, release string, templates, cves []string) ScanTrigger {
	trigger := ScanTrigger{Kind: kind, Release: release, Templates: slices.Clone(templates), CVEs: slices.Clone(cves)}
	slices.Sort(trigger.Templates)
	slices.Sort(trigger.CVEs)
	trigger.Templates = slices.Compact(trigger.Templates)
	trigger.CVEs = slices.Compact(trigger.CVEs)
	payload, _ := json.Marshal(trigger)
	digest := sha256.Sum256(payload)
	trigger.Key = hex.EncodeToString(digest[:])
	return trigger
}

// ScanTriggerStore is the optional durable feed-to-queue outbox capability.
// Put must preserve acknowledged rows; Ack happens only after fan-out succeeds.
type ScanTriggerStore interface {
	PutScanTrigger(ctx context.Context, trigger ScanTrigger) error
	ListPendingScanTriggers(ctx context.Context, kind string) ([]ScanTrigger, error)
	AckScanTrigger(ctx context.Context, key string) error
}
