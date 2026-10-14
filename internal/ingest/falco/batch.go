package falco

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

const maxEvents = 100000

type observation struct {
	finding ingest.Finding
	at      time.Time
	id      string
	count   int64
}

type incidentGroup struct {
	finding     ingest.Finding
	first, last time.Time
	counts      map[string]int64
}

// batch counts are deduplicated within this input, never lifetime counters.
func parseBatch(data []byte, o ingest.ParseOptions, parse func([]byte, ingest.ParseOptions) (observation, error)) ([]ingest.Finding, error) {
	if o.Scope == "" || len(o.Scope) > ingest.MaxScopeLen || ingest.Line(o.Scope, ingest.MaxScopeLen) != o.Scope {
		return nil, fmt.Errorf("%s requires a bounded operator-supplied scope", Tool)
	}
	records, err := records(data)
	if err != nil {
		return nil, err
	}
	groups := map[string]*incidentGroup{}
	for index, raw := range records {
		observed, err := parse(raw, o)
		if err != nil {
			return nil, fmt.Errorf("%s event %d: %w", Tool, index, err)
		}
		if observed.finding.Key == "" {
			continue
		}
		key := observed.finding.Key
		group := groups[key]
		if group == nil {
			group = &incidentGroup{finding: observed.finding, first: observed.at, last: observed.at, counts: map[string]int64{}}
			groups[key] = group
			if len(groups) > ingest.MaxFindings {
				return nil, fmt.Errorf("%s incident count exceeds the ingest limit", Tool)
			}
		}
		if observed.at.Before(group.first) {
			group.first = observed.at
		}
		if observed.at.After(group.last) {
			group.last = observed.at
		}
		if observed.finding.Severity.Rank() > group.finding.Severity.Rank() {
			group.finding.Severity = observed.finding.Severity
		}
		if observed.count > group.counts[observed.id] {
			group.counts[observed.id] = observed.count
		}
	}
	out := make([]ingest.Finding, 0, len(groups))
	for _, group := range groups {
		var count int64
		for _, n := range group.counts {
			count += n
		}
		if count > 1000000000 {
			return nil, fmt.Errorf("%s batch count exceeds the limit", Tool)
		}
		group.finding.Evidence["runtime_batch_count"] = count
		group.finding.Evidence["runtime_first_seen"] = group.first.UTC().Format(time.RFC3339Nano)
		group.finding.Evidence["runtime_last_seen"] = group.last.UTC().Format(time.RFC3339Nano)
		out = append(out, group.finding)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func records(data []byte) ([]json.RawMessage, error) {
	if len(data) > MaxInputBytes {
		return nil, fmt.Errorf("%s input exceeds 64 MiB", Tool)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var out []json.RawMessage
	for {
		var raw json.RawMessage
		err := decoder.Decode(&raw)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s input is not valid JSON", Tool)
		}
		raw = bytes.TrimSpace(raw)
		if raw[0] == '[' {
			if len(out) != 0 {
				return nil, fmt.Errorf("%s input cannot mix arrays and event streams", Tool)
			}
			if json.Unmarshal(raw, &out) != nil {
				return nil, fmt.Errorf("%s event array is invalid", Tool)
			}
			var extra json.RawMessage
			if decoder.Decode(&extra) != io.EOF {
				return nil, fmt.Errorf("%s event array has trailing data", Tool)
			}
			if len(out) > maxEvents {
				return nil, fmt.Errorf("%s event count exceeds the limit", Tool)
			}
			return out, nil
		}
		out = append(out, raw)
		if len(out) > maxEvents {
			return nil, fmt.Errorf("%s event count exceeds the limit", Tool)
		}
	}
}

func eventID(parts ...string) string {
	encoded, _ := json.Marshal(parts)
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func identityPart(value string, limit int) bool {
	if len(value) > limit {
		return false
	}
	for _, r := range value {
		if r != '-' && r != '_' && r != '.' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
