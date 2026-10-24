package tetragon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	finding         ingest.Finding
	first, last     time.Time
	counts          map[string]int64
	podNameConflict bool
}

// observePodName combines optional display metadata without selecting an
// arbitrary sensor's conflicting claim. This never changes incident identity.
func (g *incidentGroup) observePodName(evidence map[string]any) {
	name, _ := evidence["runtime_pod_name"].(string)
	current, _ := g.finding.Evidence["runtime_pod_name"].(string)
	if g.podNameConflict || name == "" {
		return
	}
	if current == "" {
		g.finding.Evidence["runtime_pod_name"] = name
	} else if current != name {
		delete(g.finding.Evidence, "runtime_pod_name")
		g.podNameConflict = true
	}
}

// batch counts are deduplicated within this input, never lifetime counters.
func parseBatch(data []byte, o ingest.ParseOptions) ([]ingest.Finding, error) {
	accumulator, err := NewAccumulator(o)
	if err != nil {
		return nil, err
	}
	records, err := records(data)
	if err != nil {
		return nil, err
	}
	for _, raw := range records {
		if err := accumulator.add(raw); err != nil {
			return nil, err
		}
	}
	return accumulator.Findings()
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
