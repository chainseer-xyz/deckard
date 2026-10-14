package identity

import (
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
)

type runtimeIdentity struct{ cluster, namespace, podUID string }

// RuntimeIndex joins immutable Kubernetes identities from current native
// facts. It never joins display names, canonical projections or ingest facts.
type RuntimeIndex struct{ assets map[runtimeIdentity]int64 }

func NewRuntimeIndex(assets []model.Asset) *RuntimeIndex {
	index := &RuntimeIndex{assets: map[runtimeIdentity]int64{}}
	for _, asset := range assets {
		if asset.ID <= 0 || asset.Kind != model.KindWorkload || asset.RemovedAt != nil {
			continue
		}
		var claims []runtimeIdentity
		usable := true
		for _, reporter := range asset.Reporters {
			fact, exists := asset.SourceFacts[reporter]
			if !exists || model.IsIngestSource(reporter) || fact.Attrs["provider"] != "kubernetes" {
				continue
			}
			claim, valid := runtimeFact(fact.Attrs)
			if !valid {
				usable = false
				continue
			}
			if len(claims) > 0 && claims[0] != claim {
				usable = false
			}
			claims = append(claims, claim)
		}
		for _, claim := range claims {
			previous, exists := index.assets[claim]
			if !usable || exists && previous != asset.ID {
				index.assets[claim] = 0
			} else if !exists {
				index.assets[claim] = asset.ID
			}
		}
	}
	return index
}

func runtimeFact(attrs map[string]any) (runtimeIdentity, bool) {
	cluster, _ := attrs["cluster_id"].(string)
	namespace, _ := attrs["namespace"].(string)
	uid, _ := attrs["uid"].(string)
	id := runtimeIdentity{cluster, namespace, uid}
	return id, attrs["k8s_kind"] == "Pod" && id.valid()
}

func (id runtimeIdentity) valid() bool {
	if !strings.HasPrefix(id.cluster, "uid:") || len(id.cluster) <= len("uid:") || id.namespace == "" || id.podUID == "" {
		return false
	}
	for _, part := range []string{id.cluster, id.namespace, id.podUID} {
		if len(part) > 253 || strings.ContainsAny(part, " \t\r\n\x00") {
			return false
		}
	}
	return true
}

// Resolve returns only one current authoritative Pod, in the operator's exact
// immutable cluster scope. A match conveys metadata association, not ownership.
func (i *RuntimeIndex) Resolve(scope string, evidence map[string]any) (int64, bool) {
	cluster, _ := evidence["runtime_cluster_id"].(string)
	namespace, _ := evidence["runtime_namespace"].(string)
	uid, _ := evidence["runtime_pod_uid"].(string)
	id := runtimeIdentity{cluster, namespace, uid}
	if !id.valid() || scope != "k8s:"+cluster {
		return 0, false
	}
	assetID := i.assets[id]
	return assetID, assetID > 0
}
