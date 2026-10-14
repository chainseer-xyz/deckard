package ingest

import (
	"fmt"

	"github.com/chainseer-xyz/deckard/internal/model"
)

const (
	MaxArtifacts         = 5000
	MaxArtifactRelations = 10000
)

func artifactKey(kind model.AssetKind, key string) bool {
	var canonical string
	var ok bool
	switch kind {
	case model.KindContainerImage:
		canonical, ok = model.ContainerImageKey(key)
	case model.KindPackage:
		canonical, ok = model.PackageKey(key)
	}
	return ok && canonical == key
}

func validateArtifacts(v *validator, r *Request) {
	if len(r.Artifacts) > MaxArtifacts || len(r.Relations) > MaxArtifactRelations {
		v.req(fmt.Sprintf("artifact graph exceeds %d nodes or %d relations", MaxArtifacts, MaxArtifactRelations))
		return
	}
	type assetKey struct {
		kind model.AssetKind
		key  string
	}
	seen := make(map[assetKey]bool, len(r.Artifacts))
	for i, artifact := range r.Artifacts {
		key := assetKey{artifact.Kind, artifact.Key}
		if !artifactKey(artifact.Kind, artifact.Key) || seen[key] {
			v.req(fmt.Sprintf("artifacts[%d]: duplicate or noncanonical image/package identity", i))
		}
		seen[key] = true
		if problem := artifactAttrs(artifact); problem != "" {
			v.req(fmt.Sprintf("artifacts[%d]: %s", i, problem))
		}
		if v.full() {
			return
		}
	}
	for i, relation := range r.Relations {
		if relation.Type != model.RelContains || relation.FromKind != model.KindContainerImage || relation.ToKind != model.KindPackage ||
			!seen[assetKey{relation.FromKind, relation.FromKey}] || !seen[assetKey{relation.ToKind, relation.ToKey}] {
			v.req(fmt.Sprintf("relations[%d]: only contains edges between declared images and packages are allowed", i))
		}
		if v.full() {
			return
		}
	}
}

func artifactAttrs(artifact Artifact) string {
	if problem := evidenceProblem(artifact.Attrs); problem != "" {
		return problem
	}
	for key, value := range artifact.Attrs {
		switch key {
		case "digest":
			if artifact.Kind != model.KindContainerImage || value != artifact.Key {
				return "digest must match the image key"
			}
		case "purl":
			if artifact.Kind != model.KindPackage || value != artifact.Key {
				return "purl must match the package key"
			}
		case "name", "version", "type", "scanner_version":
			text, ok := value.(string)
			if !ok || len(text) > 512 || !cleanLine(text) {
				return "metadata must be bounded single-line strings"
			}
		case "repositories":
			if artifact.Kind != model.KindContainerImage {
				return "repositories requires an image"
			}
			// JSON decoding produces []any; parsers construct []string.
			var repositories []string
			switch values := value.(type) {
			case []string:
				repositories = values
			case []any:
				for _, item := range values {
					repository, ok := item.(string)
					if !ok {
						return "repositories must be strings"
					}
					repositories = append(repositories, repository)
				}
			default:
				return "repositories must be an array"
			}
			if len(repositories) > 20 {
				return "at most 20 repositories allowed"
			}
			for _, repository := range repositories {
				if len(repository) > MaxAssetKeyLen {
					return "repository reference too long"
				}
				if digest, ok := model.ContainerImageKey(repository); !ok || digest != artifact.Key {
					return "repositories must name this exact manifest digest"
				}
			}
		default:
			return "unsupported metadata field (ownership and raw reports are forbidden)"
		}
	}
	return ""
}
