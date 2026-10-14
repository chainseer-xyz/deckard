// Package cyclonedx imports SBOM inventory without inferring clean CVE scans.
package cyclonedx

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const Tool = "cyclonedx"

// MaxInputBytes bounds native reports before JSON allocation/decoding.
const MaxInputBytes = 64 << 20

type bom struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Component component `json:"component"`
	} `json:"metadata"`
	Components []component `json:"components"`
}

type component struct {
	Type       string      `json:"type"`
	PURL       string      `json:"purl"`
	Components []component `json:"components"`
}

// ParseReport accepts image SBOMs bound by a container's OCI PURL version.
// A bare component hash could identify a config or file, not a manifest.
// Vulnerabilities and arbitrary properties are intentionally not imported:
// an SBOM inventory never supplies evidence of a complete vulnerability scan.
func ParseReport(data []byte, _ ingest.ParseOptions) (ingest.ArtifactReport, error) {
	if len(data) > MaxInputBytes {
		return ingest.ArtifactReport{}, fmt.Errorf("CycloneDX report exceeds the 64 MiB input limit")
	}
	var doc bom
	if err := json.Unmarshal(data, &doc); err != nil {
		return ingest.ArtifactReport{}, fmt.Errorf("CycloneDX report is not valid JSON")
	}
	if doc.BOMFormat != "CycloneDX" || doc.Version < 1 || !supportedVersion(doc.SpecVersion) {
		return ingest.ArtifactReport{}, fmt.Errorf("CycloneDX requires bomFormat, a supported 1.4-1.7 specVersion and positive version")
	}
	digest, attrs, err := imageIdentity(doc.Metadata.Component)
	if err != nil {
		return ingest.ArtifactReport{}, err
	}
	packages := map[string]ingest.Artifact{}
	count := 0
	if err := collectComponents(packages, doc.Components, 0, &count); err != nil {
		return ingest.ArtifactReport{}, err
	}
	if err := collectComponents(packages, doc.Metadata.Component.Components, 0, &count); err != nil {
		return ingest.ArtifactReport{}, err
	}
	out := ingest.ArtifactReport{Findings: []ingest.Finding{}, Artifacts: []ingest.Artifact{{Kind: model.KindContainerImage, Key: digest, Attrs: attrs}}}
	keys := make([]string, 0, len(packages))
	for key := range packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out.Artifacts = append(out.Artifacts, packages[key])
		out.Relations = append(out.Relations, model.RelationInput{FromKind: model.KindContainerImage, FromKey: digest, ToKind: model.KindPackage, ToKey: key, Type: model.RelContains})
	}
	return out, nil
}

func supportedVersion(version string) bool {
	switch version {
	case "1.4", "1.5", "1.6", "1.7":
		return true
	}
	return false
}

func imageIdentity(root component) (string, map[string]any, error) {
	key, ok := model.PackageKey(root.PURL)
	if root.Type != "container" || !ok {
		return "", nil, fmt.Errorf("CycloneDX metadata.component must be a container with an immutable OCI PURL")
	}
	p, err := packageurl.FromString(key)
	if err != nil || p.Type != "oci" || p.Namespace != "" || p.Subpath != "" {
		return "", nil, fmt.Errorf("CycloneDX image PURL must identify one OCI artifact")
	}
	digest, ok := model.ContainerImageKey(p.Version)
	if !ok {
		return "", nil, fmt.Errorf("CycloneDX image PURL version must be a sha256 manifest digest, not a tag or file hash")
	}
	attrs := map[string]any{"digest": digest}
	for _, qualifier := range p.Qualifiers {
		if qualifier.Key == "repository_url" {
			attrs["repositories"] = []string{strings.TrimPrefix(strings.TrimPrefix(qualifier.Value, "https://"), "http://") + "@" + digest}
		}
	}
	return digest, attrs, nil
}

func collectComponents(packages map[string]ingest.Artifact, components []component, depth int, count *int) error {
	if depth > ingest.MaxEvidenceDepth {
		return fmt.Errorf("CycloneDX component nesting exceeds the limit")
	}
	for _, c := range components {
		*count++
		if *count >= ingest.MaxArtifacts {
			return fmt.Errorf("CycloneDX component count exceeds the ingest limit")
		}
		if c.PURL != "" {
			if err := addPackage(packages, c.PURL); err != nil {
				return err
			}
		}
		if err := collectComponents(packages, c.Components, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func addPackage(packages map[string]ingest.Artifact, raw string) error {
	p, err := packageurl.FromString(raw)
	if err != nil {
		return fmt.Errorf("CycloneDX package PURL cannot be decoded")
	}
	if p.Version == "" {
		p.Version = "validation-only"
		if _, ok := model.PackageKey(p.ToString()); !ok {
			return fmt.Errorf("CycloneDX unversioned PURL is malformed or credential-bearing")
		}
		return nil
	}
	key, ok := model.PackageKey(raw)
	if !ok {
		return fmt.Errorf("CycloneDX package PURL must be valid, versioned and free of credentials")
	}
	p, err = packageurl.FromString(key)
	if err != nil {
		return fmt.Errorf("CycloneDX package PURL cannot be decoded")
	}
	packages[key] = ingest.Artifact{Kind: model.KindPackage, Key: key, Attrs: map[string]any{"purl": key, "name": p.Name, "version": p.Version, "type": p.Type}}
	return nil
}
