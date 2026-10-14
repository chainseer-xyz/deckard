// Package trivy imports vulnerability findings and immutable image inventory.
package trivy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

const Tool = "trivy"

// MaxInputBytes bounds native reports before JSON allocation/decoding.
const MaxInputBytes = 64 << 20

type report struct {
	SchemaVersion int
	ArtifactType  string
	Trivy         struct{ Version string }
	Metadata      struct{ RepoDigests []string }
	Results       []result
}

type identifier struct{ PURL string }

type result struct {
	Target, Class, Type                                                string
	Packages                                                           []struct{ Identifier identifier }
	Vulnerabilities                                                    []vulnerability
	Secrets, Misconfigurations, Licenses, ExperimentalModifiedFindings []json.RawMessage
}

type vulnerability struct {
	VulnerabilityID, PkgID, PkgName, PkgPath string
	InstalledVersion, FixedVersion           string
	Severity, PrimaryURL                     string
	PkgIdentifier                            identifier
}

// ParseReport accepts native SchemaVersion 2 container-image vulnerability
// reports. RepoDigests, never ImageID or a mutable tag, establish identity.
// The importer does not infer scanner success or filtering from JSON; the
// producer must use --incomplete unless it supplies the whole vulnerability run.
func ParseReport(data []byte, _ ingest.ParseOptions) (ingest.ArtifactReport, error) {
	if len(data) > MaxInputBytes {
		return ingest.ArtifactReport{}, fmt.Errorf("trivy report exceeds the 64 MiB input limit")
	}
	var doc report
	if err := json.Unmarshal(data, &doc); err != nil {
		return ingest.ArtifactReport{}, fmt.Errorf("trivy report is not valid JSON")
	}
	if doc.SchemaVersion != 2 || doc.ArtifactType != "container_image" || doc.Results == nil {
		return ingest.ArtifactReport{}, fmt.Errorf("trivy requires SchemaVersion 2, container_image and an explicit Results array")
	}
	digest, repositories, err := imageIdentity(doc.Metadata.RepoDigests)
	if err != nil {
		return ingest.ArtifactReport{}, err
	}
	attrs := map[string]any{"digest": digest}
	if len(repositories) > 0 {
		attrs["repositories"] = repositories
	}
	if version := ingest.Line(doc.Trivy.Version, 64); version != "" {
		attrs["scanner_version"] = version
	}
	out := ingest.ArtifactReport{Findings: []ingest.Finding{}, Artifacts: []ingest.Artifact{{Kind: model.KindContainerImage, Key: digest, Attrs: attrs}}}
	packages := map[string]ingest.Artifact{}
	for index, res := range doc.Results {
		if err := appendResult(&out, packages, digest, res); err != nil {
			return ingest.ArtifactReport{}, fmt.Errorf("trivy result %d: %w", index, err)
		}
	}
	keys := make([]string, 0, len(packages))
	for key := range packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out.Artifacts = append(out.Artifacts, packages[key])
		out.Relations = append(out.Relations, model.RelationInput{FromKind: model.KindContainerImage, FromKey: digest, ToKind: model.KindPackage, ToKey: key, Type: model.RelContains})
	}
	// Finalize drops duplicate keys. Order duplicate observations first so
	// report order cannot lower severity or change the request replay digest.
	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.Severity != b.Severity {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Compare(left, right) < 0
	})
	out.Findings = ingest.Finalize(out.Findings)
	return out, nil
}

func imageIdentity(refs []string) (string, []string, error) {
	if len(refs) == 0 {
		return "", nil, fmt.Errorf("trivy Metadata.RepoDigests must identify an immutable image manifest")
	}
	var digest string
	repositories := map[string]bool{}
	for _, ref := range refs {
		key, ok := model.ContainerImageKey(ref)
		if !ok {
			return "", nil, fmt.Errorf("trivy Metadata.RepoDigests contains an invalid manifest reference")
		}
		if digest != "" && digest != key {
			return "", nil, fmt.Errorf("trivy Metadata.RepoDigests contains ambiguous manifest digests")
		}
		digest = key
		if strings.ContainsRune(ref, '@') {
			repository := strings.TrimPrefix(ref, "docker-pullable://")
			if len(repository) <= 512 {
				repositories[repository] = true
			}
		}
	}
	names := make([]string, 0, len(repositories))
	for name := range repositories {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 20 {
		return "", nil, fmt.Errorf("trivy image has too many repository aliases")
	}
	return digest, names, nil
}

func appendResult(out *ingest.ArtifactReport, packages map[string]ingest.Artifact, digest string, res result) error {
	if len(res.Secrets)+len(res.Misconfigurations)+len(res.Licenses)+len(res.ExperimentalModifiedFindings) > 0 {
		return fmt.Errorf("only vulnerability reports are supported; secret, misconfiguration, license and modified findings cannot be silently omitted")
	}
	if res.Class != "os-pkgs" && res.Class != "lang-pkgs" {
		return fmt.Errorf("unsupported result class; only os-pkgs and lang-pkgs are supported")
	}
	for _, pkg := range res.Packages {
		if _, err := addPackage(packages, pkg.Identifier.PURL); err != nil {
			return err
		}
	}
	for _, vuln := range res.Vulnerabilities {
		if strings.TrimSpace(vuln.VulnerabilityID) == "" || strings.TrimSpace(vuln.PkgName) == "" || strings.TrimSpace(vuln.InstalledVersion) == "" {
			return fmt.Errorf("vulnerability requires an ID, package name and installed version")
		}
		purl, err := addPackage(packages, vuln.PkgIdentifier.PURL)
		if err != nil {
			return err
		}
		out.Findings = append(out.Findings, makeFinding(digest, purl, res, vuln))
		if len(out.Findings) > ingest.MaxFindings {
			return fmt.Errorf("vulnerability count exceeds the ingest limit")
		}
	}
	return nil
}

func addPackage(packages map[string]ingest.Artifact, raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	p, err := packageurl.FromString(raw)
	if err != nil {
		return "", fmt.Errorf("package PURL cannot be decoded")
	}
	if p.Version == "" {
		// Validate all other identity fields and qualifiers without inventing
		// an inventory key for a package whose version is unknown.
		p.Version = "validation-only"
		if _, ok := model.PackageKey(p.ToString()); !ok {
			return "", fmt.Errorf("unversioned package PURL is malformed or credential-bearing")
		}
		return "", nil
	}
	key, ok := model.PackageKey(raw)
	if !ok {
		return "", fmt.Errorf("package PURL must be valid, versioned and free of credentials")
	}
	p, err = packageurl.FromString(key)
	if err != nil {
		return "", fmt.Errorf("package PURL cannot be decoded")
	}
	packages[key] = ingest.Artifact{Kind: model.KindPackage, Key: key, Attrs: map[string]any{"purl": key, "name": p.Name, "version": p.Version, "type": p.Type}}
	if len(packages)+1 > ingest.MaxArtifacts {
		return "", fmt.Errorf("package count exceeds the ingest limit")
	}
	return key, nil
}

func makeFinding(digest, purl string, res result, vuln vulnerability) ingest.Finding {
	packageIdentity := purl
	if packageIdentity == "" {
		packageIdentity = vuln.PkgID
	}
	if packageIdentity == "" {
		packageIdentity = vuln.PkgName
	}
	targetIdentity := res.Target
	if res.Class == "os-pkgs" {
		// OS Target is an image display label and may contain a mutable tag
		// or registry alias. The manifest digest already identifies its rootfs.
		targetIdentity = "os-pkgs:" + res.Type
	}
	identity, _ := json.Marshal([]string{digest, targetIdentity, packageIdentity, vuln.InstalledVersion, vuln.PkgPath, vuln.VulnerabilityID})
	hash := sha256.Sum256(identity)
	ev := map[string]any{"image_digest": digest, "package_purl": purl, "package_name": vuln.PkgName,
		"installed_version": vuln.InstalledVersion, "fixed_version": vuln.FixedVersion, "target": res.Target,
		"package_path": vuln.PkgPath, "vulnerability_id": vuln.VulnerabilityID, "primary_url": ingest.SafeURL(vuln.PrimaryURL)}
	tags := []string{"trivy", "vulnerability"}
	if cve, ok := vulnintel.NormalizeCVE(vuln.VulnerabilityID); ok {
		ev["cve_id"] = cve
		tags = append(tags, cve)
	}
	description := fmt.Sprintf("Package %s %s is affected by %s.", vuln.PkgName, vuln.InstalledVersion, vuln.VulnerabilityID)
	remediation := "Review the package advisory and upgrade to a non-vulnerable version when available."
	if vuln.FixedVersion != "" {
		remediation = "Upgrade to a fixed package version: " + vuln.FixedVersion
	}
	return ingest.Finding{Key: "trivy:" + hex.EncodeToString(hash[:]), Asset: ingest.Asset{Kind: model.KindContainerImage, Key: digest},
		Title: vuln.VulnerabilityID + " in " + vuln.PkgName, Description: description, Severity: ingest.Severity(vuln.Severity),
		Remediation: remediation, Tags: tags, Evidence: ev}
}
