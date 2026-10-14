package model

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/distribution/reference"
	packageurl "github.com/package-url/packageurl-go"
)

// ContainerImageKey returns a manifest digest identity, not an image tag or a
// container runtime config ID. Callers must establish the input's provenance;
// the syntax alone cannot distinguish a config digest from a manifest digest.
func ContainerImageKey(raw string) (string, bool) {
	value := strings.TrimPrefix(raw, "docker-pullable://")
	digest := value
	if at := strings.LastIndexByte(value, '@'); at >= 0 {
		if _, err := reference.ParseNormalizedNamed(value); err != nil {
			return "", false
		}
		digest = value[at+1:]
	}
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
		return "", false
	}
	for _, c := range digest[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return digest, true
}

// PackageKey canonicalizes a versioned package URL. Qualifiers are restricted
// to identity metadata; credentials and arbitrary producer properties must not
// become globally visible inventory keys.
func PackageKey(raw string) (string, bool) {
	if len(raw) > 512 || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", false
	}
	p, err := packageurl.FromString(raw)
	if err != nil || p.Name == "" || p.Version == "" {
		return "", false
	}
	for _, qualifier := range p.Qualifiers {
		switch qualifier.Key {
		case "arch", "distro", "epoch", "os", "os_version", "goos", "goarch", "checksum", "tag":
		case "repository_url":
			if p.Type == "oci" && !strings.Contains(qualifier.Value, "://") {
				ref, err := reference.ParseNormalizedNamed(qualifier.Value)
				if err != nil || reference.IsNameOnly(ref) == false {
					return "", false
				}
				continue
			}
			u, err := url.Parse(qualifier.Value)
			if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
				return "", false
			}
		default:
			return "", false
		}
	}
	key := p.ToString()
	return key, len(key) <= 512 && strings.IndexFunc(key, unicode.IsControl) < 0
}

// NetworkKind is deliberately a positive list. New metadata kinds must not
// inherit scope-driven resolution or network access by default.
func NetworkKind(kind AssetKind) bool {
	switch kind {
	case KindZone, KindHostname, KindIP, KindService, KindURL:
		return true
	}
	return false
}
