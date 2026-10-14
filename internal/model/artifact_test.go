package model

import (
	"strings"
	"testing"
)

func TestContainerImageKey(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, input := range []string{digest, "registry.example/team/image@" + digest, "docker-pullable://registry.example/team/image@" + digest} {
		if got, ok := ContainerImageKey(input); !ok || got != digest {
			t.Errorf("ContainerImageKey(%q) = %q, %v", input, got, ok)
		}
	}
	for _, input := range []string{"image:latest", "sha256:abc", "docker://" + digest, "sha256:" + strings.Repeat("A", 64), "https://user:secret@registry/image@" + digest, " " + digest, "bad@ref@" + digest} {
		if got, ok := ContainerImageKey(input); ok {
			t.Errorf("accepted invalid image %q as %q", input, got)
		}
	}
}

func TestPackageKey(t *testing.T) {
	for _, input := range []string{"pkg:apk/alpine/openssl@3.5.1-r0?arch=aarch64", "pkg:golang/golang.org/x/net@v0.42.0", "pkg:npm/%40example/library@1.0.0"} {
		if _, ok := PackageKey(input); !ok {
			t.Errorf("rejected versioned purl %q", input)
		}
	}
	for _, input := range []string{"", "openssl@3", "pkg:npm/library", "pkg:npm/library@1?token=secret", "pkg:generic/lib@1?repository_url=https%3A%2F%2Fu%3Ap%40host", "pkg:generic/lib@1\x00"} {
		if got, ok := PackageKey(input); ok {
			t.Errorf("accepted invalid or secret-bearing purl %q as %q", input, got)
		}
	}
}
