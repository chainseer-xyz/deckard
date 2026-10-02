# Security policy

## Reporting a vulnerability

Please report security issues privately using the "Report a vulnerability"
option (private security advisories) on this repository rather than a public
issue. Include the affected version, the impact and reproduction steps.

## Scope

In scope: authentication or authorisation bypass in the API or UI, anything that
lets deckard send probe traffic to an asset outside the configured scope
(`internal/scope`), injection, secret disclosure, and unsafe defaults in the
container image or Helm chart.

Out of scope: findings produced *about* your own infrastructure (that is what
the tool is for), and denial of service by an already-authenticated operator.

## Hardening notes for operators

- Keep `auth.mode: token` or `oidc`; use `none` only behind a trusted proxy.
- Use a read-only Cloudflare token and a read-only AWS role. See `docs/aws-iam.md`.
- Protect `/metrics` (`server.metrics_token_env`) or restrict it with the
  chart's NetworkPolicy.
- Pin image tags and scan the image (Trivy runs in CI).

## Verifying releases

Every release image (`ghcr.io/chainseer-xyz/deckard:<version>` and the `-slim`
variant) is built in GitHub Actions, signed keyless with cosign (Sigstore, the
signing identity is the release workflow) and carries an SPDX SBOM and SLSA
build provenance. Verify before you deploy; replace `<version>` with the tag:

```sh
# Signature: must have been produced by this repo's release workflow on a tag.
cosign verify ghcr.io/chainseer-xyz/deckard:<version> \
  --certificate-identity-regexp '^https://github.com/chainseer-xyz/deckard/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Build provenance attestation (GitHub CLI).
gh attestation verify oci://ghcr.io/chainseer-xyz/deckard:<version> --repo chainseer-xyz/deckard

# SBOM and provenance attached to the image index.
docker buildx imagetools inspect ghcr.io/chainseer-xyz/deckard:<version> --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/chainseer-xyz/deckard:<version> --format '{{ json .Provenance }}'
```

Pin by digest (`image@sha256:...`) after verifying so the tag cannot move.

## Dependency and image hygiene

Dependabot raises weekly PRs for Go modules, npm, the Dockerfile and GitHub
Actions. `govulncheck` runs on every PR and daily, a weekly workflow bumps the
bundled nuclei engine, and a weekly from-scratch image rebuild is Trivy-scanned;
failures open a tracking issue labelled `security`. See `docs/operations.md`.
