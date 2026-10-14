# Deckard project contracts

## Inventory and identity

Authoritative source facts establish ownership. Report imports and discovered
metadata never grant network authority. Keep exact identities, attributed facts
and typed relationships; refuse ambiguous correlations. Inventory and ingest
mutations share a PostgreSQL identity lock. Do not narrow it without concurrency
and persisted-identity tests.

Partial or failed sources cannot remove assets. Artifact inventory remains
additive until provenance can prove safe expiry. Metadata inventory changes
cannot resolve scanner findings. Upgrade every writer before enabling new
identity/topology semantics; see `docs/operations.md`.

## Producers and lifecycle

Dedicated producer tokens grant exact tools/scopes or remote discovery sources.
They are write-only, distinct from admin credentials and isolated from scanner
containers. A successful HTTP status is insufficient: validate a delivery
receipt before declaring collection successful.

Delivery freshness and complete coverage are separate concepts. Runtime incidents
never resolve through silence, asset removal or empty batches. Older/duplicate
events cannot reopen resolved incidents. Manual runtime resolution requires an
audit note. SBOM, restricted posture and agentic reports remain additive.

## Assessment boundary

Only explicit operator requests can start isolated assessments against current
owned inventory targets. Never inherit cloud/admin/Kubernetes credentials, host
sockets or arbitrary scanner arguments. Use immutable tool images, dedicated
namespaces, enforced egress, cumulative budgets and bounded lifecycle cleanup.
Session status is ephemeral; findings are durable.

Preserve strict scope/TLS/refusal behavior even when a scanner exits successfully.
Current ZGrab2, ZAP and Strix integrations do not establish vulnerability absence.
Read `docs/collectors.md` and `docs/oss-platform-threat-model.md` before changing
the network, credential, authentication or completeness boundaries.

## Verification and delivery

Run real PostgreSQL race tests, not just fake stores. Native scanner fixtures
test actual pinned binaries and wrappers; opt-in skips mean missing coverage.
The Helm suite includes collector/RBAC/assessment contracts and real offline
BBOT SDK fixtures. Runner CI also checks dependencies and license notices.

Docker fixtures and rendered NetworkPolicies do not prove Kubernetes containment.
Verify real positive/negative CNI fixtures before enabling assessments. Model
protocol and failure fixtures do not prove a successful model-backed assessment.
Never invent provider credentials, paid-model authority or live coverage.

Marina staging's source of truth is `marina-infra`; its publishing workflow writes
`marina-platform-manifests` on `platform-staging`. Update the source image/chart
pins, follow generation and Argo, then verify Pods and behavior. Do not edit an
unrelated `marina-manifests` checkout or deploy a production tag for staging work.
