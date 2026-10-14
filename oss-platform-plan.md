# OSS practitioner platform

## Goal
Join exposure, cloud posture, Kubernetes workloads and vulnerable artifacts in Deckard's existing inventory and finding lifecycle.

## Scope
Build the first release without paid APIs: exact resource correlation, opt-in Kubernetes topology, native Trivy/CycloneDX imports and BBOT file discovery. Reuse PostgreSQL, the graph, source health and scanner reconciliation. Do not bundle scanners, grant credentials, enable active scans or deploy production.

## Actions
1. [ ] Define digest-addressed image/package/workload contracts in `internal/model` and bounded artifact ingest in `internal/ingest`. Verify malformed identities and forbidden probe kinds. Blocked by: none.
2. [ ] Persist artifact nodes and edges atomically through `internal/api/ingest.go` and `internal/store/postgres/ingest.go`. Verify replay, partial reports, source overlap and CVE retention. Blocked by: 1.
3. [ ] Import Trivy JSON and CycloneDX through `cmd/deckard/ingest.go`. Verify clean reports, digest joins, package identities and secret exclusion. Blocked by: 1–2.
4. [ ] Add optional workload topology to `internal/source/kubernetes`. Verify namespace/cluster isolation, backend links, denied RBAC and unresolved image tags. Blocked by: 1.
5. [ ] Correlate cloud resources using exact authoritative identity in `internal/identity`. Verify account/region ambiguity cannot merge resources or change ownership. Blocked by: 1.
6. [ ] Import BBOT NDJSON through `internal/source` without running BBOT. Verify discovery cannot claim zones/IP ownership or remove assets. Blocked by: 1.
7. [ ] Expose new graph kinds in `web/src` and document configuration, minimum RBAC and coverage gaps in `docs`. Verify UI tests, examples and OpenAPI agree. Blocked by: 2–6.
8. [ ] Review the final diff, run Go race/PostgreSQL, web and Helm checks, then land a PR and clean owned branches/processes. Verify the merged remote commit. Blocked by: 1–7.

## Requirement → evidence
| Requirement | Evidence | Reviewer |
|---|---|---|
| Shared identity without new scan authority | Identity, scope and source-overlap regressions | Independent code review |
| Workload → image digest → package → CVE | Kubernetes fixtures plus API/store artifact integration tests | Independent code review |
| Failure is not clean | Denied-RBAC, malformed-report, partial and replay tests | Independent code review |
| Honest OSS coverage | Source health, ingest scope history and documented profiles | Source/example comparison |

## Later milestones
Selective ZGrab2 requires enforced subprocess egress, not hostname preflight. Falco runtime events need an event lifecycle, not snapshot reconciliation. Authenticated ZAP and optional Strix pentesting need explicit target authorization, credential isolation and budgets. Strix v1.7.0 SARIF compatibility is tested now; no agentic runner is enabled. Automated collector jobs need operator-selected scope, permissions and schedules. These remain separate releases; imported reports do not mean a collector is running.

## Done when
The first release's actions pass and merge. The API and UI show shared digest identities and retained findings without enabling new probes. Remaining milestones stay explicit rather than appearing as implemented coverage.
