# Complete and deploy the OSS platform

## Outcome and scope
Ship the remaining OSS integrations through reviewed source changes and a pinned Marina staging deployment. Reuse existing inventory, PostgreSQL, scanner reconciliation and Marina's Tetragon sensor. Include scheduled collectors, event-only runtime findings, bounded ZGrab2/ZAP/Strix execution and operational coverage. Never treat telemetry silence, skipped probes, failed scans or an SBOM as a clean assessment.

## Delivery actions
1. [x] Add scheduled Trivy/Kubescape/Prowler/BBOT collector templates under `deploy/helm/deckard/templates` with separate credentials, bounded jobs and fresh-report delivery. Verify render and local scanner fixtures. Includes runtime-image and existing Tetragon collectors.
2. [x] Add native Falco/Tetragon event parsers under `internal/ingest`, exact workload correlation and incomplete-only lifecycle. Verify malformed/replayed/late events, retained incidents and secret exclusion with real PostgreSQL.
3. [x] Implement enforced assessment authorization and execution in `internal/assessment`; integrate contained ZGrab2, ZAP and Strix without host sockets or inherited cloud/cluster credentials. Verify positive and denied local fixtures, DNS changes, bypass attempts, timeout/output limits and incomplete results. Live CNI verification remains step 9.
4. [x] Wire collector/runtime/assessment commands in `cmd/deckard` and authenticated API operations in `internal/api`. Verify public command/API contracts and lifecycle end to end.
5. [x] Expose producer freshness and runtime/assessment state in metrics, alerts, OpenAPI, web UI and operator docs. Verify healthy-empty, stale, partial and failed runs differ.
6. [x] Exercise artifact retention and identity-lock throughput. Preserve additive artifacts because current provenance cannot prove safe removal. Findings and overlapping authorities remain intact.
7. [ ] Review each slice independently; run race/PostgreSQL, web, Helm, vulnerability, secret and shipped-binary containment checks. Merge source PRs and publish a signed, pinned release. Blocked by: 1–6.
8. [ ] Update only Deckard's staging configuration in `marina-infra`; follow the generated `marina-platform-manifests` pipeline. Drain old writers before enabling new topology/collectors. Blocked by: 7.
9. [ ] Watch ArgoCD, boot logs, readiness, scanner jobs, runtime delivery and authenticated UI/API behavior. Fix failures, repeat tests, verify persistent results, then clean owned branches/worktrees/processes. Blocked by: 8.

## Execution contract
Root owns integration, merges, release, rollout, verification and cleanup. Workers own disjoint files and return test evidence. Each behavior starts with a failing test. After three unchanged failures, inspect the evidence and change strategy instead of repeating the same attempt. Preserve progress through atomic commits and this checklist. Stop only after the outcome passes or a real access/safety dependency prevents further progress.

## Deployment decisions
Use the existing Marina staging Deckard environment and its established read-only IAM identity. Do not widen cloud permissions, expose internal services, add CPU limits or install a second privileged runtime sensor. Runtime events remain incomplete. Active assessment jobs require explicit inventory-backed target authorization and enforced egress; model inference uses an approved local service or an explicitly configured provider, never an invented credential or unapproved paid account.

## Evidence required
Green reviewed source and infra changes; immutable release digest; generated manifest revision; healthy new pods with old writers gone; successful scheduled collector runs and retained image/workload/package joins; real runtime delivery; contained positive/negative assessment fixtures; authenticated UI/API smoke tests; zero owned resource leaks. Record unavailable live coverage plainly, never as a passing test.

## Source evidence, 2026-10-14

- Core source commit `4527a5d`; runtime identity/lifecycle commit `dd7e616`.
- Full Go race suite: `3103` tests, `80` tested packages, no failures; real PostgreSQL containers used. Opt-in native Trivy and contention tests ran separately.
- Contention fixture: `144` transactions, `3200` finding updates and `800` inventory rows in `17.935s`; p95 `1.398s`. This is local regression evidence, not Marina capacity.
- Actual native ZGrab2/ZAP/Strix interoperability passed with no skips. ZAP native TLS preconnections and foreign-origin probes remain conservatively partial. Strix missing-model and local protocol tests do not claim live-model coverage.
- Optional runner images retain upstream notices. Strix applies five exact hashed security upgrades and excludes unused pip vendors. ZAP excludes unused Python/Webswing components.
- Full application/Nuclei, ZAP, Strix and patched ZGrab candidate scans have no fixable high/critical vulnerabilities. CI, merge and signed release are pending.
- Native browser desktop/mobile checks use local mock data, not live Marina evidence. Producer freshness and controller-restart recovery have UI regression tests.

## Deployment blocker

`marina-staging-superuser` AWS SSO is expired. Read-only STS verification still fails; no live Kubernetes write, CNI check or deployment is claimed.
Continue source delivery and prepare immutable staging configuration, but do not invent cluster UIDs, scoped Secrets, CNI enforcement or model credentials.
The new API assessment ServiceAccount needs an exact-subject IRSA trust update before it performs AWS inventory work. Resolve its final rendered name before changing trust.
