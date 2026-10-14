# Complete and deploy the OSS platform

## Outcome and scope
Ship the remaining OSS integrations through reviewed source changes and a pinned Marina staging deployment. Reuse existing inventory, PostgreSQL, scanner reconciliation and Marina's Tetragon sensor. Include scheduled collectors, event-only runtime findings, bounded ZGrab2/ZAP/Strix execution and operational coverage. Never treat telemetry silence, skipped probes, failed scans or an SBOM as a clean assessment.

## Delivery actions
1. [ ] Add scheduled Trivy/Kubescape/Prowler/BBOT collector templates under `deploy/helm/deckard/templates` with separate credentials, bounded jobs and fresh-report delivery. Verify render and local scanner fixtures. Blocked by: none.
2. [ ] Add native Falco/Tetragon event parsers under `internal/ingest`, exact workload correlation and incomplete-only lifecycle. Verify malformed/replayed/late events, retained incidents and secret exclusion with real PostgreSQL. Blocked by: none.
3. [ ] Implement enforced assessment authorization and execution in `internal/assessment`; integrate contained ZGrab2, ZAP and Strix without host sockets or inherited cloud/cluster credentials. Verify positive and denied local fixtures, DNS changes, bypass attempts, timeout/output limits and incomplete results. Blocked by: none.
4. [ ] Wire collector/runtime/assessment commands in `cmd/deckard` and authenticated API operations in `internal/api`. Verify public command/API contracts and lifecycle end to end. Blocked by: 1–3.
5. [ ] Expose producer freshness and runtime/assessment state in metrics, alerts, OpenAPI, web UI and operator docs. Verify healthy-empty, stale, partial and failed runs differ. Blocked by: 1–4.
6. [ ] Exercise artifact retention and identity-lock throughput; add bounded retention only where provenance proves safe removal. Preserve findings and overlapping authorities. Blocked by: 2, 4.
7. [ ] Review each slice independently; run race/PostgreSQL, web, Helm, vulnerability, secret and shipped-binary containment checks. Merge source PRs and publish a signed, pinned release. Blocked by: 1–6.
8. [ ] Update only Deckard's staging configuration in `marina-infra`; follow the generated `marina-platform-manifests` pipeline. Drain old writers before enabling new topology/collectors. Blocked by: 7.
9. [ ] Watch ArgoCD, boot logs, readiness, scanner jobs, runtime delivery and authenticated UI/API behavior. Fix failures, repeat tests, verify persistent results, then clean owned branches/worktrees/processes. Blocked by: 8.

## Execution contract
Root owns integration, merges, release, rollout, verification and cleanup. Workers own disjoint files and return test evidence. Each behavior starts with a failing test. After three unchanged failures, inspect the evidence and change strategy instead of repeating the same attempt. Preserve progress through atomic commits and this checklist. Stop only after the outcome passes or a real access/safety dependency prevents further progress.

## Deployment decisions
Use the existing Marina staging Deckard environment and its established read-only IAM identity. Do not widen cloud permissions, expose internal services, add CPU limits or install a second privileged runtime sensor. Runtime events remain incomplete. Active assessment jobs require explicit inventory-backed target authorization and enforced egress; model inference uses an approved local service or an explicitly configured provider, never an invented credential or unapproved paid account.

## Evidence required
Green reviewed source and infra changes; immutable release digest; generated manifest revision; healthy new pods with old writers gone; successful scheduled collector runs and retained image/workload/package joins; real runtime delivery; contained positive/negative assessment fixtures; authenticated UI/API smoke tests; zero owned resource leaks. Record unavailable live coverage plainly, never as a passing test.
