# Independent review findings (round 1)

Source: two read-only reviews (core: engine/inventory/finding/app/store; API: api/auth/UI/helm).
Status legend: [ ] open, [~] in progress, [x] fixed + regression-tested.

## Core (correctness and safety)

- [x] **C1 Findings on removed assets never resolve.** `ApplySnapshot` marks an asset removed, `runScan` refuses removed assets, nothing resolves its findings, and the dispatcher re-pushes the alert forever. Breaks "fixing an issue resolves its alert". Fix: resolve open/acknowledged findings of removed assets in the snapshot transaction (or housekeeping) and exclude removed assets from the dispatcher's open list.
- [x] **C2 Ownership hijack.** `owns := revived || old.Source == own` lets any check revive a removed asset and take ownership (no snapshot removes it again), and a source can never claim an asset a check discovered first. Fix: sources may claim assets owned by `check:*`/`net.*`; check discovery revives without taking ownership.
- [x] **C3 Derived assets/relations never garbage-collected.** Closed ports/changed IPs leave stale `service` assets and edges; `origin.exposed` sees old IPs forever. Fix: prune derived assets/relations not re-observed by their producing check.
- [x] **C4 Partial discovery counts as success.** Cloudflare/Kubernetes skip sub-features on 403/NotFound, then the snapshot removes everything that feature produced. Fix: `Discovery.Partial` flag skips removal (plus an empty/shrink guard).
- [x] **C5 `net.services` attrs dropped/clobbered.** Owner mismatch drops the `tls` attr, and `net.ports` rewrites attrs each scan, so `tls.config` never applies to discovered services. Fix: per-key attr merge for derived assets.
- [x] **C6 Scheduling window too small.** `ListScans(limit)` window loses active/intrusive history, so checks look never-scanned and re-run every 30s tick (worse with split roles and after restart). Fix: store query for last scan per (asset, check) with index, plus retention on `scans`.
- [x] **C7 Graceful shutdown defeated.** `cancel()` runs before `eng.Stop`; River treats cancelled start context as stop-and-cancel. Fix: `eng.Start(context.WithoutCancel(ctx))`.
- [x] **C8 Errors count as attempts.** Errored scans satisfy `isDue`, delaying retries to the full interval. Fix: ignore errored runs in last-scan state or retry sooner.
- [x] **C9 Drift noise.** `days_remaining` (and any volatile field) causes daily drift open/resolve and per-value fingerprints. Fix: add to default ignore keys, wire `learning.ignore_keys` config.
- [x] **C10 Wiring gaps.** (expansion scheduled; queue workers configurable; inventory metric counted once; single DB pool) Expansion (CT/wildcard/bruteforce) unreferenced (being fixed in engine-v2); `WithQueueWorkers` never set from config; `inventory_changes_total` double-counted; two pools each sized `MaxConns`.
- [x] **C11 Classifier state is per-process.** Not rehydrated at startup; with multiple replicas a replica that did not sync keeps scanning dropped zones/prefixes. Fix: rebuild zones/prefixes from the DB at startup and refresh periodically.
- [x] **C12 nuclei/plugin verify hostname string only** and use their own network stack: an owned name whose CNAME/A points at a third party gets actively scanned. Fix: resolve and require every answer IP to be owned (or refuse), via the guard.
- [x] C13 (low; dispatcher-side suppression, batching, suppressed-finding resolution, worker timeouts done; the two-sources-claim case is covered by the reporters set) config-suppression race between reconcile and suppress; suppressed findings never accumulate misses; `scheduleWorker`/`housekeepingWorker` inherit River's 1-minute timeout; two sources claiming one asset flap; dispatcher resend not batched.

## API / auth / deployment

- [x] **A1 Open redirect after OIDC login** (`safeNext` accepts `/<TAB>/evil.com`); same gap in client `safeLoginUrl`.
- [x] **A2 OIDC writes from the SPA always 403** (client reads a `deckard_csrf` cookie the server never sets; token comes from `/me`).
- [x] **A3 SSE has no connection cap** (global + per-identity).
- [x] **A4 Audit actor from unverified email** (use only when `email_verified`).
- [x] **A5 /metrics unauthenticated; Helm networkPolicy off by default; compose binds all interfaces and defaults the DB password.**
- [x] A6 (hardening) logout POST-only; require https base_url for OIDC; warn on empty `allowed_groups`; min 32-byte static token; `__Host-` cookies; pin nuclei/compose image tags.

## Verified sound (no action)
Scope guard (rebinding/TOCTOU/redirects/resolver), authn on every route incl. SSE and openapi, constant-time token compare, AES-GCM session cookies + HKDF, OIDC state/nonce/PKCE, CSRF coverage, CSP/headers, no XSS sinks in the UI from scanned data, parameterised SQL, path traversal, container hardening, River uniqueness, `runScan` safety ordering, reconcile row-locking, baseline learning termination.

## Live validation on a real estate (71 zones, 732 DNS records)

A read-only capture of a real Cloudflare account was replayed through the real Cloudflare source and scanned
with the passive tier (no port scanning). Result: 3,140 checks, 0 errors, 1,323 assets, and a genuine dangling
CloudFront alias found. It also exposed four precision problems, all fixed and re-verified on the same data:

- [x] **L1 dns.takeover false positive** (CloudFront alias served a valid certificate over HTTPS): a valid cert for the host now suppresses; provider-default cert confirms.
- [x] **L2 tls.cert severity on vendor-hosted hosts** (`does not cover` on hosts that CNAME to a third party): downgraded to low with `served_by` evidence.
- [x] **L3 dns.hygiene severity ignored mail usage:** DMARC/SPF now medium only when MX exists.
- [x] **L4 http.headers duplicated http/https findings:** headers judged on https only; http judged only for missing redirect.
- [x] **L5 log noise:** external redirect refusals at DEBUG, URLs stripped of query strings.
- Before -> after: 1,090 -> 940 findings; high 8 -> 1; medium 62 -> 8; scope-refusal WARN lines 89 -> 15.

## Graph-guided review (round 2, 2026-10-04)

Review base: `e41f232378562539b8c19151d34110daf9ad8091`. Graph queries guided source inspection and focused regression tests.
Go interfaces and callbacks need manual tracing; a missing graph edge does not prove dead code or missing tests.

- [x] **R1 Scanner network policy did not contain subprocess traffic.** Nuclei now receives a fresh exact-address policy and isolated configuration. Request failures make scans incomplete. Exec plugins use an OS-enforced socket sandbox and guarded network channel.
- [x] **R2 Failed SARIF scans could reconcile findings.** Explicitly unsuccessful invocations now fail before ingestion posts any findings.
- [x] **R3 SSE replay could skip large backlogs.** Ascending ID pages and a fixed replay boundary preserve every event. The newest-first changes endpoint keeps its existing behavior.
- [x] **R4 Published intelligence could lose its scan fan-out.** A pre-publication PostgreSQL outbox preserves template and KEV deltas across crashes, partial insertion, restarts, and volume moves. Revision checks prevent premature template scans. One-shot scans drain local work before acknowledgment.
- [x] **R5 Old relationship reporters survived complete snapshots.** Source and check reporters now replace only their own registrations. Partial snapshots preserve edges, and queries exclude removed endpoints.
- [x] **R6 Findings survived when their check stopped applying.** Enabled checks retire those findings with `no_longer_applicable`. Disabled checks and scope refusals cannot use this path.
- [x] **R7 Capped collection reads hid findings in triage views.** Server-side queries provide complete counts, bounded pages, exact severity filters, group members, and asset summaries. Graph views disclose truncation. Debounced search cannot overwrite newer filters.
- [x] **R8 Scan retention erased scheduling watermarks.** Atomic `RecordScan` updates durable `scan_state`, independent of history pruning.

Additional regressions cover exactly-full Nuclei verification pages, global proxy configuration, unsafe/pipeline request clients, repeated KEV catalog additions, and failed observation reads.
Migration `00009` adds relationship reporters, `00010` adds scan state, and `00011` adds the scan-trigger outbox.

Validation passed `2,411` race-enabled Go tests with real PostgreSQL and no test-level skips, plus `225` UI tests, build, and lint.
Go vet, security lint, Helm lint/render variants, and scanner fixtures also passed. Govulncheck found no reachable or imported-package vulnerabilities.

Linux ARM64 plugin fixtures verify the actual sandbox and guarded channel. Local Nuclei fixtures exercise normal, raw, unsafe, and pipeline clients.

This review did not deploy Deckard or scan the user's estate. Network plugins must migrate to the [guarded channel](../../plugins.md#guarded-network-channel).

### Remaining operator work

Deploy a chosen release through the normal environment workflow. Let Deckard apply the three migrations before starting workers.
Migrate any custom network plugins, then verify source freshness, pending triggers, and expected findings in that environment.
These steps require environment-specific choices and were not performed during this repository review.
