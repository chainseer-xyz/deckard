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
