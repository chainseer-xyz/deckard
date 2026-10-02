# deckard — Continuous External Attack-Surface Monitor

**Status:** Approved (2026-10-02) · **Owner:** @quaekr

## 1. Purpose

deckard discovers every externally reachable asset an operator owns — from
Cloudflare, Route53, Kubernetes, and static lists — and continuously probes
it the way an outside attacker would: dangling DNS / subdomain takeover,
unexpectedly open ports, origins bypassing the CDN, TLS problems, exposed
panels, known CVEs, misconfigurations. It learns a baseline per asset and
alerts on drift and new findings through Prometheus Alertmanager.

Success criteria:

1. Point it at a Cloudflare token and within one sync interval every zone,
   record, LB pool origin, and tunnel is in the inventory.
2. A newly created dangling CNAME produces an Alertmanager alert within
   `passive.interval` (default 5m) of the next inventory sync.
3. Fixing a finding resolves its alert automatically.
4. Nothing outside the operator's scope is ever actively probed.
5. Runs as one container (`deckard serve`) against Postgres; Helm chart and
   docker-compose provided.

Non-goals (v1): editing sources/profiles in the UI (config is GitOps/YAML),
native Slack/Discord senders (Alertmanager routes those), exploitation
beyond detection.

## 2. Scope Guard (safety invariant)

Every probe goes through `scope.Guard`. An asset is classified:

| Class | Meaning | Allowed tiers |
|---|---|---|
| `owned` | Hostname under an owned zone, IP from an owned origin/LB pool/unproxied record/K8s LB/static entry | passive, active, intrusive (if enabled) |
| `shared` | IP belonging to shared edge/SaaS infra (Cloudflare, CloudFront, Fastly, Akamai, GitHub Pages, Heroku, Netlify, Vercel, S3, Azure Front Door, etc. — embedded CIDR list, refreshable) | none by IP; HTTP checks only *by owned hostname* |
| `external` | CNAME/target outside owned zones (e.g. `foo.s3.amazonaws.com`) | passive fingerprinting only, performed by resolving/requesting the **owned** hostname |
| `excluded` | Matched by `scope.exclude` | none |

Rules: port scans and nuclei only ever target `owned` IPs or `owned`
hostnames. Discovered hostnames (CT logs, cert SANs, redirects) enter
inventory only if they fall under an owned zone or `scope.include`.
`scope.exclude` always wins. The guard is unit-tested as a table and is the
only path to a network-touching check.

## 3. Architecture

Single Go binary, modular monolith, Postgres for state **and** job queue
(River). `deckard serve --roles=api,scheduler,worker` (default all).

```
 Sources ──sync──▶ Inventory (graph + diff) ──events──▶ Scheduler ──jobs──▶ Workers
 (cf/r53/k8s/static)        │                             (tiers/cadence)     │ checks
                            ▼                                                 ▼
                         Postgres ◀──────── Findings reconciler ◀──── observations
                            │                      │
                       API + UI (OIDC)        Notifier ──▶ Alertmanager ──▶ Slack/Discord/ntfy/...
                            │
                        /metrics (Prometheus)
```

### Packages

| Package | Responsibility |
|---|---|
| `cmd/deckard` | CLI: `serve`, `migrate`, `config validate`, `sync --once`, `scan --once`, `version` |
| `internal/config` | YAML + env (`DECKARD_` prefix, `__` nesting) via koanf, defaults, validation |
| `internal/model` | Domain types: Asset, Relation, Observation, Finding, Severity, Tier |
| `internal/scope` | Guard, shared-infra CIDR DB, zone ownership |
| `internal/source` | `Source` interface + registry; `cloudflare`, `route53`, `kubernetes`, `static` |
| `internal/inventory` | Upsert assets/relations, diff (added/removed/changed), expansion (CT, SANs) |
| `internal/check` | `Check` interface + registry, tiers; subpackages per check family |
| `internal/plugin` | exec-plugin protocol (JSON stdin/stdout) |
| `internal/nuclei` | runs bundled `nuclei` binary, JSONL parsing, tech→tag selection |
| `internal/finding` | Fingerprinting, lifecycle reconciler, suppressions |
| `internal/notify` | `Notifier` interface; `alertmanager` implementation |
| `internal/store` | `Store` interface; `postgres` (pgx v5, goose migrations embedded) |
| `internal/engine` | River workers, scheduler, cadence, rate limiting, leader election |
| `internal/api` | chi REST API, OIDC/token auth, embedded UI |
| `internal/metrics` | Prometheus collectors |
| `web/` | React + Vite + TS + Tailwind UI, built into `internal/api/ui/dist` |
| `deploy/helm/deckard` | Helm chart (CNPG optional) |

## 4. Domain Model

- **Asset** `{id, kind, key, source, scope_class, attrs jsonb, first_seen, last_seen, removed_at}`
  - kinds: `zone`, `hostname`, `ip`, `service` (ip:port/proto), `url`, `certificate`, `cloud_resource`
  - `key` is canonical and unique per kind (lowercased FQDN, normalized IP, `ip:port/tcp`).
- **Relation** `{from_id, to_id, type}` — `resolves_to`, `cname_to`, `alias_to`, `proxied_by`, `origin_of`, `serves`, `exposes`, `has_cert`, `in_zone`.
- **Observation** — raw check output `{asset_id, check, data jsonb, observed_at}`; latest kept per (asset, check) + baseline.
- **Baseline** — learned per-asset state (open ports set, tech stack, cert fingerprint, headers, status code). Drift between baseline and observation generates `drift` findings; baselines auto-promote after `learning.stable_after` consecutive consistent observations.
- **Finding** `{id, fingerprint, check, asset_id, severity, title, description, evidence jsonb, remediation, tags, status, first_seen, last_seen, resolved_at, suppressed_until, suppression_reason}`
  - `fingerprint = sha256(check | asset.key | finding_key)`; dedup key.
  - status: `open → resolved` (not seen for `findings.resolve_after` consecutive runs of that check), `open → acknowledged`, `* → suppressed`, `* → false_positive`; resolved findings reopen if seen again (`reopened_count++`).
- Severity: `info, low, medium, high, critical`.

## 5. Sources

```go
type Source interface {
    Name() string                      // instance name from config
    Type() string                      // cloudflare|route53|kubernetes|static
    Discover(ctx context.Context) (*Discovery, error)
}
type Discovery struct { Zones []Zone; Assets []model.AssetInput; Relations []model.RelationInput }
```

- **cloudflare**: token (API token, read-only: Zone:Read, DNS:Read, Load Balancers:Read, Account settings read, Cloudflare Tunnel read). Zones, DNS records (proxied flag → `proxied_by` cloudflare), LB pools/origins, Spectrum apps, tunnels. Plain REST client with pagination & retry; base URL overridable for tests.
- **route53**: aws-sdk-go-v2 default chain or static creds/role ARN; hosted zones, record sets, alias targets (ELB/CloudFront/S3 classified via scope).
- **kubernetes**: one or more kubeconfig contexts or in-cluster; Services type LoadBalancer (ingress IPs/hostnames, ports), NodePort on nodes with external IPs, Ingress hosts/TLS, Gateway API HTTPRoute hostnames (if CRDs present).
- **static**: hostnames, IPs, CIDRs (expanded up to `max_cidr_hosts`, default /22), URLs.

Sync: each source on `sync.interval` (default 10m) as a River job; inventory diff emits `asset_added|removed|changed` events (in-DB) which trigger immediate passive scans of new/changed assets. A source failing does **not** mark its assets removed (removal only on successful sync).

### Expansion (learning discovery)
- Certificate SANs from TLS checks under owned zones → new hostnames.
- CT log search (crt.sh, configurable/disable-able) for owned zones.
- HTTP redirects/links to owned-zone hosts.
- DNS brute of common labels (passive-safe wordlist, opt-in `expansion.dns_bruteforce`).
- Wildcard detection per zone so brute/CT results aren't polluted.

## 6. Checks

```go
type Check interface {
    Name() string
    Tier() model.Tier                 // passive|active|intrusive
    Applies(a *model.Asset) bool      // asset kind / attrs filter
    Run(ctx context.Context, t Target) (*Result, error)
}
type Result struct { Observations []model.ObservationInput; Findings []model.FindingInput; Discovered []model.AssetInput; Relations []model.RelationInput }
```

`Target` bundles the asset, its graph neighbourhood, a scope-guarded
dialer/HTTP client/resolver, and per-host rate limiter. Checks never create
their own network clients.

Built-in (v1):

| Check | Tier | Applies | Detects |
|---|---|---|---|
| `dns.dangling` | passive | hostname | CNAME → NXDOMAIN, A → unallocated cloud IP pattern, NS delegation lame/dangling |
| `dns.takeover` | passive | hostname w/ external CNAME | fingerprint DB (can-i-take-over-xyz style, embedded YAML) |
| `dns.hygiene` | passive | zone | missing/weak SPF, DMARC p=none/missing, DNSSEC absent, wildcard records, open AXFR |
| `tls.cert` | passive | hostname, service(tls) | expiry (warn/crit days), hostname mismatch, self-signed, weak key/sig, SANs → expansion |
| `tls.config` | active | service(tls) | TLS1.0/1.1 enabled, weak ciphers |
| `http.probe` | passive | hostname, url | liveness, status, title, tech fingerprint, redirect chain (httpx lib) |
| `http.headers` | passive | url | missing HSTS/CSP/X-CTO/X-Frame, server banner leak, info disclosure |
| `http.exposed` | active | url | exposed `.git`/`.env`/backup files, directory listing, admin panels (safe nuclei `exposure`/`misconfiguration` tags) |
| `net.ports` | active | ip (owned) | TCP connect scan via naabu, service map → `service` assets |
| `net.services` | active | service | banner/version fingerprint |
| `origin.exposed` | passive | ip (owned origin behind proxy) | origin reachable directly, not firewalled to CDN ranges |
| `cve.nuclei` | active | url, service | nuclei templates matched to detected tech; severity from template |
| `cloud.bucket` | passive | hostname/external | open S3/GCS/Azure bucket on owned-named resources |
| `drift.*` | passive | any | new open port, changed tech, new cert, changed headers vs. baseline |

Extensibility: (a) **nuclei templates**: operator mounts a dir, selected by
tags/tech; (b) **exec plugins**: `plugins` entries; deckard sends
`{assets:[...], config:{}}` JSON on stdin, reads `{observations, findings,
discovered}` JSON on stdout; tier and applies-filter declared in config;
timeout enforced; plugin receives only in-scope targets.

Tiers and cadence: each tier has `enabled`, `interval`, and rate controls;
per-asset-group overrides. Passive also runs on inventory-change events.
Global and per-host rate limits are enforced by the engine, not by checks.

## 7. Findings → Alertmanager

```go
type Notifier interface { Notify(ctx context.Context, active []model.Finding, resolved []model.Finding) error }
```

`alertmanager` posts to `/api/v2/alerts`. Each open finding becomes one alert:
labels `{alertname, deckard_check, severity, asset, zone, source, fingerprint}`;
annotations `{summary, description, evidence, remediation, first_seen}`;
`startsAt=first_seen`. Open findings are re-pushed every `notify.resend`
(shorter than Alertmanager `resolve_timeout`). On resolution deckard sends
`endsAt=now`. Suppressed, acknowledged and false-positive findings are not
pushed. The repo ships an example `alertmanager.yml` with Slack, Discord and
ntfy receivers routed on `severity`. The interface leaves room for direct
senders later.

## 8. Config (YAML + env)

`DECKARD_` env prefix, `__` nesting, env wins. `deckard config validate` checks
the schema. Sketch:

```yaml
server: { http_addr: ":8080", metrics_addr: ":9090", base_url: "https://deckard.example.com" }
log: { level: info, format: json }
database: { url: "postgres://...", max_conns: 10 }   # or DECKARD_DATABASE__URL
sync: { interval: 10m }
sources:
  - { name: prod-cf, type: cloudflare, token_env: CF_API_TOKEN }
  - { name: aws, type: route53, region: us-east-1 }
  - { name: cluster, type: kubernetes, kubeconfig: /etc/deckard/kubeconfig, contexts: [prod] }
  - { name: extra, type: static, hostnames: [foo.example.com], cidrs: [203.0.113.0/24] }
scope:
  include: ["*.example.com"]
  exclude: ["legacy.example.com", "198.51.100.5"]
  max_cidr_hosts: 1024
profiles:
  passive:   { enabled: true,  interval: 5m,  on_inventory_change: true }
  active:    { enabled: true,  interval: 6h,  rate_limit: "50/s", per_host_concurrency: 2 }
  intrusive: { enabled: false, interval: 24h }
expansion: { ct_logs: true, dns_bruteforce: false, wordlist: "" }
learning: { stable_after: 3 }
checks:
  tls.cert: { warn_days: 21, crit_days: 7 }
  net.ports: { ports: "top-1000", exclude_ports: [] }
nuclei: { enabled: true, templates_dir: /etc/deckard/nuclei, severity_min: low, tags_exclude: [dos] }
plugins:
  - { name: my-check, exec: ["/plugins/check.py"], tier: active, applies: {kind: url}, timeout: 60s }
findings: { resolve_after: 2 }
notify:
  alertmanager: { urls: ["http://alertmanager:9093"], resend: 4m }
asset_groups:
  - { name: homelab, match: { zones: [home.example.com] }, profiles: { active: {interval: 1h}, intrusive: {enabled: true} } }
suppressions:
  - { match: "check=http.headers asset=blog.example.com", reason: "accepted", until: 2026-12-31 }
auth:
  mode: oidc    # oidc|token|none
  oidc: { issuer: "...", client_id: "...", client_secret_env: OIDC_SECRET, allowed_groups: [sec] }
  token_env: DECKARD_ADMIN_TOKEN
```

12-factor: all config via env/file, no baked secrets, stateless process
(state in Postgres), logs to stdout as JSON (slog), graceful shutdown,
`/healthz` and `/readyz`.

## 9. API + UI

chi REST, OpenAPI documented. Read: `/api/assets`, `/api/assets/{id}` (+graph),
`/api/findings` (filters: severity/status/check/zone/source), `/api/findings/{id}`,
`/api/scans`, `/api/sources`, `/api/stats`, `/api/changes?since=`. Write
(authenticated): acknowledge, suppress (reason + expiry), false-positive,
rescan-now, trigger-sync. SSE `/api/events` for live updates. Auth: OIDC
(Authorization Code + PKCE), static bearer token, or none (behind a trusted
proxy).

UI (React + Vite + TS + Tailwind, `go:embed`): Dashboard (posture tiles,
severity trend, recent changes), Inventory (searchable table + graph map:
hostname→ip→service), Findings (filterable, evidence, lifecycle, actions),
Asset detail (relations, observations, baseline, findings, rescan), Sources
and scans status. UI-created suppressions are stored in the DB and labelled
distinctly from YAML-sourced ones.

## 10. Metrics

`deckard_assets{kind,source,scope}`, `deckard_findings_open{severity,check}`,
`deckard_scan_duration_seconds{check,tier}`, `deckard_scan_errors_total{check}`,
`deckard_source_sync_duration_seconds{source}`,
`deckard_source_last_success_timestamp{source}`,
`deckard_checks_run_total{check,tier}`, `deckard_queue_depth{queue}`,
`deckard_inventory_changes_total{type}`, build_info. Grafana dashboard JSON in repo.

## 11. Deployment

- **Image**: multi-stage distroless (static Go binary + embedded UI); bundles
  `nuclei` and a versioned template snapshot; non-root; healthcheck.
- **docker-compose.yml**: deckard + postgres + optional alertmanager.
- **Helm chart** `deploy/helm/deckard`: Deployment (configurable roles/replicas),
  Service, ServiceMonitor, ConfigMap, Secret refs, optional CNPG `Cluster`
  (`postgres.cnpg.enabled`), PVC for nuclei templates, Ingress,
  PodSecurityContext (no CPU limits, per platform rule), ServiceAccount and RBAC
  for the in-cluster k8s source, NetworkPolicy template.
- **GitOps**: values documented for ArgoCD.

## 12. Testing

- **Unit** (TDD, table-driven): scope.Guard matrix, config load/validate,
  inventory diff, finding fingerprint/lifecycle/dedup, each check's
  parser/classifier (fixtures, no live network), baseline drift, alertmanager
  payload builder, exec-plugin protocol, each Source parser against recorded
  API JSON fixtures.
- **Integration**: Postgres via testcontainers-go (store, River, migrations);
  Source clients against httptest servers replaying sanitized fixtures
  (Cloudflare fixtures captured from the live `cf` CLI); check engine against
  local stub targets; API handlers via httptest; Alertmanager via a mock receiver.
- **E2E (tagged)**: compose up, seed a static source at a controlled local
  target, assert a finding appears via the API and a mock Alertmanager
  receives it.
- **Safety test**: assert no check ever dials an out-of-scope target (invariant
  test with a recording dialer).
- CI: `golangci-lint`, `go test -race ./...`, `gosec`, `trivy` image scan,
  web `vitest` + typecheck. Coverage gate on core packages (scope, finding,
  inventory, config).

## 13. Build Order

1. Scaffold: module, config, model, logging, store + Postgres + migrations,
   metrics skeleton, `serve` wiring, CI, Dockerfile.
2. Sources + inventory + diff + scope guard (Cloudflare first, then Route53,
   Kubernetes, static) with fixture tests; `sync --once`.
3. Engine: River queue, scheduler, cadence, rate limiting, roles.
4. Passive checks (dns.*, tls.cert, http.probe/headers, origin.exposed) +
   baseline/learning; finding lifecycle.
5. Alertmanager notifier; example config.
6. Active checks (net.ports/services, tls.config, http.exposed, cve.nuclei) +
   nuclei integration + exec plugins + expansion.
7. API + OIDC + metrics complete.
8. Web UI.
9. Helm chart + CNPG + compose + Grafana dashboard + docs.
10. Hardening: scope invariant tests, trivy/gosec, coverage, README/CONTRIBUTING.

Each phase: tests first, green, reviewed (self + subagent/peer CLI), committed.
