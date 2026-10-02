# deckard

**Continuous external attack-surface monitoring you can self-host.**

Point deckard at your Cloudflare, AWS and Kubernetes accounts and it keeps
answering four questions:

1. **What do I own?** Every zone, DNS record, load balancer, public IP and
   cluster endpoint, from the sources you connect.
2. **What is reachable from the internet?** Open ports, services, TLS, web
   endpoints, discovered and re-verified on a schedule.
3. **What changed?** New subdomain, new open port, new certificate, a DNS record
   that now points nowhere.
4. **Did that make me less secure?** Dangling DNS and subdomain takeover,
   exposed origins behind a CDN, weak TLS, exposed admin paths, known CVEs.

It is one container plus Postgres. Alerts go through **Prometheus Alertmanager**
(so Slack, Discord, ntfy, email and PagerDuty all work), metrics are exposed for
Prometheus and Grafana, and there is a web UI for triage.

> **Use it only on infrastructure you own or are authorised to test.**
> See [Responsible use](#responsible-use).

## Quick start

```sh
cp .env.example .env            # set DECKARD_ADMIN_TOKEN, POSTGRES_PASSWORD and CF_API_TOKEN
$EDITOR deploy/compose/deckard.yaml
docker compose up -d            # UI on http://127.0.0.1:8080, metrics on :9090
```

Images: `ghcr.io/chainseer-xyz/deckard` (includes the nuclei engine for `cve.nuclei`) and
`ghcr.io/chainseer-xyz/deckard:latest-slim` (13 MB, no nuclei; set `nuclei.enabled: false`).
Both run as non-root on a distroless base. nuclei is built from a pinned tag in
the Dockerfile, so its dependencies are patched with the rest of the image.

Or run the image directly:

```sh
docker run --rm \
  -e DECKARD_DATABASE__URL=postgres://user:pass@db:5432/deckard \
  -e CF_API_TOKEN=... -e DECKARD_ADMIN_TOKEN=... \
  -v ./deckard.yaml:/etc/deckard/deckard.yaml:ro \
  ghcr.io/chainseer-xyz/deckard:latest serve --config /etc/deckard/deckard.yaml
```

Minimal `deckard.yaml`:

```yaml
sources:
  - { name: cf, type: cloudflare, token_env: CF_API_TOKEN }   # read-only token
notify:
  alertmanager: { urls: ["http://alertmanager:9093"] }
auth: { mode: token, token_env: DECKARD_ADMIN_TOKEN }
```

The Cloudflare token needs only read permissions: Zone:Read, DNS:Read, Load
Balancers:Read, Account Settings:Read, Cloudflare Tunnel:Read.

Kubernetes (Helm, with an optional CloudNativePG database):

```sh
helm install deckard deploy/helm/deckard \
  --set database.cnpg.enabled=true \
  --set-json 'config.sources=[{"name":"cf","type":"cloudflare","token_env":"CF_API_TOKEN"}]' \
  --set 'extraEnvFrom[0].secretRef.name=deckard-secrets'
```

## How it works

```
Cloudflare ┐
Route 53   │            ┌──────────┐    ┌───────────┐    ┌──────────────┐
AWS        ├─ sources ─▶│ inventory │───▶│ scheduler │───▶│ tiered checks │
Kubernetes │            │  (graph)  │    │ + cadence │    └──────┬───────┘
Static     ┘            └─────┬─────┘    └───────────┘           │
CT logs / DNS expansion ──────┘                                    ▼
                                     Postgres ◀── findings (dedup, lifecycle, baselines)
                                         │                         │
                                  API + web UI              Alertmanager ─▶ Slack, Discord, ntfy…
                                         │
                                  Prometheus /metrics
```

- **Sources** discover assets and relationships (hostname → IP → service →
  cloud resource). A source that fails or only partly succeeds never causes
  assets to be marked removed.
- **Checks** run in three **tiers**: `passive` (about the traffic a browser
  sends), `active` (port and service scanning, rate-limited) and `intrusive`
  (off unless you enable it for a group). Each tier has its own cadence, and new
  assets are inspected immediately.
- **Findings** are deduplicated, have a lifecycle (open → resolved, with
  acknowledge, suppress and false-positive), and resolve automatically when the
  issue stops reproducing. Learned baselines turn "port 8080 appeared" into a
  drift finding.
- **Alerts** carry lineage ("api.example.com → Cloudflare → origin 203.0.113.7 →
  :8080") and previous/current state.

### What it checks

| Tier | Check | Finds |
|---|---|---|
| passive | `dns.dangling` | CNAME chains ending in NXDOMAIN, dangling NS delegations |
| passive | `dns.takeover` | provider takeover fingerprints (S3, GitHub Pages, Heroku, Azure, …) |
| passive | `dns.hygiene` | SPF/DMARC/CAA/DNSSEC gaps, wildcard records, open AXFR |
| passive | `tls.cert` | expiry, hostname mismatch, weak keys, self-signed |
| passive | `http.probe`, `http.headers` | liveness, tech fingerprint, missing security headers |
| passive | `origin.exposed`, `origin.correlation` | CDN origin reachable directly; origin IP published by an unproxied record |
| active | `net.ports`, `net.services` | unexpected open ports, unauthenticated databases/caches |
| active | `tls.config` | TLS 1.0/1.1, weak ciphers |
| active | `http.exposed` | `.git`, `.env`, actuator, backups, directory listings |
| active | `cve.nuclei` | known CVEs and misconfigurations via [nuclei](https://github.com/projectdiscovery/nuclei) templates, kept fresh automatically: new CVE templates are fetched every few hours and run against every owned web asset right away (see [configuration](docs/configuration.md#nuclei-and-cve-templates)); findings that reference a CVE are ranked by CISA KEV / FIRST EPSS, and a CVE newly added to KEV triggers an immediate targeted scan ([exploit intelligence](docs/configuration.md#exploit-intelligence-cisa-kev-and-first-epss)) |

Add your own with **nuclei templates** (no code) or **exec plugins** in any
language ([docs/plugins.md](docs/plugins.md)).

## Responsible use

deckard sends network traffic to the assets it inventories. It is built so that
it cannot be pointed at things you do not own:

- Every probe goes through a **scope guard**. Only hostnames under zones from
  your sources (or `scope.include`) and IPs you own or explicitly list are ever
  actively probed. `scope.exclude` always wins.
- Third-party CNAME targets (S3, Heroku, GitHub Pages, …) are only
  *fingerprinted* by requesting **your** hostname. They are never port-scanned.
- Each dial re-checks the resolved IP (defence against DNS rebinding), refuses
  loopback, link-local and cloud-metadata ranges, and sources can never register
  them as owned.
- `intrusive` checks are off by default and never triggered automatically.

You are still responsible for having authorisation to test everything in
scope, and for your cloud provider's and CDN's acceptable-use policies.

## Metrics

Prometheus metrics (default `:9090/metrics`) expose posture, not per-finding
labels, so cardinality stays bounded: `deckard_assets`, `deckard_findings_open`,
`deckard_scan_duration_seconds`, `deckard_scan_errors_total`,
`deckard_source_last_success_timestamp`, `deckard_queue_depth`,
`deckard_inventory_changes_total`, plus the freshness and exploit-intelligence series
(`deckard_nuclei_templates_age_seconds`, `deckard_nuclei_template_updates_total`,
`deckard_refdata_age_seconds`, `deckard_vulnintel_age_seconds`,
`deckard_findings_kev_open`, ...; full list in [docs/operations.md](docs/operations.md#metrics)). A Grafana dashboard ships in the Helm chart,
and `deploy/examples/` has an Alertmanager config (Slack, Discord, ntfy) and
alert rules for deckard's own health.

## Configuration

Everything is YAML plus `DECKARD_`-prefixed environment variables (`__` for
nesting, env wins). See the full reference in
[docs/configuration.md](docs/configuration.md); validate with
`deckard config validate --config deckard.yaml`. Per-tier cadence, per-check
intervals, asset-group overrides, suppressions and baselines are all
configurable.

- **Staying current**: template/reference-data/KEV updaters, signed images,
  egress, air-gapped use and alerting: [docs/operations.md](docs/operations.md).

## Commands

```
deckard serve             run API, scheduler and workers (roles via server.roles)
deckard migrate           apply database migrations
deckard sync              one inventory sync
deckard scan              sync, scan everything due, notify, print a summary
deckard findings          print current findings (--min-severity, --status, --format table|json)
deckard config validate   check a config file
```

Run several replicas by splitting roles: API pods plus worker pods against the
same Postgres (see the Helm `worker.enabled` option).

## Development

```sh
make test         # go test -race ./...  (Postgres tests use Docker via testcontainers)
make build        # static binary in bin/
make web          # build the UI (Node 22)
deploy/helm/tests/render_test.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md). The design lives in
[docs/superpowers/specs](docs/superpowers/specs).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
