# Configuration reference

deckard reads a YAML file (`--config` or `DECKARD_CONFIG`) and environment variables.
Environment wins over the file. Variables use the `DECKARD_` prefix with `__` for
nesting: `DECKARD_DATABASE__URL` sets `database.url`, `DECKARD_LOG__LEVEL=debug` sets
`log.level`. Lists can be given comma-separated (`DECKARD_SERVER__ROLES=api,worker`).
Validate any config with `deckard config validate --config deckard.yaml`.

Secrets are never read from the file by default: reference an environment
variable by name (`token_env`, `password_env`, `client_secret_env`).

## Top level

| Key | Default | Description |
|---|---|---|
| `server.http_addr` | `:8080` | API and UI listener |
| `server.metrics_addr` | `:9090` | Prometheus `/metrics` listener. Binds all interfaces so in-cluster Prometheus can scrape; restrict it with a NetworkPolicy (Helm default), a firewall, or `127.0.0.1:9090` |
| `server.metrics_token_env` | | Env var holding a bearer token required on `/metrics` (constant-time compare). Empty leaves metrics open. Startup fails if the named variable is empty. Pair with ServiceMonitor `bearerTokenSecret` in Helm |
| `server.base_url` | | Public URL, used in alert links |
| `server.roles` | `api,scheduler,worker` | Which components this process runs |
| `log.level` / `log.format` | `info` / `json` | JSON logs to stdout |
| `database.url` | | Postgres URL (required) |
| `database.max_conns` | `10` | Connection pool size |
| `sync.interval` | `10m` | How often each source is re-synced |
| `scheduling.error_retry` | `10m` | A check is due when its last *successful* run is older than its interval. After a *failed* attempt it is retried no sooner than `min(interval, error_retry)`, so a broken target is not hammered every tick. Must be > 0 |
| `scheduling.queue_workers` | `sync: 2, passive: 10, active: 4, intrusive: 1, default: 2, expand: 1, maintenance: 1` | Max concurrent jobs per queue (positive integers; unknown queue names are rejected). Per-host concurrency and rate limits still apply. Everything shares one Postgres pool (`database.max_conns`), so size it above the busiest replica's total |
| `retention.scans` | `168h` | Scan history older than this is deleted by housekeeping. Due-computation uses a per-(asset, check) index, not the history, so this only bounds table size. Must be > 0 |
| `retention.relations` | `720h` | Relations touching an asset removed longer ago than this are deleted by housekeeping. Must be > 0 |

## nuclei and CVE templates

`cve.nuclei` runs [nuclei](https://github.com/projectdiscovery/nuclei) templates against owned web assets
(`url` assets and web `service` assets, active tier). The container image ships the binary but **no
templates**, and nuclei never updates itself (deckard starts it with `-duc`), so deckard keeps the
templates fresh itself. This matters most when a critical CVE lands: ProjectDiscovery usually publishes
a detection template within hours, and deckard fetches it and tests every owned web asset promptly.

```yaml
nuclei:
  enabled: true
  binary: nuclei
  scan_mode: tech          # tech | all
  severity_min: low        # info|low|medium|high|critical
  tags_exclude: [dos, fuzz]
  extra_tags: []
  templates_dir: ""        # default: <update.dir>/current while update.enabled
  update:
    enabled: true
    interval: 6h           # how often to look for a new release (jittered, plus once at start)
    dir: /var/lib/deckard/nuclei-templates
    timeout: 10m           # one update, download included
    run_new_templates: true
    max_age_warn: 72h
```

| Key | Default | Description |
|---|---|---|
| `nuclei.enabled` | `true` | Register `cve.nuclei`. The slim image has no nuclei binary: deckard logs a warning and skips the check |
| `nuclei.binary` | `nuclei` | Executable to run (the image pins v3.11.1) |
| `nuclei.templates_dir` | | Templates to run. Empty with `update.enabled` means the updater's current release. Setting it explicitly turns the updater off (deckard logs a warning): it would update a directory nothing reads |
| `nuclei.severity_min` | `low` | Lowest severity run and reported |
| `nuclei.tags_exclude` | `[dos, fuzz]` | Template tags never run. `dos` and (for `cve.nuclei`) `intrusive` are always excluded |
| `nuclei.extra_tags` | | Extra tags added to every tech-based scan |
| `nuclei.scan_mode` | `tech` | `tech`: select templates by the technologies `http.probe` detected (next.js, react, nuxt, vue, angular, express, spring, struts, laravel, django, rails, wordpress, drupal, joomla, confluence, jenkins, grafana, gitlab, citrix, fortinet, ...), with a generic `exposure,misconfig,cve` fallback. `all`: run **every** non-excluded template against every asset. That is thousands of templates per asset every `profiles.active.interval` (minutes of CPU and several thousand requests per asset), so raise the interval and lower `rate_limit` first |
| `nuclei.update.enabled` | `true` | Run the template updater (below) |
| `nuclei.update.interval` | `6h` | Time between update checks. Must be > 0 |
| `nuclei.update.dir` | `/var/lib/deckard/nuclei-templates` | Writable state directory (absolute path). Must be writable: the container root filesystem is read-only, so mount a volume here (the Helm chart and the compose file do) |
| `nuclei.update.timeout` | `10m` | Bound for one update. Must be > 0 |
| `nuclei.update.run_new_templates` | `true` | After an update that added templates, scan every eligible owned web asset with just those templates (see below) |
| `nuclei.update.max_age_warn` | `72h` | Template age that logs a warning and is exported as `deckard_nuclei_templates_max_age_warn_seconds` for the staleness alert. Must be > 0 |

Per-check options (`checks.cve.nuclei.*`): `rate_limit` (requests/s, default 50), `concurrency` (default 10),
`timeout` (per request, default 10s), `run_timeout` (per nuclei process, default 600s), `interactsh`
(default `false`: OAST templates do not run), `interval`, `on_new_asset`.
`deckard` never passes nuclei's `-code`, `-headless`, `-file` or `-dast` flags and restricts every run to the
`http,ssl,dns,tcp` template protocols (nuclei would otherwise run its `javascript` templates by default).

### How updates work

The updater runs the pinned nuclei binary's own installer
(`nuclei -update-templates -update-template-dir <staging>`; **no template is executed**) with a throwaway
`HOME`/`XDG_*` so a read-only root filesystem works, validates the download, and publishes it atomically:

```
<update.dir>/current   -> releases/<version>-<time>     what scans read
<update.dir>/previous  -> releases/<older release>      kept as fallback
<update.dir>/releases/ installed releases (older ones are pruned, with a 1h grace)
<update.dir>/run/      per-scan HOME/config directories
<update.dir>/state.json last update status
```

A release is rejected (and the last good one keeps serving) when it has fewer than 1000 templates or 100
http templates, more than 512 MiB or 200,000 files, special files, dangling symlinks, or symlinks leaving the
directory, or when more than 10% of its template files are unparseable. Failures are logged, counted in
`deckard_nuclei_template_updates_total{result="error"}`, and retried (River retries the job; every worker
also re-checks every few minutes while its templates are stale). One update is a ~15 MB download from
GitHub; it happens every `interval` even when nothing changed, because nuclei starts from an empty config
each time (that is what makes the check reliable).

The update runs as the `update_templates` job on the dedicated `maintenance` queue (one worker), scheduled on
the scheduler role, once shortly after start. Every worker also keeps its **own** templates fresh (the job
only runs on one worker), so separate worker replicas with their own volumes stay current.

### New templates are tested immediately

When an update adds templates (compared with the previous release by template id, and the release's
`.new-additions`), deckard queues `scan_new_templates` jobs: **every non-removed owned `url` or web
`service` asset** (and `hostname` assets with a live `http.probe` observation that no URL asset already
covers) whose active tier is enabled by its profile is scanned with exactly those templates, regardless of the
asset's technology tags (a brand-new CVE template must run even where no tech hint matches). Severity
minimum, `tags_exclude`, the profile rate limit and per-host concurrency still apply, and every target passes
the scope verifier before nuclei sees it. Targets are batched (50 per nuclei process); a crashed run is redone
by the job queue. The first install is not treated as "new" (the regular full scan covers it).

These are **partial runs**: they open and refresh findings (same `cve.nuclei` check and template-id key as
the regular scan, so there are no duplicates) but never count misses or resolve anything, because only some
templates ran. Only the regular full scans resolve a fixed finding. In scan history they appear as
`cve.nuclei.delta`.

**Open findings are re-verified by their own template.** Every regular full scan of an asset also re-runs the
template behind each of its unresolved `cve.nuclei` findings (open, acknowledged, suppressed and
false-positive alike, at most 200), in a second nuclei run with the same scope check, rate limits and network
protocol restriction, even when `scan_mode: tech` would not select it. A still-vulnerable host therefore
re-matches on every scan and stays open with no misses; once fixed, the template runs, no longer matches, and
the finding resolves after `findings.resolve_after` clean runs. A finding whose template was removed from the
active set simply accrues misses and resolves; a scan that could not locate every template (no template
directory, or more than 200 unresolved findings) counts no misses at all.

`deckard scan` (one-shot) runs the updater first, then the regular pass, then the new-template scan; pass
`--no-update` to skip the update (air-gapped hosts).

### CVE-targeted scans

`EnqueueCVEScan(ctx, []string{"CVE-2025-55182"})` queues `scan_cves` jobs: each worker looks up the templates
in its current set whose id or `classification.cve-id` matches and runs **only those** against every eligible
owned web asset (same scope verifier, protocol restriction and batching as above), as a partial run.

deckard calls it by itself when CISA adds a CVE to KEV (see
[Exploit intelligence](#exploit-intelligence-cisa-kev-and-first-epss)): a CVE whose template is already
installed, but which the technology-based scan would never select, is tested against your inventory within
one `vulnintel.interval` of CISA listing it, and the finding opens with the `kev` tag at `vulnintel.kev_floor`.
If nuclei is disabled or missing, the trigger is logged and dropped (no error, no retry); findings are still
enriched. The trigger runs under `deckard serve`; the one-shot `deckard scan` only refreshes the feeds.

### Air-gapped installs and operator-provided templates

Set `nuclei.update.enabled: false` and supply templates yourself:

```yaml
nuclei:
  update: { enabled: false }
  templates_dir: /mnt/nuclei-templates   # mounted read-only is fine
```

With the updater off deckard never contacts GitHub and no volume at `nuclei.update.dir` is needed (the Helm
chart skips it). nuclei still needs a writable `HOME`: the image sets `HOME=/tmp`, which the chart and
compose mount as a tmpfs. Keep your own template set current out of band; the staleness alert only exists
when the updater runs. Setting `nuclei.templates_dir` while the updater is on also turns the updater off.

### Observability

| Metric | Meaning |
|---|---|
| `deckard_nuclei_templates_age_seconds` | Seconds since the templates were last confirmed current. Absent without the updater |
| `deckard_nuclei_templates_max_age_warn_seconds` | `nuclei.update.max_age_warn` |
| `deckard_nuclei_template_count` | Templates in the active release |
| `deckard_nuclei_template_updates_total{result}` | Update attempts: `ok` (new release), `unchanged`, `error` |
| `deckard_nuclei_new_templates_total` | Templates added by updates |

`deploy/examples/prometheus-rules.yml` alerts on stale templates, repeated update failures and a first update
that never succeeded.

## Sources

Each entry needs a unique `name` and a `type`.

```yaml
sources:
  - { name: cf, type: cloudflare, token_env: CF_API_TOKEN }       # read-only token
  - { name: aws, type: route53, region: us-east-1, role_arn: "" }  # default AWS credential chain
  - { name: prod, type: kubernetes, kubeconfig: /etc/deckard/kc, contexts: [prod] }
  - { name: this, type: kubernetes, in_cluster: true }
  - { name: extra, type: static, hostnames: [a.example.com], ips: [203.0.113.5], cidrs: [203.0.113.0/28] }
```

Cloudflare token permissions (all read-only): Zone:Read, DNS:Read, Load
Balancers:Read, Account Settings:Read, Cloudflare Tunnel:Read.
Features your plan does not include (Spectrum, Load Balancing) are skipped with
a warning rather than failing the sync.

### AWS resource inventory (`type: aws`)

Inventories public EC2/EIP/ENI addresses, internet-facing ELBv2 load
balancers, their listeners and open-to-world security group rules, and
CloudFront distributions. Settings: `regions` (list; falls back to `region`,
then `us-east-1`), `profile`, `role_arn`, `endpoint` (tests/localstack).
Multiple accounts are multiple entries, one `role_arn` each. See
[aws-iam.md](aws-iam.md) for the minimum read-only policy.

```yaml
  - { name: prod-aws, type: aws, regions: [us-east-1, eu-west-1], role_arn: "arn:aws:iam::111122223333:role/deckard-readonly" }
```

A source that fails never causes its assets to be marked removed.

## Scope

```yaml
scope:
  include: ["*.example.com"]          # extra hostnames treated as yours
  exclude: ["legacy.example.com", "198.51.100.5", "198.51.100.0/24"]  # always wins
  max_cidr_hosts: 1024                # static CIDRs larger than this are rejected
  resolvers: ["1.1.1.1", "8.8.8.8"]   # optional: DNS servers every scan uses (IP or IP:port)
```

`scope.resolvers` sets the vantage point. By default deckard uses the system
resolvers, so inside a cluster or VPC with split-horizon DNS your internal names
resolve to private addresses (which the scope guard refuses to probe) and you see
the inside view. List public resolvers to see your names as an outside attacker
does: the same answers the internet gets, including CDN and proxy addresses. Both
the DNS checks and the address lookup before every connection use them; entries
are tried in rotation. Leave it empty to keep the system resolvers. Notifier and
source calls (for example an in-cluster Alertmanager URL) are not affected and
keep using the system resolver.

deckard only actively probes assets it can show are yours: names under zones from
your sources, IPs from your static lists, origins, load balancers and cluster
endpoints. Third-party CNAME targets (S3, Heroku, GitHub Pages, ...) are only
fingerprinted by requesting *your* hostname. They are never port-scanned.

## Profiles (tiers and cadence)

```yaml
profiles:
  passive:   { enabled: true,  interval: 5m,  on_inventory_change: true, rate_limit: "100/s" }
  active:    { enabled: true,  interval: 6h,  on_inventory_change: true, rate_limit: "50/s", per_host_concurrency: 2 }
  intrusive: { enabled: false, interval: 24h }
```

| Tier | What runs | Traffic |
|---|---|---|
| passive | DNS, certificates, HTTP headers, takeover fingerprints, origin exposure | about what a browser sends |
| active | port scans, service banners, TLS configuration, exposure paths, nuclei | scan-like, rate limited |
| intrusive | checks that may disturb services | off unless you enable it per group |

Per-group overrides:

```yaml
asset_groups:
  - name: homelab
    match: { zones: [home.example.com] }          # also: sources, hostnames, cidrs
    profiles:
      active: { interval: 1h, rate_limit: "200/s" }
      intrusive: { enabled: true }
```

### Per-check cadence

Every check can override its tier's cadence under `checks.<name>` (unknown
names are accepted, so plugins can be tuned too):

```yaml
checks:
  tls.cert:    { interval: 1h }                       # slower than the passive tier's 5m
  net.ports:   { interval: 24h, on_new_asset: false } # slower, and not on discovery
```

| Key | Default | Effect |
|---|---|---|
| `interval` | the tier's (or asset group's) interval | Replaces the tier interval for this check. May shorten or lengthen it. Must be a duration `> 0`. |
| `on_new_asset` | `true` | Scan this check as soon as an asset is added, changed or revived. Can only switch the tier's `on_inventory_change` off for this check, never on. |

### Check-specific options

Keys under `checks.<name>` that individual checks read (unknown keys are
ignored):

| Check | Key | Default | Effect |
|---|---|---|---|
| `http.headers` | `min_severity` | `info` | Drop findings below this severity (`info`, `low`, `medium`, ...). Set `low` to silence the info-level noise such as a missing `Referrer-Policy`. Dropped findings are never stored; to keep them visible but not alerted on, use `notify.alertmanager.min_severity` instead. The security-header set is evaluated on `https://` URLs only; `http://` URLs are checked only for "does not redirect to HTTPS". |
| `http.headers` | `required_headers`, `hsts_min_age`, `timeout_seconds` | see check docs | Which header classes to require and the minimum HSTS max-age. |
| `dns.hygiene` | `expects_mail` | `false` | Force mail treatment of a zone. Without it, a zone with MX records gets medium for a missing DMARC/SPF record and a zone without MX (parked) gets low, with a null-sender recommendation (`v=spf1 -all`, `v=DMARC1; p=reject;`). |
| `dns.takeover` | `timeout_seconds` | `10` | Per-request timeout. Before reporting, the check handshakes with the owned hostname over HTTPS: a certificate valid for the host that is not the provider's default certificate suppresses the finding. |

`tls.cert` reports hostname-mismatch, self-signed and untrusted-chain findings
at `low` (and `expired` at `high` instead of `critical`) when the host has an
outbound `cname_to` neighbour that is external, since the operator cannot fix
a third party's certificate; the evidence carries `served_by`.

Order of evaluation: the scope guard, then the tier's `enabled` (global, then
asset-group overrides), then the per-check values. A per-check override can
therefore never enable a disabled tier and never reach a non-owned asset.

`on_inventory_change` applies to the passive and active tiers (default `true`
for both): a new asset gets an immediate scan, still rate limited and
scope-guarded. The intrusive tier is **never** triggered by inventory change,
whatever the config says: its probes can disturb services, so they only run on
their own schedule or when an operator asks.

## Discovery expansion

```yaml
expansion:
  ct_logs: true          # query crt.sh for names under each owned zone
  dns_bruteforce: false  # resolve a wordlist of labels under each owned zone
  wordlist: ""           # path; empty = built-in list
  interval: 6h           # how often each owned zone is expanded (must be > 0)
```

Each `interval` the scheduler queues one `expand_zone` job per owned, live zone
asset (new zones are expanded right after the sync that finds them). A job asks
crt.sh once per zone (identifying itself with a User-Agent, honouring
`Retry-After` on 429), probes the zone for wildcard DNS once and drops
candidates that only match the wildcard, optionally bruteforces the wordlist
through the scope-guarded resolver (passive tier, owned class, at the passive
`rate_limit`), and hands the names to the inventory with origin
`expansion:ct` / `expansion:dns`. The inventory keeps only names that classify
as owned; new ones get their immediate scans through `on_inventory_change`.
Expansion only ever adds assets. If crt.sh is down or a lookup fails the job
is retried with backoff and everything else keeps running. It is skipped for a
zone whose passive tier is disabled.

## Reference data refresh

```yaml
refdata:
  enabled: true                       # false = never touch the network for reference data (air-gapped)
  interval: 24h                       # how often the sources are re-fetched (minimum 1h)
  dir: /var/lib/deckard/refdata       # last good copy; must be writable ("" = memory only)
  timeout: 30s                        # per HTTP request
  datasets:
    takeover_fingerprints: true       # dns.takeover provider database
    shared_ranges: true               # CDN/SaaS ranges classified "shared"
```

Two datasets are embedded in the binary and would otherwise change only with a
release. With `refdata.enabled` they refresh themselves; the embedded copy is
always the fallback.

| Dataset | Sources | Merge rule |
|---|---|---|
| `takeover_fingerprints` | [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) `fingerprints.json`: only `Vulnerable` / `Edge case` entries with a usable CNAME suffix and a plain-text body fingerprint or NXDOMAIN | The hand-curated entries (and their `default_cert` lists) win on provider-name conflicts; refreshed entries add new providers. Precision rules (valid-certificate suppression, unconfirmed edge case = medium) apply to every entry |
| `shared_ranges` | Cloudflare `ips-v4`/`ips-v6`, AWS `ip-ranges.json` (**only** `CLOUDFRONT`, `GLOBALACCELERATOR`, `S3`; never `EC2`/`AMAZON`, which hold customers' own addresses), Fastly `public-ip-list`, GitHub `meta` (`pages`) | Added to the embedded list. Classification order is unchanged: excluded > owned > shared > external, so an address you declare owned stays owned |

How a refresh stays safe:

- HTTPS only (a redirect to `http` is refused), no credentials, a 10 MiB cap per
  response, conditional requests (`ETag` / `Last-Modified`), retries with backoff.
- A download is applied only if it parses, meets a minimum size and has not shrunk
  by more than 50% against the data in use. Otherwise it is **rejected**, the
  previous data stays live and `deckard_refdata_refresh_total{result="rejected"}`
  increments. Shared ranges are validated strictly: prefixes shorter than /8
  (IPv4) or /16 (IPv6) and anything overlapping loopback, private, link-local,
  cloud-metadata or other special space are dropped.
- The last good copy is written atomically to `refdata.dir` and loaded at startup
  *before* the first network refresh. With neither, the embedded data is used.
- Applying is an atomic in-memory swap; no restart is needed.

Scheduling: every scanning process (scheduler or worker role) refreshes once at
startup and then every `interval` (with jitter); the scheduler also enqueues a
unique `refresh_refdata` job. `deckard scan` refreshes first; pass `--no-update`
to skip it. Metrics: `deckard_refdata_age_seconds{dataset}`,
`deckard_refdata_entries{dataset}`, `deckard_refdata_refresh_total{dataset,result}`
(`ok|unchanged|rejected|error`); alert rules are in
`deploy/examples/prometheus-rules.yml`.

**Air-gapped deployments:** set `refdata.enabled: false` (or
`DECKARD_REFDATA__ENABLED=false`). Nothing is fetched and the embedded copy is used,
refreshed by upgrading the image. To keep the data current without egress, mirror
the sources internally and run `make refdata-snapshot` in CI.

**Containers:** `refdata.dir` lives under `/var/lib/deckard`, which must be a
writable volume (Helm mounts an `emptyDir`, or the PVC when
`persistence.enabled`; the compose file mounts a named volume). Without one the
refresh still works but is re-downloaded after each restart.

**Embedded snapshots:** `make refdata-snapshot` (`go run ./cmd/refdata-snapshot`)
regenerates `internal/check/dns/takeover/fingerprints_community.yaml` and
`internal/scope/shared_cidrs_snapshot.txt` from the live sources with the same
converters. Flags: `-only takeover|shared|all`, `-takeover-out PATH`,
`-shared-out PATH`, `-timeout`, `-check` (write nothing, exit 1 if a file would
change) and `-force` (accept a snapshot that shrank by more than half). Pass them
via `make refdata-snapshot ARGS="-only shared"`. A scheduled CI job can run it and
open a pull request when the files change. The hand-curated
`fingerprints.yaml` and `shared_cidrs.txt` are never rewritten.

## Exploit intelligence (CISA KEV and FIRST EPSS)

```yaml
vulnintel:
  enabled: true                       # false = air-gapped: nothing is fetched or enriched
  interval: 6h                        # feed refresh period (jittered); also runs once at startup
  dir: /var/lib/deckard/vulnintel     # last-good feed copies, reloaded on startup
  timeout: 30s                        # per HTTP request
  kev_floor: critical                 # severity floor for a CVE listed in CISA KEV
  epss_high: 0.7                      # EPSS >= this raises a finding to at least high
  epss_medium: 0.3                    # EPSS >= this raises a finding to at least medium
```

When a finding references a CVE (a `cve-YYYY-N` tag, a `cve`/`cve-id`/`cves`
evidence key, or a check key that starts with `CVE-`), deckard ranks it by
real-world risk. Severity is only ever raised, never lowered, and the
fingerprint is unchanged, so a finding keeps its identity and history.

- **In KEV**: severity is floored at `kev_floor`, the finding gets the `kev`
  tag and the evidence `kev`, `kev_date_added`, `kev_ransomware` and
  `kev_required_action`, and the description gains "Known exploited (CISA KEV,
  added <date>)". The Alertmanager alert carries the label `kev="true"`.
- **EPSS**: the highest score among the finding's CVEs is stored as the
  evidence `epss` and `epss_percentile` (0 to 1) and raises severity to at least
  high (`>= epss_high`) or medium (`>= epss_medium`).

Enrichment is re-evaluated on every scan, so a CVE that enters KEV later
upgrades an already-open finding on that asset's next scan.

Feeds are fetched over HTTPS only from `www.cisa.gov` (the KEV JSON catalog,
using `ETag`/`If-Modified-Since`) and `api.first.org` (EPSS, at most 100 CVEs
per request, scores cached 24h, CVEs EPSS does not know are cached negatively).
Responses are size-capped, retried with backoff, and a KEV download that is
invalid, truncated or smaller than half the last good copy is rejected, keeping
the last good copy. Scans never wait on the network: lookups read an in-memory
cache and misses are fetched by the refresh job (`refresh_vulnintel`, run by
the scheduler role). If a feed is unreachable deckard keeps using the last good
copy, and with no data at all enrichment is a no-op. Only CVE ids from your
own findings are sent to api.first.org.

`vulnintel.dir` must be writable to persist the last-good copies (mount a
volume there; the Helm chart's `persistence` volume is mounted at
`/var/lib/deckard`). If it is not writable deckard logs a warning and keeps the
copies in memory only (a warning is logged on every failed refresh write), so after a restart the first refresh is again a silent
first load and a KEV addition made while deckard was down is not reported as new.

The refresh job detects CVEs newly added to KEV (never on the very first load,
so a fresh install does not fire a storm), fetches their EPSS scores and hands
them to the [CVE-targeted scan](#cve-targeted-scans). Metrics: `deckard_vulnintel_age_seconds{feed}`,
`deckard_vulnintel_kev_entries`, `deckard_vulnintel_refresh_total{feed,result}`
and `deckard_findings_kev_open` (updated by each refresh job). Example alerts
are in `deploy/examples/prometheus-rules.yml`, and a route that pages on
`kev="true"` is in `deploy/examples/alertmanager.yml`.

**Air-gapped or offline deployments**: set `vulnintel.enabled: false`. deckard
then makes no request to cisa.gov or api.first.org and never enriches.

## Findings and learning

```yaml
findings: { resolve_after: 2 }   # consecutive clean runs before a finding resolves
learning:
  stable_after: 3                # consistent observations before a baseline is trusted
  ignore_keys:                   # extra volatile observation keys that never count as drift
    "*": [build_id]              # every check
    http.headers: [date, etag]   # one check
suppressions:
  - { match: "check=http.headers asset=blog.example.com", reason: "accepted risk", until: 2026-12-31 }
```

## Alerting

deckard pushes findings to Alertmanager (`/api/v2/alerts`); route to Slack,
Discord, ntfy, email or PagerDuty there. See `deploy/examples/alertmanager.yml`.

```yaml
notify:
  alertmanager:
    urls: ["http://alertmanager:9093"]
    resend: 4m
    timeout: 10s
    min_severity: info   # info|low|medium|high|critical
```

| Key | Default | Description |
|---|---|---|
| `notify.alertmanager.urls` | | Alertmanager base URLs (deckard posts to `/api/v2/alerts`). Credentials in the URL are redacted from logs |
| `notify.alertmanager.resend` | `4m` | How often every open finding is re-asserted |
| `notify.alertmanager.timeout` | `10s` | Per-request timeout |
| `notify.alertmanager.min_severity` | `info` | Lowest severity sent to Alertmanager. Open findings below it are not sent, and neither are their resolution notices (a notice is sent exactly when the finding's severity is at or above the floor, so nothing that was never sent gets "resolved"). Everything below the floor is still stored, shown in the UI and API, and counted in `deckard_findings_open`. The default sends everything |

`min_severity` only silences notification. It differs from the per-check
`checks.http.headers.min_severity`, which drops the findings entirely, so they
never reach the store, the UI or the metrics. Use the check option to stop
recording noise you never want to see, and this one to keep low-severity
findings visible in deckard without routing them to Slack. A finding whose
severity is later raised above the floor (for example by KEV enrichment) is
sent from the next notification cycle on.

## Auth

`auth.mode` is `token` (default), `oidc` or `none` (only behind a trusted proxy).
Token mode reads the bearer token from the env var named by `auth.token_env`;
it must be at least 32 bytes (`openssl rand -hex 32`) or startup fails.

OIDC (`auth.oidc.*`):

- `issuer`, `client_id`, `client_secret_env`, `redirect_url` (defaults to `server.base_url` + `/auth/callback`).
- `allowed_groups`: only members may sign in. **Empty admits every account at the issuer with write access**;
  deckard logs a loud warning at startup.
- `groups_claim` (default `groups`).
- `allow_insecure_base_url` (default `false`): `server.base_url` (or `redirect_url`) must be `https://` so cookies
  are `Secure` (and `__Host-`/`__Secure-` prefixed) and HSTS is on. Config validation fails otherwise; set this
  only for local development.
- Only a verified (`email_verified: true`) email names the audit actor; otherwise the actor is `sub (iss <issuer>)`.
- Logout is `POST /auth/logout` with the `X-CSRF-Token` from `GET /api/v1/me`.

The event stream (`GET /api/v1/events`) admits at most 100 concurrent streams (10 per identity; in token mode all
callers share one identity); extras get `429` with `Retry-After`.

## Extending

- **nuclei templates**: deckard keeps the community set fresh automatically (see
  [nuclei and CVE templates](#nuclei-and-cve-templates)). For your own, mount a directory and set
  `nuclei.templates_dir` (this turns the updater off), or run an air-gapped install.
- **exec plugins**: see `docs/plugins.md`.
