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
| `scheduling.queue_workers` | `sync: 2, passive: 10, active: 4, intrusive: 1, default: 2, expand: 1, intel: 8, maintenance: 1` | Max concurrent jobs per queue (positive integers; unknown queue names are rejected). Per-host concurrency and rate limits still apply. The `intel` queue runs the checks that wait on slow remote lookups (see below); the other scan queues follow the tier. Everything shares one Postgres pool (`database.max_conns`), so size it above the busiest replica's total (the defaults add up to 29, but jobs mostly wait on the network, not the database) |
| `retention.scans` | `168h` | Scan history older than this is deleted by housekeeping. Due-computation uses a per-(asset, check) index, not the history, so this only bounds table size. Must be > 0 |
| `retention.relations` | `720h` | Relations touching an asset removed longer ago than this are deleted by housekeeping. Must be > 0 |

### Queues and slow checks

Scan jobs run in the queue of their tier (`passive`, `active`, `intrusive`),
with one exception: a check that spends its run waiting on rate-limited remote
services runs in the `intel` queue whatever its tier. Today these are
`web.history` (Wayback), `domain.expiry` (RDAP), `intel.internetdb`,
`cloud.bucket` (the object-storage provider) and `domain.lookalike` (up to 600
DNS queries behind one shared rate ceiling). A run of such a check can take
half a minute or more, and in the shared `passive` queue a few of them used to
hold most of its workers while the fast DNS checks (`dns.dangling`,
`dns.takeover`) waited behind them. The queue is chosen when the job is
inserted and stays with the job through retries and crash recovery. Raise
`intel` if `deckard_queue_depth{queue="intel"}` stays high; it never competes
with `passive` for workers, only for the database pool.

After an upgrade from a version without this queue, each instance moves the
still-pending (`available`, `scheduled`, `retryable`) scan jobs of these checks
from the old queue to `intel` when it starts, and again every 30 seconds while
older instances of a rolling update are still inserting into `passive`. Running
jobs are never touched.

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
  - { name: gcp, type: gcpdns, projects: [my-project-a] }          # Application Default Credentials
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

### Google Cloud DNS (`type: gcpdns`)

Discovers Cloud DNS managed zones and their record sets and produces the same
assets and relations as the Route 53 source (zones, hostnames in their zone,
`resolves_to` and `cname_to` relations, `record_types`), so every check works on
it unchanged. In addition the zone asset carries `dnssec` (`on`, `off` or
`transfer`, from the zone's `dnssecConfig.state`), every target of a weighted,
geo or primary/backup routing policy is discovered (not just the first), and
internal load balancers named by a policy are recorded as `cloud_resource`
assets. CNAME targets that are Google-hosted endpoints (Cloud Run, App Engine,
Cloud Storage, Cloud Functions, Firebase) get an `alias_target_type`.

```yaml
sources:
  - name: gcp
    type: gcpdns
    projects: [my-project-a, my-project-b]   # required: project ids to scan (projects are not discovered)
    include_private: false                   # private zones are skipped unless true
    zones: []                                # optional allow-list of zone names or DNS names; empty = all
```

- `projects` is required. Each entry is a project **id** (not the number or
  display name); a malformed id is rejected at startup.
- Private zones are skipped by default: their names are not visible from the
  internet. With `include_private: true` they are inventoried too; a private
  zone with the same DNS name as a public one is never merged into it.
  Peering zones serve no records and are always skipped.
- `zones` matches either the managed zone name (`prod-zone`) or its DNS name
  (`example.com`, case and trailing dot ignored). It only narrows the set:
  private zones still need `include_private`.

**Credentials** are Application Default Credentials only: Workload Identity on
GKE, a service-account key named by `GOOGLE_APPLICATION_CREDENTIALS`, or
`gcloud auth application-default login` locally. There is no key or token
setting in the config. Credentials are looked up when a sync runs, so a missing
identity shows up as a failed sync in the source's status, not as a failed start.

**IAM**: grant `roles/dns.reader` to the identity on each project listed. It
includes `dns.managedZones.list` and `dns.resourceRecordSets.list`, which is all
the source calls; nothing is ever written. The Cloud DNS API must be enabled in
each project.

**Workload Identity on GKE**: bind the Kubernetes ServiceAccount the chart
creates to a Google service account that has `roles/dns.reader`, and annotate
it through the chart:

```sh
gcloud iam service-accounts add-iam-policy-binding \
  deckard-dns@my-project-a.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-project-a.svc.id.goog[deckard/deckard]"
```

```yaml
# values.yaml
serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: deckard-dns@my-project-a.iam.gserviceaccount.com
config:
  sources:
    - { name: gcp, type: gcpdns, projects: [my-project-a, my-project-b] }
```

(The member is `PROJECT.svc.id.goog[NAMESPACE/SERVICEACCOUNT]`; adjust the
namespace and the ServiceAccount name to your release.)

**Partial discovery.** A project the identity cannot read (HTTP 403, or 404 for
a wrong id or a disabled API) or a zone whose record sets cannot be listed does
not fail the sync. The rest is still returned and the source reports

```
partial discovery, removals skipped: gcpdns project my-project-b: managed zones not listed (HTTP 403 ...; needs dns.managedZones.list, grant roles/dns.reader)
```

naming the project or zone and the missing permission. A partial sync updates
what it saw but never marks unseen assets removed, so a permission gap cannot
make assets vanish from the inventory. The sync fails outright (and also
removes nothing) when the credentials do not work, when listing zones fails for
a reason other than a permission or missing-project error, or when no listed
project could be read at all.

Requests are rate limited (5 per second), time-limited, size-limited and retried
with backoff on 429 and 5xx, honouring `Retry-After`. Tokens and URL query
strings never appear in logs, errors or warnings.

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
the DNS checks and the address lookup before every connection use them, and so
does the lookalike sweep of `domain.lookalike`; entries
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
| `interval` | the tier's (or asset group's) interval; `12h` for `domain.expiry`, `7d` for `domain.lookalike` | Replaces the tier interval for this check. May shorten or lengthen it. Must be a duration `> 0`. A check with its own default cadence (`domain.expiry`: registry data moves slowly; `domain.lookalike`: a sweep costs hundreds of DNS queries) uses it instead of the tier's; this key still overrides it. |
| `interval` | the tier's (or asset group's) interval; `12h` for `domain.expiry`, `24h` for `intel.internetdb` | Replaces the tier interval for this check. May shorten or lengthen it. Must be a duration `> 0`. A check with its own default cadence (`domain.expiry`, `intel.internetdb`: slow-moving third-party data) uses it instead of the tier's; this key still overrides it. |
| `interval` | the tier's (or asset group's) interval; `12h` for `domain.expiry` and `cloud.bucket`, `7d` for `web.history` | Replaces the tier interval for this check. May shorten or lengthen it. Must be a duration `> 0`. A check with its own default cadence (`domain.expiry`: registry data moves slowly; `web.history`: so does the archive) uses it instead of the tier's; this key still overrides it. |
| `on_new_asset` | `true` | Scan this check as soon as an asset is added, changed or revived. Can only switch the tier's `on_inventory_change` off for this check, never on. |

### Check-specific options

Keys under `checks.<name>` that individual checks read (unknown keys are
ignored):

| Check | Key | Default | Effect |
|---|---|---|---|
| `http.headers` | `min_severity` | `info` | Drop findings below this severity (`info`, `low`, `medium`, ...). Set `low` to silence the info-level noise such as a missing `Referrer-Policy`. Dropped findings are never stored; to keep them visible but not alerted on, use `notify.alertmanager.min_severity` instead. The security-header set is evaluated on `https://` URLs only; `http://` URLs are checked only for "does not redirect to HTTPS". |
| `http.headers` | `required_headers`, `hsts_min_age`, `timeout_seconds` | see check docs | Which header classes to require and the minimum HSTS max-age. |
| `dns.hygiene` | `expects_mail` | `false` | Force mail treatment of a zone. Without it, a zone with MX records gets medium for a missing DMARC/SPF record and a zone without MX (parked) gets low, with a null-sender recommendation (`v=spf1 -all`, `v=DMARC1; p=reject;`). |
| `domain.expiry` | `high_days`, `medium_days`, `low_days` | `14`, `30`, `60` | Days before expiry at which `expiring` is high, medium and low. Must satisfy `1 <= high_days <= medium_days <= low_days <= 3650`; invalid values fall back to the defaults and are noted in the observation. |
| `domain.expiry` | `lock_exempt_tlds` | `[]` | TLDs (for example `[de]`) whose registrars cannot set transfer or delete locks: `transfer-unlocked` and `no-delete-protection` are not raised for them. |
| `domain.lookalike` | `enabled` | `true` | `false` switches the check off (and resolves its findings). The check is DNS-only and does not depend on `intel`. |
| `domain.lookalike` | `zones` | every owned apex | Only these registrable domains are swept. Apexes not listed record `lookalike: not_selected` and their findings resolve. |
| `domain.lookalike` | `exclude` | `[]` | Names to ignore, for example known partners or defensive registrations: a name and everything under it is never queried or reported. Every owned zone is ignored automatically. |
| `domain.lookalike` | `tlds` | about 25 common suffixes (`com`, `net`, `org`, `io`, `co`, `app`, ...) | Suffixes tried by the TLD-swap technique. `[]` turns the technique off. Invalid names are ignored and noted. |
| `domain.lookalike` | `max_candidates_per_zone`, `max_findings_per_zone` | `600`, `50` | Cap on the names queried per apex per run (taken evenly across the techniques; the observation says how many were dropped) and on the findings reported (highest severity first; the observation says how many were cut). `1` to `5000` and `1` to `500`. |
| `domain.lookalike` | `min_label_length` | `5` | Brand labels shorter than this are not permuted at all: a 3-letter label yields mostly meaningless noise. `1` to `63`. |
| `domain.lookalike` | `rate_per_second` | `20` | Hard ceiling on DNS queries per second for the whole process, however many zones run at once. `(0, 1000]`. Read at startup. Invalid values fall back to the default and are noted. |
| `mail.policy` | `expects_mail` | `false` | Same meaning as for `dns.hygiene`: judge the zone as a mail zone even without MX records. MTA-STS and TLS-RPT absence is still raised only for zones with a real MX. |
| `mail.policy` | `check_mta_sts`, `check_tls_rpt` | `true`, `true` | `false` skips every MTA-STS (respectively TLS-RPT) finding and, for MTA-STS, the policy fetch. |
| `mail.policy` | `min_max_age` | `604800` | MTA-STS `max_age` in seconds below which `mta-sts-max-age-short` is raised (one week). |
| `mail.policy` | `timeout_seconds` | `10` | Timeout of the MTA-STS policy fetch. |
| `intel.internetdb` | `expected_ports` | `[]` | Ports that may be open although `net.ports` does not list them (outside its scan range, or reachable from some networks only). They never raise `unexpected-port`. |
| `intel.internetdb` | `max_cves` | `200` | At most this many CVE findings per IP (`1` to `2000`); a longer list is cut after sorting and the run is partial. |
| `dns.takeover` | `timeout_seconds` | `10` | Per-request timeout. Before reporting, the check handshakes with the owned hostname over HTTPS: a certificate valid for the host that is not the provider's default certificate suppresses the finding. |
| `web.history` | `max_findings` | `10` | Findings per host (`1`-`50`), highest severity first and newest capture first. When more paths match, the run is partial so nothing beyond the cap is resolved. |
| `web.history` | `max_results` | `3000` | Archive rows requested per host (`100`-`10000`). A full page means the history was cut off: what was seen is reported and the run is partial. |
| `web.history` | `min_severity` | `low` | Drop findings below this severity (`info` keeps the soft-404 downgrades of low-severity paths). |
| `web.history` | `ignore_paths` | `[]` | Path prefixes never reported, for paths that are public on purpose (for example `[/admin, /swagger-ui]`). |
| `web.history` | `max_age_days` | `0` | Ignore captures older than this many days. `0` means no limit. |
| `cloud.bucket` | `timeout_seconds` | `10` | Per-request timeout for the `GET /` of the owned hostname (https first, then http). |
| `cloud.bucket` | `sensitive_keywords` | `[]` | Extra case-insensitive substrings that make a listing critical, on top of `.env`, `backup`, `.sql`, `id_rsa`, `credentials`, `tfstate` and `.pem`. |

`tls.cert` reports hostname-mismatch, self-signed and untrusted-chain findings
at `low` (and `expired` at `high` instead of `critical`) when the host has an
outbound `cname_to` neighbour that is external, since the operator cannot fix
a third party's certificate; the evidence carries `served_by`.

`domain.expiry` runs on owned zones that are registrable domains (the label in
front of the ICANN public suffix: `example.com`, `example.co.uk`); subzones such
as `corp.example.com` share the apex's registration and are skipped. It asks
the registry's RDAP service (through [`intel`](#third-party-metadata-intel))
and raises `expired` (critical; also for the `redemption period` and
`pending delete` statuses), `expiring` (high/medium/low by the thresholds
above), `transfer-unlocked` (medium: neither `clientTransferProhibited` nor
`serverTransferProhibited`), `no-delete-protection` (info), and, against the
learned baseline, `drift/registrar` and `drift/nameservers` (high: a registrar
or delegation change nobody planned is how domains are hijacked; a mere
reordering of the nameservers is not a change). Evidence carries the expiry
date, days remaining, registrar, statuses and nameservers. A TLD without RDAP,
a domain the registry does not know, a lookup failure or `intel.enabled:
false` raise nothing: the observation says `rdap: unsupported`, `not_found`,
`unavailable` or `skipped` and the run is partial, so no finding resolves on
missing data.

`domain.lookalike` finds registered lookalikes of your registrable domains
(typosquats such as `exmple.com`, `examp1e.com`, `ex-ample.com`, `example.net`
and confusable Unicode as `xn--` names), a common phishing and brand-abuse
vector. It runs once per owned apex (`example.com`, not
`corp.example.com`), by default every 7 days. It is **DNS-only**: it generates
permutations of the brand label and asks your recursive resolvers whether each
name exists and what its NS, A, AAAA and MX answers are. It never connects to,
or fetches anything from, a lookalike. The techniques are omission,
repetition, transposition, QWERTY-neighbour replacement and insertion, vowel
swap, hyphen insertion, ASCII homoglyphs (`rn`/`m`, `vv`/`w`, `l`/`1`/`i`,
`o`/`0`), a capped set of confusable Unicode letters rendered as punycode,
splitting the label into a subdomain (`ex.ample.com`), single-bit flips that
stay in the hostname alphabet, and swapping the TLD. Names inside any owned zone
(the estate legitimately owns many variants of its own names, including your
other apexes) and names under `exclude` are never generated.

A candidate is registered when it has NS records, an A/AAAA record or a usable
MX (a null MX, `0 .`, does not count), or is an alias (CNAME). Each registered
lookalike is its own finding, `registered:<domain>`, so a new registration
opens a new finding and alerts and one that disappears resolves normally:
`medium` when it has MX (it can receive mail: business e-mail compromise,
phishing), `low` when it only resolves or only delegates (typically parked).
Evidence carries the technique, the A/AAAA/MX/NS answers and when it was first
seen. There is no escalation to `high` for a lookalike that already has a
certificate in Certificate Transparency: the only CT client deckard has belongs
to discovery expansion (it queries crt.sh outside the scope guard and `intel`),
and checks may reach the network only through those two, so no certificate data
is consulted.

SERVFAIL, timeouts and resolver errors are unknown, never "does not exist":
the run is partial, so nothing resolves, and the observation lists a sample
under `unknown_sample`. A run that exhausts its time budget (the engine's
`checks.domain.lookalike.timeout`, 30m by default; the check stops a tenth
earlier to store its result) is partial too and records `unchecked`. Partial
runs still raise and refresh findings. See
[operations.md](operations.md#lookalike-sweeps-domainlookalike) for the query
volume and the design.
`mail.policy` runs on owned zones that are registrable domains and covers what
`dns.hygiene` does not; it never repeats hygiene's findings (SPF and DMARC
presence, `+all`, `?all`, a missing `all`, more than ten SPF lookups, multiple
SPF records, `p=none`). A zone counts as a mail zone when it has MX records (or
`expects_mail` is set); MTA-STS and TLS-RPT protect inbound mail, so their
absence is raised only for zones with a real MX. Findings, none above medium:

| Key | Severity | Raised when |
|---|---|---|
| `mta-sts-missing` | low | the zone has MX records but no `_mta-sts` TXT record |
| `mta-sts-txt-invalid` | medium | more than one `v=STSv1` record, or no valid `id` |
| `mta-sts-policy-unavailable` | medium | the TXT record is published but `https://mta-sts.<zone>/.well-known/mta-sts.txt` answers 4xx |
| `mta-sts-policy-redirect` | medium | the policy URL redirects (RFC 8461 forbids following redirects, so senders ignore it) |
| `mta-sts-policy-invalid` | medium | the policy lacks `version: STSv1`, a valid `mode`, `max_age` or (unless `mode: none`) an `mx:` line |
| `mta-sts-mode-none`, `mta-sts-mode-testing` | low | the policy is switched off, or only tests and never makes a sender refuse delivery |
| `mta-sts-max-age-short` | low | `max_age` is below `min_max_age` |
| `mta-sts-mx-mismatch` | medium (`enforce`), low (`testing`) | a real MX host matches no `mx:` pattern (a `*.example.com` pattern matches exactly one label) |
| `tls-rpt-missing` | info; low when MTA-STS is published | no `_smtp._tls` TXT record |
| `tls-rpt-invalid` | low | more than one record, or no `mailto:`/`https:` `rua` |
| `dmarc-multiple` | medium | more than one DMARC record (receivers discard all of them) |
| `dmarc-pct`, `dmarc-sp-none` | low | `pct` below 100, or `sp=none`, on an enforcing (`quarantine`/`reject`) policy |
| `dmarc-no-rua` | info | no aggregate report address |
| `spf-softfail` | low; info when DMARC is enforcing | the SPF record ends in `~all` |
| `null-mx-missing` | info | the zone has no MX at all and no null MX (`example.com. IN MX 0 .`, RFC 7505) |

A zone with no MX is treated as parked and is not asked about its mail
policies; `dns.hygiene` already reports its missing null SPF and DMARC records
(`v=spf1 -all`, `v=DMARC1; p=reject;`). The policy file is fetched with the
scope-guarded HTTP client, at most 64 KiB. Anything the check could not
establish (MX not answered, a TXT lookup that failed, a policy fetch that
failed, timed out, was refused or answered 5xx/429) is noted in the observation
and makes the run partial, so no finding resolves on missing data.

`intel.internetdb` runs on owned `ip` assets that are public addresses
(private, loopback, link-local, CGNAT, documentation and other reserved ranges
are skipped) and asks Shodan's key-free
[InternetDB](https://internetdb.shodan.io) what internet scanners know about
each one, through [`intel`](#third-party-metadata-intel): one request per IP.
**The data is a snapshot that Shodan refreshes about weekly**, so it lags behind
changes: a port closed or a CVE patched days ago can still be listed. Findings:

| Key | Severity | Raised when |
|---|---|---|
| `cve:<id>` | medium, raised by exploit intelligence | InternetDB lists the CVE for the IP. The finding goes through the same KEV/EPSS enrichment as `cve.nuclei` findings (a CISA KEV listing raises it to `vulnintel.kev_floor`, critical by default, and tags it `kev`; an EPSS at or above `vulnintel.epss_high`, `0.7` by default, makes it high; see [Exploit intelligence](#exploit-intelligence-cisa-kev-and-first-epss)). Evidence: the CVE, CPEs, ports, hostnames and tags. InternetDB infers CVEs from banners and CPEs, so a match can be a **false positive**: confirm the running version, then patch or restrict the port, or mark it false positive. |
| `unexpected-port:<n>` | medium | scanners saw port `n` open and the latest `net.ports` observation of the same IP does not list it. Close it, add it to `checks.net.ports.ports` so it is scanned, or to `expected_ports`. |
| `tag:compromised`, `tag:malware`, `tag:c2`, `tag:botnet` | critical | InternetDB flags the IP with that tag. |

Other tags (`honeypot`, `cdn`, `self-signed`, ...) and the hostnames are
evidence only. A 404 means the scanners know nothing about the IP and is a
clean result. `unexpected-port` needs a `net.ports` observation of the IP: until
there is one (the active tier is off, or the IP has not been scanned yet) no
port finding is raised and the run is partial (`ports_baseline: missing`). The
observation records only the lookup state (`internetdb: ok` or `not_found`),
never the scanners' lists, so Shodan's refreshes do not raise baseline drift
findings.

For all checks that use `intel`: a lookup that fails, is rate limited, blocked
or unsupported, an unusable answer, `intel.enabled: false` and a missing intel
client never raise a finding: the observation says `skipped` or `unavailable`
and the run is partial.
`web.history` runs on owned hostnames (not IP addresses), once when a hostname
appears and then every `7d`. It asks the Wayback Machine's CDX API (through
[`intel`](#third-party-metadata-intel), service `wayback`) which paths of the
host the archive captured with HTTP 200 and matches them against a fixed
pattern table. It never requests the live host or the archived URL: a finding
says the path *was* publicly served, with the capture date in the evidence.
Confirm it is gone (the active `http.exposed` check probes the live host where
active scanning is allowed), rotate any credential the file could have held, and
ask the Internet Archive to exclude the capture if needed (info@archive.org).

| Class | Severity | Paths |
|---|---|---|
| secrets and VCS metadata | high | `/.env*`, `.git/`, `.svn/`, `.hg/`, `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`, `*.pem`, `*.key`, `.aws/credentials`, `*.tfstate`, `.npmrc`, `wp-config.php.*`, `config.php.bak` |
| database and archive dumps | high | `*.sql` (also `.sql.gz` and similar), `*.dump`, `*.bak`, `*.old`, and `*.zip`, `*.tar.gz`, `*.tgz`, `*.7z` named `backup`, `db`, `database`, `site`, `www` or `website` |
| admin and debug surfaces | medium | `/phpmyadmin`, `/adminer`, `/admin`, `/actuator/*`, `/server-status`, `/debug`, `/_profiler`, `/telescope`, `/horizon`, `/graphiql`, `/swagger*`, `/openapi.json`, `/api-docs` (web root only) |
| leftovers | low | `.DS_Store`, `/web.config` |

Matching is case-insensitive, on the path without its query string. Each path is
one finding with the key `path:<lower-cased path>`; subtree patterns (`.git/`,
`/actuator/*`, `/swagger*`, ...) report the directory, so one exposed
repository is one finding, not one per object. Evidence holds the archived
URLs without query strings (at most five), the newest capture time, the status
and the MIME type. A path that should be a file (a `.env`, a `.sql`) but was
archived only as `text/html` is probably a soft 404 or an application shell and
is reported one severity lower (so a soft-404 `.DS_Store` falls below the
default `min_severity`). An archive that returns nothing is a complete,
clean answer; a lookup that is rate limited, too large, unavailable, disabled
(`intel.enabled: false` or `intel.services.wayback.enabled: false`), a hostname
the archive cannot be asked about, an unusable answer, a full page of rows or a
match count above `max_findings` leaves the observation `wayback: skipped`,
`rate_limited`, `too_large`, `unavailable`, `not_found`, `unsupported` or `unusable` (or
`truncated`/`capped` on an otherwise good answer) and makes the run partial: no
finding resolves on missing data.

`cloud.bucket` runs on owned hostnames and every `12h`. When the CNAME chain
(resolved like `dns.takeover` does) ends at object storage (`*.s3.amazonaws.com`,
`*.s3-<region>.amazonaws.com`, `*.s3.<region>.amazonaws.com`, `s3-website*`,
`storage.googleapis.com`, `*.storage.googleapis.com`, `*.blob.core.windows.net`,
`*.web.core.windows.net`, `*.r2.dev`, `*.r2.cloudflarestorage.com`), it requests
`GET /` of the **owned hostname** through the scope-guarded HTTP client, https
first and then http. The provider's endpoint is only resolved by DNS, never
contacted; nothing is written, no key is requested, only the first page of a
listing is read and at most 20 key names are kept in the evidence (sensitive
names first, each truncated). The response decides:

| Response | Result |
|---|---|
| `ListBucketResult` (S3, GCS) or `EnumerationResults` (Azure), 2xx | `listable`: high, or critical when a key contains `.env`, `backup`, `.sql`, `id_rsa`, `credentials`, `tfstate`, `.pem` or a `sensitive_keywords` entry |
| `AccessDenied`, `AllAccessDisabled`, 403 and similar | private: no finding |
| `NoSuchBucket` | left to `dns.takeover` and `dns.dangling`: no finding |
| any other 2xx page | static website: `website: true` in the observation only |
| 5xx, 429, a redirect, or no answer on either scheme | inconclusive: the run is partial |

`cloud.bucket` asks no third-party service, so `intel.enabled` does not affect it.

Order of evaluation: the scope guard, then the tier's `enabled` (global, then
asset-group overrides), then the per-check values. A per-check override can
therefore never enable a disabled tier and never reach a non-owned asset.

An owned name that resolves to shared (CDN/SaaS), third-party or undeclared
private addresses is probed by the passive tier only: active and intrusive checks for it are
recorded as skipped, counted in `deckard_checks_skipped_total`, and never
resolve a finding (see [Skipped checks](operations.md#skipped-checks)).

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
Expansion only ever adds assets. crt.sh is often briefly unavailable: a
timeout, network error, 429 or 5xx (after the client's own two retries) is
treated as transient. The zone's expansion stays incomplete (nothing is ever
pruned because of it), whatever the DNS bruteforce found is still added, one
WARN per zone per hour is logged (DEBUG otherwise), and the job is snoozed
with backoff (5m, doubling to at most 1h or `interval`) instead of failing and
logging "Job errored; retrying" on every attempt. Any other failure (an
unparseable answer, a failed wildcard probe) is retried by the job queue as an
error. Everything else keeps running either way. It is skipped for a
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

## Third-party metadata (`intel`)

Some checks ask public metadata services about *your own* domains and IPs:
`domain.expiry` asks the registry's RDAP service when a zone apex expires and
who its registrar is; `intel.internetdb` asks Shodan's InternetDB what internet
scanners know about your public IPs. That is not a probe of your assets, so it does not go
who its registrar is; `web.history` asks the Wayback Machine which paths of a
hostname it has seen served. That is not a probe of your assets, so it does not go
through the scope guard; it goes through a separate, narrower client instead:

```yaml
intel:
  enabled: true                          # false = air-gapped: consumers record "skipped", never a finding
  user_agent_contact: security@example.com   # optional, appended to the User-Agent
  services:
    rdap:       { rate_per_second: 2, timeout: 20s, cache_ttl: 6h, negative_cache_ttl: 15m, max_bytes: 2097152 }
    internetdb: { enabled: true, rate_per_second: 1 }
    wayback:    { enabled: true, rate_per_second: 1 }
```

| Key | Default | Description |
|---|---|---|
| `intel.enabled` | `true` | `false` turns every lookup into "skipped": the consuming check records an observation (`rdap: skipped`, `internetdb: skipped`), marks the run partial and raises nothing. |
| `intel.enabled` | `true` | `false` turns every lookup into "skipped": the consuming check records an observation (`rdap: skipped`, `wayback: skipped`), marks the run partial and raises nothing. |
| `intel.user_agent_contact` | | An e-mail address or URL appended to `User-Agent: deckard/<version> (+https://github.com/chainseer-xyz/deckard; <contact>)`. Printable ASCII, at most 128 characters, no `(`, `)`, `;`, `\` or quotes. |
| `intel.services.<name>.enabled` | `true` | Switch one service off (`rdap`, `internetdb`, `wayback`). |
| `intel.services.<name>.rate_per_second` | rdap `2`, internetdb `1`, wayback `1` | Token-bucket rate per service (shared by the whole process). `(0, 50]`. |
| `intel.services.<name>.timeout` | `20s` | Per attempt, connection to last body byte. `1s` to `2m`. |
| `intel.services.<name>.cache_ttl` | `6h` | How long a successful answer is reused. `1m` to `168h`. |
| `intel.services.<name>.negative_cache_ttl` | `15m` | How long a 404 is reused. `1m` to `24h`. |
| `intel.services.<name>.max_bytes` | `2097152` (2 MiB) | Response cap, applied to the compressed and the decompressed body. `4096` to `33554432`. |

The block is closed: unknown keys fail validation. In particular there is no
`extra_allowed_hosts` and no way to add a host from configuration; the hosts
are fixed in code (listed in [operations.md](operations.md#network-egress)).

What the client enforces, whatever the configuration:

- every request names a service, and the URL's host must be on that service's
  allow-list. RDAP servers are allowed only if they appear in IANA's bootstrap
  file (`https://data.iana.org/rdap/dns.json`, fetched on first use, cached for
  24h, kept on a failed refresh; only `https` URLs on a hostname and port 443
  are accepted from it);
- `https` on port 443 only, TLS 1.2 or later with certificate verification, at
  most three redirects, each re-checked against the allow-list, and no proxy
  from `HTTPS_PROXY`/`HTTP_PROXY`;
- the client resolves the host itself and refuses it if any address is
  loopback, private, link-local, CGNAT, multicast, unspecified, reserved,
  documentation or a cloud metadata endpoint; it then connects to the address
  it checked, so a DNS answer cannot change between the check and the
  connection;
- 429 and 5xx answers and timeouts are retried twice with jittered backoff,
  honouring `Retry-After` up to 30s (a longer one ends the attempt);
  concurrent identical requests share one upstream call.

Metrics: `deckard_intel_requests_total{service,result}` (`ok`, `cached`,
`not_found`, `rate_limited`, `error`, `blocked`) and
`deckard_intel_request_duration_seconds{service}`. Each request is logged at
DEBUG (service, host, path, result; never the query string or the body). A
`blocked` request is logged at WARN: it means a bug or an upstream redirecting
somewhere it should not.

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

## Ingest (external scanners)

Account-level and secret scanners that run elsewhere (Prowler, Kubescape, trufflehog,
gitleaks, s3scanner, any SARIF producer) post their findings to `POST /api/v1/ingest`,
usually through `deckard ingest`. Findings are stored under check `ext.<tool>` and follow the
normal lifecycle; deckard never probes anything they name. The contract, the reconciliation
rules and CronJob examples are in [ingest.md](ingest.md).

```yaml
ingest:
  enabled: true            # default: any identity that may acknowledge or suppress may ingest
  rate_limit: 60/m         # per identity
  burst: 10
  max_concurrent: 4        # per API process; more get 429
  timeout: 2m
  max_scopes_per_tool: 50  # scope-label cap of deckard_ingest_last_success_timestamp
  tools:
    prowler:
      owned: true          # label the cloud_resource assets it creates owned (never probable)
      max_findings: 5000   # per request, at most 5000
      expected_interval: 24h   # DeckardIngestStale fires after twice this without a complete run
```

The `ingest:` source-name prefix and the `ext.` plugin-name prefix are reserved.

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

### External heartbeat (dead-man's switch)

Prometheus and Alertmanager usually run in the same cluster as deckard, so an
outage of the whole cluster (or of deckard) silences every alert, including
the ones about deckard itself. A heartbeat to a monitor **outside** the cluster
closes that gap: deckard requests a URL every `interval` while it is healthy,
and the external service alerts when the requests stop.

```yaml
notify:
  heartbeat:
    url: ""          # empty = disabled (default). Prefer DECKARD_NOTIFY__HEARTBEAT__URL from a Secret
    interval: 5m
    method: GET      # GET or POST
    timeout: 10s
```

| Key | Default | Description |
|---|---|---|
| `notify.heartbeat.url` | | `http(s)` URL to request. Empty disables the heartbeat. It is treated as a secret: logs and validation errors show only its scheme and host, never the path, query string or credentials |
| `notify.heartbeat.interval` | `5m` | Time between pings. Must be > 0 |
| `notify.heartbeat.method` | `GET` | `GET` or `POST` (empty body) |
| `notify.heartbeat.timeout` | `10s` | Bound for the health check and for the request |

deckard pings **only while healthy**: the database answers, and at least one
check run completed without error within the last two intervals (skipped and
failed runs do not count). A wedged scheduler or worker therefore stops the
pings, which is the point. Each beat is counted in
`deckard_heartbeat_total{result}` with `result` = `ok`, `error` (the ping
failed; logged at WARN) or `unhealthy` (withheld; logged at WARN with the
reason). Only the `scheduler` role pings; worker and API replicas never do.

Pick the external monitor's grace period above the interval plus your
shortest check cadence (the passive tier runs every 5m by default). If every
check you run has a long interval, raise `notify.heartbeat.interval` to at
least half of it, or the heartbeat will report a healthy but idle deckard as
unhealthy.

**healthchecks.io style** (a GET to a URL whose path is the token; set the
check's period to the interval and its grace to two intervals):

```yaml
notify:
  heartbeat: { interval: 5m, method: GET }
# DECKARD_NOTIFY__HEARTBEAT__URL=https://hc-ping.com/<uuid>
```

**PagerDuty style** (an integration heartbeat URL that expects a request every
period, here a POST; configure the expected interval in PagerDuty as 10m):

```yaml
notify:
  heartbeat: { interval: 5m, method: POST, timeout: 10s }
# DECKARD_NOTIFY__HEARTBEAT__URL=https://<your PagerDuty heartbeat ping URL>
```

The same works with Cronitor, Better Stack, Uptime Kuma push monitors or any
endpoint that alerts on silence. `deploy/examples/prometheus-rules.yml` also
has `DeckardHeartbeatFailing` for the in-cluster view (pings failing or
withheld for 30m).

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
