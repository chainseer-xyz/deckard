# Operations

## Staying current

deckard is meant to run unattended for months. Four things go stale if nobody
looks: the nuclei template corpus, the reference data behind the DNS/CDN
checks, the vulnerability-intelligence feeds (KEV/EPSS), and the software
itself (deckard, its base image, the bundled nuclei engine). Each has an
automatic mechanism, a metric that tells you when it stops working, and a
runbook below.

The config keys referenced here (`nuclei.update.*`, `refdata.*`,
`vulnintel.*`) are the knobs of those updaters; the exact sub-keys and defaults
are in [configuration.md](configuration.md). Every one of them keeps its state
under `/var/lib/deckard` (see [Writable state](#writable-state)).

### 1. nuclei templates (`nuclei.update.*`)

The `cve.nuclei` check runs templates from a directory (by default the updater's
valid `current` release under `nuclei.update.dir`, falling back to the baked image snapshot;
`nuclei.templates_dir` overrides it
and turns the updater off). A background updater refreshes the community corpus **every 6 hours by
default**. When a refresh brings in new templates, deckard schedules a scan of
the affected assets with just those templates ("new-template scans"), so a
newly published CVE template is tried against your inventory within hours
rather than at the next full cadence.

Template and KEV scan deltas enter the PostgreSQL `scan_triggers` outbox before
the updater publishes new state. Failed fan-out retries from that outbox, including after restart or a volume move.
Acknowledgment follows complete queue insertion. One-shot scans acknowledge only after their queued scans finish.

Delivery is at least once. A crash before acknowledgment can repeat work; queue uniqueness and finding reconciliation tolerate retries.
KEV trigger identity includes the catalog revision, so a later revision can scan the same CVE again.

- Source: projectdiscovery/nuclei-templates, downloaded by the pinned nuclei
  binary's own installer (`nuclei -update-templates`; no template is executed).
  The hosts are nuclei's, not deckard's, so confirm them in your proxy logs when
  you restrict egress (see the egress table).
- A refresh that fails or looks wrong leaves the previous templates in place;
  scanning continues with what it has.
- A pod restart before the first refresh still scans with the baked official snapshot. Operator packs in
  `nuclei.extra_templates_dirs` are validated independently; a bad pack is skipped and logged.
- Staleness metric: `deckard_nuclei_templates_age_seconds`, compared with
  `deckard_nuclei_templates_max_age_warn_seconds` (`nuclei.update.max_age_warn`,
  default 72h) by the `DeckardNucleiTemplatesStale` rule. The `DeckardNucleiCheckStale` rule fires when a
  target-bearing process was attempted recently but no clean nuclei run has completed for six hours. It
  stays quiet when the deployment has no eligible targets; tune it if the active cadence is intentionally slower.

### 2. Reference data (`refdata.*`)

Subdomain-takeover fingerprints and provider IP ranges (CDN/cloud) are refreshed
from their upstreams on a schedule, validated, then swapped in atomically. A
**suspicious-shrink guard** rejects a refresh that drops far more entries than
is plausible (an upstream outage or format change must not silently disable a
check); the previous data stays active and the rejection is logged and counted.

- Staleness metric: `deckard_refdata_age_seconds{dataset}`; the
  `DeckardRefdataStale` rule fires after 3 days (3x the default `refdata.interval`
  of 24h).

### 3. KEV / EPSS enrichment (`vulnintel.*`)

Findings that reference a CVE are enriched from two public feeds: CISA's Known
Exploited Vulnerabilities catalogue (`www.cisa.gov`) and FIRST's EPSS scores
(`api.first.org`). A CVE in KEV is tagged `kev` and escalated; EPSS adds an
exploitation-probability score used for ordering. Feeds are cached locally, so
a transient outage only delays enrichment.

- A CVE newly added to KEV (never on the first load) triggers an immediate
  targeted scan of just that CVE's templates (`scan_cves`), so a template that
  the technology-based scan would not select is still tried right away. The
  finding it opens stays open: every later full scan re-runs that template
  against the asset, and it resolves only after the template has run and
  stopped matching `findings.resolve_after` times.
- Staleness metric: `deckard_vulnintel_age_seconds{feed}`; the
  `DeckardVulnintelFeedStale` rule fires after 18h (3x the default
  `vulnintel.interval` of 6h).

### Writable state

The container root filesystem is read-only. All updater state lives under
`/var/lib/deckard`, which is owned by the non-root user (uid 65532) in the image
and backed by a volume at run time (Helm: an `emptyDir`, or the PVC when
`persistence.enabled`, plus a dedicated volume at `nuclei.update.dir`; compose:
the `deckard-data` named volume):

| Config key | Default | Holds |
| --- | --- | --- |
| `nuclei.update.dir` | `/var/lib/deckard/nuclei-templates` | template releases, per-scan HOME |
| `refdata.dir` | `/var/lib/deckard/refdata` | last good fingerprints / ranges |
| `vulnintel.dir` | `/var/lib/deckard/vulnintel` | last good KEV catalog and EPSS cache |

The Helm render test asserts each default is under a mounted volume. If you
move one of these keys, mount a volume at the new path. Without persistence
everything is re-downloaded after a restart; with `vulnintel.dir` on an
`emptyDir` the first refresh after each restart is a silent first load, so a CVE
added to KEV while the pod was down is not reported as new.

### 4. The software itself

| Mechanism | Cadence | What it does |
| --- | --- | --- |
| Dependabot (`.github/dependabot.yml`) | weekly | PRs for Go modules, npm (`web/`), the Dockerfile base images and GitHub Actions (minor+patch grouped). Security updates are on regardless of schedule. |
| `govulncheck` workflow | every PR/push and daily | Fails builds on vulnerabilities deckard's code can reach; the daily run opens/updates one `security` issue and closes it when clean. `make vulncheck` runs it locally. |
| `nuclei-bump` workflow | weekly | Opens a PR when a newer nuclei release exists (builds both targets, Trivy-scans them), and a PR that drops the Dockerfile's transitive-dependency pins once Trivy is clean without them. |
| `scheduled-image` workflow | weekly | Rebuilds `slim` and `full` with `--no-cache --pull` (patched base image, Go toolchain) and Trivy-scans for fixed HIGH/CRITICAL; failures open/update a `security` issue and upload SARIF to code scanning. |
| Release (`v*` tag) | per release | Multi-arch images, SPDX SBOM, SLSA provenance, keyless cosign signature and a build-provenance attestation. |

Releases are tag-driven: a green weekly rebuild publishes nothing. To pick up a
base-image fix in production, cut a patch release and deploy it. Verify what you
deploy with the commands in [SECURITY.md](../SECURITY.md#verifying-releases).

## Network egress

deckard needs outbound HTTPS to these hosts for its own housekeeping (probe
traffic to your assets is separate and governed by the scope guard):

| Host | Used for | Needed when |
| --- | --- | --- |
| `api.github.com`, `github.com`, `codeload.github.com` | nuclei templates (the pinned nuclei binary's own installer; exact hosts are nuclei's) | `nuclei.update.enabled` |
| `raw.githubusercontent.com` | takeover fingerprints (can-i-take-over-xyz) | `refdata.*` enabled |
| `api.github.com` | GitHub's published ranges (`/meta`) | `refdata.*` enabled |
| `www.cloudflare.com` | Cloudflare IP ranges | `refdata.*` enabled |
| `ip-ranges.amazonaws.com` | AWS IP ranges | `refdata.*` enabled |
| `api.fastly.com` | Fastly IP ranges | `refdata.*` enabled |
| `www.cisa.gov` | KEV catalogue | `vulnintel.*` enabled |
| `api.first.org` | EPSS scores | `vulnintel.*` enabled |
| `crt.sh` | Certificate Transparency discovery | `expansion.ct_logs` is on |

`domain.lookalike` sends plain DNS to your configured resolvers and needs no
extra egress host ([details](#lookalike-sweeps-domainlookalike)).

Plus whatever your configured sources use (Cloudflare API, AWS APIs, Google
Cloud DNS at `dns.googleapis.com` with tokens from `oauth2.googleapis.com` or the
GKE metadata server, your Kubernetes API). If you restrict egress with a NetworkPolicy or proxy, allow
exactly the rows that match the features you left on.

### Metadata services (`intel.*`)

Checks that ask third-party services about your own domains and IPs use one
restricted client ([configuration](configuration.md#third-party-metadata-intel)).
It can reach exactly these hosts, over HTTPS on port 443, and nothing else;
there is no setting that adds one:

| Host | Service | Used by |
| --- | --- | --- |
| `data.iana.org` | `rdap`: the RDAP bootstrap file (`/rdap/dns.json`, once per 24h) | `domain.expiry` |
| the RDAP server of each TLD you own (from the bootstrap file, for example `rdap.verisign.com` for `.com` and `.net`, `rdap.publicinterestregistry.org` for `.org`) | `rdap`: one `GET /domain/<apex>` per owned zone apex, at most every 6h (cache) | `domain.expiry` |
| `internetdb.shodan.io` | `internetdb`: one `GET /<ip>` per owned public IP, at most every 6h (cache) | `intel.internetdb` |
| `web.archive.org` | `wayback` | reserved for upcoming checks; no traffic yet |
| `internetdb.shodan.io` | `internetdb` | reserved for upcoming checks; no traffic yet |
| `web.archive.org` | `wayback`: one CDX query per owned hostname (`/cdx/search/cdx?url=<host>/*`, at most every 6h per host, one request per second) | `web.history` |

To find the RDAP host for a TLD, look it up in
`https://data.iana.org/rdap/dns.json`. The client ignores `HTTPS_PROXY`, so
allow these hosts directly. It uses the system resolver (not
`scope.resolvers`) and refuses any host that resolves to a private, loopback,
link-local, CGNAT or metadata address. `deckard_intel_requests_total{result="blocked"}`
should stay at zero (example alert `DeckardIntelRequestBlocked` in
`deploy/examples/prometheus-rules.yml`).

## Running air-gapped

1. Disable the updaters: `nuclei.update.enabled: false`, `refdata.enabled: false`,
   `vulnintel.enabled: false` (check configuration.md for the exact keys), and
   turn discovery expansion off (no `crt.sh`). Set `intel.enabled: false` to stop
   RDAP, InternetDB and other metadata lookups: `domain.expiry` then records
   `rdap: skipped` and `intel.internetdb` records `internetdb: skipped`; neither
   raises anything. `mail.policy` fetches each mail zone's MTA-STS policy from
   `mta-sts.<zone>` through the scope-guarded client, so it needs no extra egress
   rule beyond your own zones.
   RDAP and other metadata lookups: `domain.expiry` then records `rdap: skipped`,
   `web.history` records `wayback: skipped`, and neither raises anything.
2. Provide the data yourself: mount a templates directory at
   `nuclei.templates_dir`, and mount reference-data / vulnintel snapshots at the
   configured paths. Refresh them on your own schedule (for example a CronJob in
   a connected zone that publishes to an internal volume or object store).
3. Pin and mirror images: copy the verified release images (`cosign verify`
   first) to your internal registry and deploy by digest. Use the `slim` image
   with `nuclei.enabled: false` if you do not run nuclei at all.
4. Expect the staleness metrics to grow; alert on your own thresholds (below)
   so a forgotten snapshot refresh is noticed.

## Lookalike sweeps (`domain.lookalike`)

`domain.lookalike` looks for domains that imitate yours (typosquats,
confusable characters, other TLDs) and are registered by someone else. Judge it
by what it sends:

- **DNS only.** It asks your recursive resolvers (`scope.resolvers`, otherwise
  the system's) whether a name exists and what its NS, A, AAAA and MX records
  are. It never opens an HTTP or TLS connection to a lookalike and never
  fetches a page from one: those are third parties' hosts, possibly hostile.
  It adds no egress host: the only new traffic is plain DNS to resolvers you
  already configured.
- **One narrow path.** The names are not yours, so they cannot go through the
  scope guard (which refuses them). They go through one client built in one
  place (`internal/app/lookup.go`, handed to checks as `Target.Lookup`) that
  only sends DNS queries to those resolvers.
- **A hard rate ceiling.** `checks.domain.lookalike.rate_per_second` (default
  20) caps queries per second for the whole process, however many zones run at
  once, with no burst.

**Query volume.** Per apex and run, about N + 3E queries, where N is the number
of candidates and E the number of candidate names that exist. A name that does
not exist costs one query (the NS query answers NXDOMAIN); one that exists
costs four (NS, A, AAAA, MX). N depends on the brand label (the part before the
registrable suffix) and is capped by `max_candidates_per_zone` (600), taken
evenly across the techniques:

| Brand label | Candidates (default TLD list) |
| --- | --- |
| 5 letters (`acme1`) | about 145 |
| 7 letters (`example`) | about 190 |
| 9 letters (`northwind`) | about 270 |
| 14 letters | about 410 |
| 20 letters or more | the cap, 600 |

So a typical apex costs 150 to 450 queries per run, which is under half a
minute at the default rate when nothing else is running, and an estate of 20
apexes costs about 6000 queries a week at the default 7-day interval, spread
over a few minutes. Labels shorter than `min_label_length` (5) are not swept.
Lower `rate_per_second` or `max_candidates_per_zone` to be gentler on the
resolvers; raise the rate only against resolvers you operate.

**Timing.** The engine gives a run `checks.domain.lookalike.timeout` (30m by
default, instead of the 2m of other checks). The check stops its sweep a tenth
earlier so that the result can be stored. If the budget ends first, the
observation records `budget_exhausted` and `unchecked`, and the run is partial:
absence proves nothing, so no finding resolves.

**Unknown is not absent.** A SERVFAIL, a timeout or a resolver error on any
candidate marks the run partial (`unknown` and `unknown_sample` in the
observation). Lame delegations and broken DNSSEC among hundreds of random names
make this common; findings are still raised and refreshed, but a lookalike that
went away resolves only after a complete run.

**Switching it off.** `checks.domain.lookalike.enabled: false` skips the check
everywhere (its findings resolve), `zones: [...]` limits it to some apexes, and
`exclude: [...]` ignores names (partners, defensive registrations). Air-gapped
deployments keep it off or give it internal resolvers; `intel.enabled: false`
does not affect it because it uses no metadata service. There is no Certificate
Transparency escalation to `high`; see
[configuration](configuration.md#check-specific-options).

## Skipped checks

The active and intrusive tiers only probe destinations whose IP addresses you
own. An owned name proxied by a CDN (a Cloudflare orange-cloud record), hosted
on a third-party platform, or seen through split-horizon DNS as a private
address you have not declared owned resolves to addresses deckard may not
probe, so
`cve.nuclei`, `http.exposed`, `tls.config` and the like have nothing they are
allowed to connect to. deckard notices this before it dials (one DNS lookup
per scan job, then the scope guard still vets every connection) and records
the check as **skipped** rather than failed:

- no `check failed` warning (a `check skipped` line at debug level), no
  increment of `deckard_scan_errors_total` or `deckard_checks_run_total`;
- `deckard_checks_skipped_total{check,tier,reason}` counts them, with
  `reason` = `shared_destination`, `external_destination` or
  `private_destination`;
- the scan history shows `skipped: unowned destination: <name> resolves to ...`;
- the check is retried at its normal interval (not `scheduling.error_retry`),
  so a name that moves onto owned addresses is picked up at the next run.

A skip made no observation. It never refreshes, misses, resolves or ages out a
finding and never removes a derived asset: an open finding from before the
name moved behind the CDN stays open until a real run proves it fixed. The
same holds when the guard refuses a connection during a run for any other
reason: that run is treated as partial. Passive checks (DNS, certificates,
headers by hostname) keep running against these names.

Answers that point at something wrong (loopback, link-local or metadata
addresses, an excluded IP, an unparseable answer) are never skipped: the check
runs, the guard refuses the connection and logs it at WARN, and the run is
treated as partial.

A steady skip count is normal for a proxied estate. To scan the origin
servers behind the CDN, declare their addresses owned (a static source or
`scope.include`).

### Scope refusals

Every operation the scope guard refuses is logged as `scope refusal` and
counted in `deckard_scope_refusals_total{tier,class,reason}` (`reason` is a
fixed phrase such as `tier requires an owned destination IP`). Most refusals
are expected by design (a third-party CNAME target, an SSO redirect, a shared
destination reached during a run), so each distinct target and reason is
logged at WARN at most once an hour and at DEBUG in between; the counter keeps
the full volume visible. Refusals that point at something genuinely wrong are
logged at WARN every time:

- an excluded name or address (`excluded=true` in the log line);
- a loopback, link-local (cloud metadata), multicast or reserved destination
  that is not owned, whether reached by IP or through an owned name's DNS
  answer;
- an unparseable resolver answer, a forbidden DNS query type or network.

Private destinations (RFC1918, ULA, CGNAT) that are not declared owned are
throttled like routine refusals: split-horizon DNS returns them all the time
when deckard runs inside a cluster or VPC (see `scope.resolvers`).

A sudden rise of `deckard_scope_refusals_total` for one `reason` after a DNS
or inventory change is worth a look; a flat rate is the guard doing its job.

## Alerting

Findings reach Alertmanager as one alert per open finding (see
`deploy/examples/alertmanager.yml`). Two additions are worth having.

**Route KEV findings to the urgent receiver.** KEV means exploitation in the
wild, regardless of nominal severity. The enrichment tags such findings `kev`;
the alert payload carries the label `kev="true"` for every finding tagged `kev`
(it is absent otherwise), alongside `severity`:

```yaml
route:
  routes:
    - matchers: [kev="true"]
      receiver: urgent
      repeat_interval: 4h
      continue: false   # first match wins; put this above the severity routes
```

**Watch deckard from outside the cluster.** In-cluster rules cannot fire when
the cluster itself is down. Configure `notify.heartbeat` (see
[configuration.md](configuration.md#external-heartbeat-dead-mans-switch)) so an
external service alerts when deckard stops vouching for itself: it pings only
while the database answers and checks keep completing.

**Alert on stale data and failing updaters.** `deploy/examples/prometheus-rules.yml`
ships ready-made rules (all metrics below exist in the binary):

| Rule | Fires when | Threshold |
| --- | --- | --- |
| `DeckardNucleiTemplatesStale` | `deckard_nuclei_templates_age_seconds` exceeds `deckard_nuclei_templates_max_age_warn_seconds` | `nuclei.update.max_age_warn` (default 72h), read from deckard itself |
| `DeckardNucleiTemplateUpdatesFailing` | 3+ failed template updates in 6h and none succeeded | tunable; the update interval is 6h |
| `DeckardNucleiTemplatesNeverLoaded` | update errors and no `deckard_nuclei_template_count` series | |
| `DeckardRefdataStale` | `deckard_refdata_age_seconds` > 3 days | 3x default `refdata.interval` (24h): tune if you changed it |
| `DeckardRefdataRejected` / `DeckardRefdataRefreshFailing` | repeated `rejected` / only `error` refresh results | tunable |
| `DeckardVulnintelFeedStale` | `deckard_vulnintel_age_seconds` > 18h | 3x default `vulnintel.interval` (6h): tune if you changed it |
| `DeckardVulnintelRefreshFailing` / `DeckardVulnintelNeverLoaded` | 3+ failed refreshes in 6h / empty KEV catalog | tunable |
| `DeckardKnownExploitedOpen` | `deckard_findings_kev_open` > 0 | informational |
| `DeckardHeartbeatFailing` | heartbeat attempts in the last 30m were all `error` or `unhealthy` | only exists when `notify.heartbeat.url` is set |
| `DeckardIngestStale` | no complete ingest for a `(tool, scope)` in twice `ingest.tools.<tool>.expected_interval` (`deckard_ingest_last_success_timestamp` vs `deckard_ingest_expected_interval_seconds`) | only tools that set an expected interval; silence retired scopes (see [ingest.md](ingest.md#metrics-and-alerts)) |
| `DeckardIngestRejected` | `deckard_ingest_requests_total` with result rejected, invalid, too_large or partial in the last hour | the response and the log say why |
| `DeckardJobsReclaimed` | `deckard_jobs_reclaimed_total` increased in the last hour (or a pod that started within the hour reclaimed before its first scrape) | an instance died while running jobs; see [Crashes, restarts and orphaned jobs](#crashes-restarts-and-orphaned-jobs) |

Air-gapped installs (`*.enabled: false`) never produce the refdata, vulnintel or
template-age series, so those rules stay silent; drop them or alert on your own
snapshot refresh.

<a id="metrics"></a>
**Metrics added by the updaters**

| Metric | Labels | Meaning |
| --- | --- | --- |
| `deckard_nuclei_templates_age_seconds` | | seconds since the templates were last confirmed current (absent without the updater) |
| `deckard_nuclei_templates_max_age_warn_seconds` | | `nuclei.update.max_age_warn` |
| `deckard_nuclei_template_count` | | templates in the active release |
| `deckard_nuclei_template_updates_total` | `result` = ok, unchanged, error | update attempts |
| `deckard_nuclei_new_templates_total` | | templates added by updates |
| `deckard_refdata_age_seconds` | `dataset` | seconds since the dataset was last verified fresh |
| `deckard_refdata_entries` | `dataset` | live dataset size |
| `deckard_refdata_refresh_total` | `dataset`, `result` = ok, unchanged, rejected, error | refresh attempts |
| `deckard_vulnintel_age_seconds` | `feed` = kev, epss | seconds since the last successful fetch (absent until the first) |
| `deckard_vulnintel_kev_entries` | | entries in the loaded KEV catalog |
| `deckard_vulnintel_refresh_total` | `feed`, `result` = ok, not_modified, error | refresh attempts |
| `deckard_findings_kev_open` | | open findings tagged `kev` (as of the last refresh job) |

**Scan and notification health metrics**

| Metric | Labels | Meaning |
| --- | --- | --- |
| `deckard_checks_skipped_total` | `check`, `tier`, `reason` = shared_destination, external_destination, private_destination | checks skipped before touching the network (see [Skipped checks](#skipped-checks)); neither runs nor errors |
| `deckard_scope_refusals_total` | `tier`, `class`, `reason` | every scope-guard refusal, including those logged at DEBUG (see [Scope refusals](#scope-refusals)) |
| `deckard_heartbeat_total` | `result` = ok, error, unhealthy | external heartbeat attempts; absent unless `notify.heartbeat.url` is set |
| `deckard_queue_depth` | `queue` = sync, passive, active, intrusive, default, expand, intel, maintenance | jobs waiting (available or retryable) per queue, reported as 0 for an empty queue; a backlog in `intel` (slow remote lookups) never delays `passive` (alert: `DeckardQueueBacklog`, per queue) |
| `deckard_jobs_reclaimed_total` | `kind` (job kind) | running jobs taken back from an instance that died; 0 for every kind from engine start |

**Ingest metrics** (see [ingest.md](ingest.md#metrics-and-alerts))

| Metric | Labels | Meaning |
| --- | --- | --- |
| `deckard_ingest_requests_total` | `tool`, `result` | `POST /api/v1/ingest` requests: ok, partial, replay, rejected, invalid, too_large, rate_limited, disabled, error |
| `deckard_ingest_findings` | `tool` | open findings posted by the tool |
| `deckard_ingest_last_success_timestamp` | `tool`, `scope` | last run applied as complete; overflow scopes report as `scope="other"` |
| `deckard_ingest_expected_interval_seconds` | `tool` | `ingest.tools.<tool>.expected_interval` (only when set) |

Only the heartbeat gets an example alert (`DeckardHeartbeatFailing`): skips
and expected refusals are steady by design on a proxied estate, so alerting on
their volume would be noise. Watch them on a dashboard instead.

## Crashes, restarts and orphaned jobs

A job is `running` in `river_job` from the moment an instance fetches it
until that instance records the result. If the process dies first (OOMKilled,
SIGKILL at the end of the pod's grace period, node loss) the row stays
`running`. Jobs are unique per arguments, so an orphaned `sync_source` or
`update_templates` row also blocks the next run of that job: the source stops
syncing (`DeckardSourceSyncStale`) until the row is cleared. deckard clears
such rows in three layers.

**Instance heartbeat and reclaim (about a minute).** Every instance with the
`worker` or `scheduler` role registers its River client id (`<host>_<start
time>`, what River records in `river_job.attempted_by`) in the
`deckard_instances` table when it starts, refreshes `seen_at` every 10s and
deletes its row on a clean stop. Each such instance runs one reclaim statement
at startup and every 30s: running jobs whose latest attempt belongs to a
registered instance not seen for 60s are moved back exactly as River's own
rescuer would (retryable, or discarded when out of attempts, or cancelled when
a cancel was requested; one error entry `Running job reclaimed from dead
instance ...` is appended and no attempt is used). Retried jobs are due at a
random point in the next 60s rather than all at once, so a replacement pod is
not hit by the dead pod's whole workload in the same second. Each batch logs
one WARN line with the count per kind and increments
`deckard_jobs_reclaimed_total{kind}` (alert: `DeckardJobsReclaimed`).

What is never touched: jobs of an instance with a fresh heartbeat, and jobs of
a client that never registered (an older deckard during a rolling update);
those fall to the next layer. Staleness is judged by the database clock, so
clock skew between nodes does not matter.

**River's rescue (backstop, 35 minutes).** River rescues any job running
longer than `RescueStuckJobsAfter`, set to the longest job timeout (30m, scans)
plus 5 minutes. It must exceed every job timeout, or River would re-run slow
but healthy jobs; it is derived from the workers' timeouts in code.

**Graceful shutdown (no orphans at all).** On SIGTERM deckard stops fetching,
gives in-flight jobs 30s to finish, then cancels the rest and waits up to
about 12s more for River to record them as retryable and for the instance to
deregister. The chart's `terminationGracePeriodSeconds` (default 60) must
cover that; the Kubernetes default of 30s does not. The binary refuses to
build if the drain plus cancel window no longer fits 60s, and a test ties that
to the chart default: raise both together. A pod killed before the cancel
completes falls back to the reclaim above.

To see who holds the running jobs (read-only):

```sql
SELECT j.id, j.kind, j.queue, j.attempt, j.max_attempts, j.attempted_at,
       j.attempted_by[array_upper(j.attempted_by, 1)] AS owner,
       now() - i.seen_at AS owner_silent_for     -- NULL: owner never registered
FROM river_job j
LEFT JOIN deckard_instances i
       ON i.client_id = j.attempted_by[array_upper(j.attempted_by, 1)]
WHERE j.state = 'running'
ORDER BY j.attempted_at;
```

`owner_silent_for` above a minute means the next reclaim (within 30s) takes
the job back; NULL means River's rescue does, 35 minutes after
`attempted_at`. Jobs reclaimed recently carry the reclaim message as their
last error:

```sql
SELECT id, kind, state, scheduled_at, errors[array_upper(errors, 1)] ->> 'error' AS last_error
FROM river_job
WHERE errors[array_upper(errors, 1)] ->> 'error' LIKE 'Running job reclaimed from dead instance%'
ORDER BY id DESC LIMIT 50;
```

Do not edit `river_job` by hand: a job that looks stuck is either about to be
reclaimed or still running on a live instance.

## Runbooks

### Scan state and finding retirement

Housekeeping prunes scan history, not scheduling watermarks. The `scan_state` table retains the latest attempt and settled run for each asset and check.
Long check intervals therefore survive short history retention and process restarts.

Complete source snapshots replace that source's reported relationships. Partial snapshots retain existing relationships.
Checks replace their own relationships without removing another reporter's registrations.

An enabled check that stops applying to a live, owned asset retires its findings with event reason `no_longer_applicable`.
Disabled checks, excluded targets and refused destinations cannot retire findings through this path.

### Scanner network boundaries

Nuclei receives an exact-address policy after acquiring its process slot.
Its dialer rejects every address outside the freshly verified destination set, even if DNS changes during execution.
Deckard supplies an isolated Nuclei configuration to prevent user-global proxies from bypassing that policy.

Nuclei request errors make the run incomplete, even when the binary exits successfully.
Matches remain usable, but absent findings cannot resolve from an incomplete run.

Exec plugins cannot open sockets directly. Use the [guarded plugin channel](plugins.md#guarded-network-channel) for network checks.
Network plugins written before this boundary need migration. Offline plugins keep the same protocol.
Every plugin tier requires owned destination addresses at dial time. A passive plugin retains its passive schedule and rate limit.

### Updater failing

Symptom: `DeckardNucleiTemplatesStale`, or update errors in the logs.

1. Check logs for the updater error: `kubectl logs deploy/deckard | grep -i update`.
2. Egress: from the pod (the `full` image has no shell: use a debug container),
   `curl -sI https://api.github.com` and `https://github.com`. A NetworkPolicy, proxy or GitHub rate limit
   (unauthenticated API calls are limited) are the usual causes.
3. Disk: `nuclei.update.dir` must be writable and have space (a release is
   about 80 MB; current + previous + one download need about 300 MB). A
   read-only root filesystem needs a writable volume there (the Helm chart and
   compose file provide one).
4. Meanwhile deckard keeps scanning with the last good templates; nothing is
   deleted. Restarting the pod forces an immediate attempt.

### Feed stale

Symptom: `DeckardRefdataStale` or `DeckardVulnintelFeedStale`.

1. Identify the upstream from the egress table (CISA/FIRST for vulnintel;
   Cloudflare/AWS/Fastly/GitHub for refdata) and check it is reachable and
   returning 200 with expected content.
2. Check the logs for a validation or parse error: an upstream format change
   is rejected the same way a shrink is, and needs a deckard fix or release.
3. Stale reference data degrades quality, not safety: takeover and CDN checks
   keep using the last good copy, and KEV/EPSS enrichment keeps its cache.

### Suspicious-shrink rejection

Symptom: a log line and counter increment saying a refresh was rejected
because it shrank implausibly; the age metric keeps growing.

1. Look at the upstream manually. A genuine large removal (a provider retired
   many ranges, a fingerprint list was reorganised) is rare; an empty or
   truncated response is the common cause and usually clears on the next run.
2. There is deliberately no runtime override of the guard. If it persists and
   the new data is right, stop deckard, delete the files in `refdata.dir` (the
   last good copy is the shrink baseline; the embedded data is used then) and
   restart, or ship a release with a regenerated embedded snapshot
   (`make refdata-snapshot ARGS="-force"`).
3. Never hand-edit the live data to "make the alert go away"; a rejected
   refresh is the safety net doing its job.

### A weekly image or govulncheck issue appeared

Label `security`. The issue links the failing run. Bump the affected module in
`go.mod` (minimal bump, `go mod tidy`, `make test`), or merge the open
`nuclei-bump` PR if the finding is in the bundled engine. The issue closes
itself on the next clean scheduled run.
