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
`current` release under `nuclei.update.dir`; `nuclei.templates_dir` overrides it
and turns the updater off). A background updater refreshes the community corpus **every 6 hours by
default**. When a refresh brings in new templates, deckard schedules a scan of
the affected assets with just those templates ("new-template scans"), so a
newly published CVE template is tried against your inventory within hours
rather than at the next full cadence.

- Source: projectdiscovery/nuclei-templates, downloaded by the pinned nuclei
  binary's own installer (`nuclei -update-templates`; no template is executed).
  The hosts are nuclei's, not deckard's, so confirm them in your proxy logs when
  you restrict egress (see the egress table).
- A refresh that fails or looks wrong leaves the previous templates in place;
  scanning continues with what it has.
- Staleness metric: `deckard_nuclei_templates_age_seconds`, compared with
  `deckard_nuclei_templates_max_age_warn_seconds` (`nuclei.update.max_age_warn`,
  default 72h) by the `DeckardNucleiTemplatesStale` rule.

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

Plus whatever your configured sources use (Cloudflare API, AWS APIs, your
Kubernetes API). If you restrict egress with a NetworkPolicy or proxy, allow
exactly the rows that match the features you left on.

## Running air-gapped

1. Disable the updaters: `nuclei.update.enabled: false`, `refdata.enabled: false`,
   `vulnintel.enabled: false` (check configuration.md for the exact keys), and
   turn discovery expansion off (no `crt.sh`).
2. Provide the data yourself: mount a templates directory at
   `nuclei.templates_dir`, and mount reference-data / vulnintel snapshots at the
   configured paths. Refresh them on your own schedule (for example a CronJob in
   a connected zone that publishes to an internal volume or object store).
3. Pin and mirror images: copy the verified release images (`cosign verify`
   first) to your internal registry and deploy by digest. Use the `slim` image
   with `nuclei.enabled: false` if you do not run nuclei at all.
4. Expect the staleness metrics to grow; alert on your own thresholds (below)
   so a forgotten snapshot refresh is noticed.

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

Only the heartbeat gets an example alert (`DeckardHeartbeatFailing`): skips
and expected refusals are steady by design on a proxied estate, so alerting on
their volume would be noise. Watch them on a dashboard instead.

## Runbooks

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
