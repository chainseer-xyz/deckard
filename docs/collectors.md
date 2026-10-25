# Collectors and isolated assessments

Deckard retains inventory, correlates identities and reconciles findings. Optional
collectors run specialist tools in separate Kubernetes Jobs. All collectors and
assessment execution are disabled by default. Enabling a tool does not prove coverage.

## Coverage and lifecycle

| Producer | Coverage | Can absence resolve findings? |
| --- | --- | --- |
| Trivy image | Exact manifest and selected platform; vulnerability packages | Only a successful, comparable complete report |
| Trivy runtime images | Current qualified runtime manifests and Node platforms | Only successful cluster-wide collection with unchanged before/after inventories |
| Kubescape | Read-only resource posture; excludes Secrets, ConfigMaps, host and image assessment | No; restricted reports stay incomplete |
| Prowler App | Pulls completed provider scans; does not run a second cloud scanner | Only the native pull's complete reconciliation |
| BBOT | Keyless passive DNS discovery through three approved modules | No; discovery never asserts ownership or removal |
| Falco / Tetragon | Reported runtime incidents | No; silence is not a clean scan |
| ZGrab2 | HTTP status for explicitly granted IP/domain/port tuples | No; observations do not assess vulnerability absence |
| ZAP | Bounded HTTP assessment, optionally authenticated | No; native scan completion is not yet independently proven |
| Strix | Constrained agentic HTTP assessment | No; review agent-reported findings |

These tools do not provide a free global Internet index. Missing registry access,
unsupported runtime image identities, provider rate limits and disabled tools
remain coverage gaps. CycloneDX imports are inventory, not vulnerability scans.

## Credentials

Create distinct random producer tokens in your normal secret store. Configure
their environment variable names in Deckard. Do not reuse the administrator token.
Tokens must contain at least `32` bytes. Missing, duplicate or admin-equivalent
token values fail application startup.

```yaml
sources:
  - name: bbot-external
    type: bbot
    remote_only: true
    report_interval: 12h
ingest:
  credentials:
    runtime:
      token_env: TETRAGON_INGEST_TOKEN
      tools: [tetragon]
      scopes: ["k8s:uid:<kube-system-namespace-UID>"]
    images:
      token_env: TRIVY_INGEST_TOKEN
      tools: [trivy]
      scopes: ["k8s:uid:<kube-system-namespace-UID>:runtime-images"]
    discovery:
      token_env: BBOT_DISCOVERY_TOKEN
      discovery_sources: [bbot-external]
  tools:
    tetragon: {expected_report_interval: 5m}
    trivy: {expected_report_interval: 6h, expected_interval: 6h}
```

Tools and scopes are exact grants, not wildcard patterns. Multiple tools/scopes
grant their Cartesian product. Use separate credentials when that would be too broad.
Producer credentials cannot read inventory, start assessments, perform manual lifecycle actions or
open the UI. Only their granted ingest/discovery endpoints accept them.

## Scheduled collectors

Merge [collectors-values.yaml](../deploy/helm/deckard/collectors-values.yaml) with
your Helm values. Its examples describe each fixed command, required identity,
resource bounds and egress. Supply immutable scanner and uploader image references.

Every run uses fresh scratch, `Forbid` concurrency, no automatic retries and a
deadline. Scanner success must precede upload. A successful Job includes accepted
ingest, not merely scanner exit. Jobs run non-root with a read-only root filesystem,
dropped capabilities, no host mounts and no CPU limits.

Collector Pods inherit the chart's top-level `nodeSelector`, `tolerations` and
`affinity`. A per-job field replaces that entire global field; explicit `{}` or
`[]` clears it. BBOT always adds `kubernetes.io/os: linux` and
`kubernetes.io/arch: amd64`, and rejects conflicting effective selectors. Its
affinity must also permit those nodes.

Kubescape jobs accept `frameworks: [nsa]`, `[mitre]` or both; the default is both.
The list must be nonempty and unique. For large clusters, use separately named
jobs with the same immutable cluster scope when combined reports approach the
`5000`-finding limit. Measure each report first; every restricted report remains
incomplete, so these jobs cannot resolve findings through absence.

### Collector failures

Check collection, upload and report freshness separately. Application readiness
only proves that the service can reach its database; it does not prove collection.
Find the collector Pods with the alert's `diagnostic_command`. Inspect the failed
Pod's `scanner` logs first. If scanning succeeded, inspect its `ingest` logs and
validate the delivery receipt. A report must be accepted, not merely return HTTP `200`.

An `unknown flag` error means the pinned scanner does not support the rendered
command. Validate every rendered argument against that exact binary before an
image update. Do not remove host/image/Secrets exclusions to make it run. Pin an
explicit version and digest; an unversioned digest update can select an older CLI.

`DeckardCollectorFailed` identifies a failed run after the last accepted upload.
`DeckardCollectorStale` identifies delivery beyond its configured age limit.
A newer successful accepted upload clears the failed-run condition. Old failed
Jobs may remain for diagnosis and keep generic Kubernetes alerts firing after
recovery. Argo evaluates the CronJob's latest schedule and success timestamps.

`DeckardCollectorFailed` also detects an idle, nonsuspended CronJob whose latest
scheduled run has no successful ingest. This condition persists after finished
Jobs and their metrics expire. Active runs, missing scheduling state and
suspended CronJobs cannot establish this fallback. The five-minute hold remains.

Use `ttlSecondsAfterFinished: 600` for short Job retention when collector alerts
are enabled and diagnostic logs persist outside Pods. Capture failed Job logs
and verify a later accepted upload before retiring historical failures. Job
cleanup never resolves durable security findings or establishes complete coverage.

Runtime findings remain durable even when their Alertmanager notifications expire.
Notification clearance, event silence and Pod removal do not prove remediation.
Runtime presentation uses reported namespace, Pod and policy metadata without
changing incident identity or granting ownership. Batch event times and counts do
not claim lifetime counts or complete sensor coverage.

Only uploader containers receive Deckard producer tokens. Kubernetes scanners
receive narrowly scoped projected API tokens. Registry credentials are explicit,
read-only and scanner-only. Jobs do not inherit Deckard's IRSA, cloud credentials,
admin token or `envFrom`. Prowler pull uses a dedicated read-only Prowler API key.

Collector NetworkPolicies allow DNS and the local Deckard API, then deny other
egress unless configured. Add the actual Kubernetes API and approved provider,
registry and vulnerability database destinations. Standard NetworkPolicy cannot
pin changing CDN addresses by hostname. Use a controlled proxy or separately
managed CNI FQDN policy; do not use unrestricted Internet egress as containment proof.

Trivy's database can exceed `1.5 GiB`. Its example reserves `4 GiB` disk scratch
and `2 GiB` memory. Private registry denial fails the run; it does not certify clean
coverage. BBOT's pinned `3.0.2` image supports `amd64` only; select compatible nodes.
BBOT is separately licensed `AGPL-3.0`; Deckard does not bundle its source.

## Runtime delivery

Reuse an existing Tetragon sensor's `export-stdout` container. Deckard does not
install another privileged sensor. The collector lists sensor Pods and reads a
bounded `6m` log window every `5m`. All selected Pods must be readable; truncation,
reported event drops, oversized output or a failed read fails the whole collection.
Raw input is bounded to `32 MiB` per sensor and `256 MiB` across the collection.
Streaming discards each raw record after parsing; the normalized report remains
limited to `10 MiB`. Byte limits and transport failures remain explicit failures,
not malformed-JSON warnings or successful prefix uploads.

```sh
deckard runtime collect --namespace tetragon --selector app.kubernetes.io/name=tetragon \
  --container export-stdout --cluster-scope k8s:uid:<kube-system-namespace-UID> \
  --output /report/request.json
deckard runtime upload --file /report/request.json \
  --cluster-scope k8s:uid:<kube-system-namespace-UID> \
  --url https://deckard.example.com --token-env TETRAGON_INGEST_TOKEN
```

Use the immutable `kube-system` namespace UID, not a display name. Runtime events
join workloads only on exact cluster UID, namespace and Pod UID. Ambiguous claims
do not attach. Ordinary process telemetry is ignored; policy events retain only
rule identity, workload identity, timestamps and counts. Arguments, environment,
labels and raw log bodies are not retained.

The lookback overlap deduplicates repeat incidents. Equal or older timestamps
cannot reopen a resolved incident. A newer occurrence can reopen it. Resolve a
reviewed incident from the finding drawer with an audit note. Deleting a Pod or
receiving no events cannot resolve an incident. Collector report freshness proves
delivery, not that the sensor saw every event.

Scheduled Tetragon collectors may set an integer `backoffLimit` from `0` to `4`
to retry failed whole-Pod attempts during node churn. The default remains `0`.
The maximum allows four retries, or five total Pod attempts; other collectors
cannot opt into nonzero retries. Each retry uses a fresh report volume and
re-reads every selected sensor. A failed attempt uploads nothing when collection
fails; retries never skip unreadable sensors or assert complete coverage.

An upload receipt failure can follow an accepted ingest. Event keys and
timestamps deduplicate delivery retries. The Job's existing deadline and
`Forbid` concurrency still bound all attempts. The default deadline remains
`300` seconds and can prevent all retries from starting or completing. A higher
retry limit does not extend that deadline. Retries cannot recover logs already
lost to rotation or node removal. Each retry uses the current six-minute lookback,
not the original attempt's window. Long retry delays can leave an earlier gap
even when a later attempt succeeds.

## Runtime images

`deckard images collect` reads current Pods and Nodes, then scans qualified
`repository@sha256:...` runtime manifests with pinned Trivy. It never uses a host
socket, mutable tag or bare container config digest as a manifest identity.
Regular, init and ephemeral container status families are included.

Limits are `10000` Pods, `1000` Nodes, `64` image/platform pairs, `2m` per image,
`45m` total, `5000` findings/artifacts and a `10 MiB` normalized envelope. The
collector re-lists inventory after scanning. Changed identities, missing runtime
digests, unknown platforms or any failed scan prevent upload.

A container explicitly waiting for `PodInitializing` with no ImageID is not yet
running. Its UID, spec and waiting state enter the inventory fingerprint. It is
not scanned or certified; a transition before the final re-list fails collection.

Use explicit `--all-namespaces` for complete reconciliation. Namespace-filtered
runs always remain incomplete, so shrinking a filter cannot resolve older CVEs.
Only the collector receives registry/API credentials; use `--output` plus a
separate `images upload` container for scheduled delivery.

## Isolated assessments

Set `config.assessment` only after a real CNI containment fixture passes. Helm
requires one API replica, `Recreate`, NetworkPolicy enabled and a dedicated
assessment namespace. The private broker uses Pod IP port `9092`; do not expose
it through an Ingress or Service. The API manager has a separate ServiceAccount.
Update exact-subject IRSA trust if that API also performs AWS inventory work.

The following is a template, not runnable credentials or verified containment:

```yaml
assessment:
  enabled: false
  namespace: deckard-assessments
  broker_addr: 0.0.0.0:9092
  broker_ip_env: DECKARD_POD_IP
  network_policy_enforced: false
  images:
    zgrab2: ghcr.io/chainseer-xyz/deckard-assessment-zgrab2@sha256:<digest>
    zap: ghcr.io/chainseer-xyz/deckard-assessment-zap@sha256:<digest>
  uploader_image: ghcr.io/chainseer-xyz/deckard@sha256:<slim-digest>
  max_sessions: 16
  max_running: 2
  timeout: 15m
  max_requests: 500
  max_request_bytes: 8388608
  max_response_bytes: 33554432
```

Select a current owned network asset in the UI, choose a configured scanner and
explicitly authorize testing. Tests can change application data. The API offers
`GET /api/v1/assessments`, `POST /api/v1/assessments` and per-session status.
Nothing schedules intrusive assessments automatically.

ZAP and Strix target traffic must cross an authenticated broker. It enforces exact
origins, current ownership, guarded DNS/dialing, strict target TLS and cumulative
request/byte/deadline limits. Redirects cannot enlarge the origin grant. Refused
traffic makes the session incomplete. Proxy and upload credentials are distinct.

ZGrab2 requires direct fixed-IP connections. Its NetworkPolicy grants only the
selected addresses/ports for at most `15m`; DNS, redirects and protocol retries
are disabled. Ownership revocation during that interval is not immediate. Final
ownership verification prevents a revoked grant from producing clean coverage.

Stock ZAP disables certificate and hostname verification for scan traffic,
including its TLS connection through the broker. Deckard performs strict,
session-CA-verified Go preflights before ZAP starts. The broker independently
verifies target TLS. This boundary trusts the broker and enforced cluster/CNI; it
does not provide strict end-to-end ZAP client TLS or protection against a
compromised broker/CNI. ZAP `2.17` can silently time out its passive wait; therefore
even successful native reports remain additive.

Native ZAP can open an unused TLS connection or attempt an HTTPS upgrade outside
an HTTP-only grant. The broker retains these conservative incomplete/refused
reasons. A useful report does not turn those refusals into complete coverage.

### Authenticated ZAP

Create `auth.json` in a Secret in the isolated namespace. Set
`assessment.zap_auth_secret_name` to its name. The file is at most `16 KiB`.

```json
{"schema_version":1,"origins":[{"origin":"https://app.example.com","verification_path":"/account","header":"Authorization","value":"Bearer <target-only-token>","expected_status":200}]}
```

Only `Authorization` and `X-Api-Key` are supported. Each exact origin needs an
unauthenticated `401`/`403` and authenticated `200` from its verification path.
Failed auth controls stop scanning. Cookie/login flows and arbitrary ZAP scripts
are unsupported. Only the scanner receives target credentials; reports discard
request headers, cookies, bodies, reflected descriptions and query values.

### Constrained Strix

The separate Strix image retains genuine upstream `1.7.0`, its `Apache-2.0`
license and pinned SDK dependencies with an explicit hashed security overlay. The adapter deliberately excludes Caido,
browser automation, search, MCP and upstream host/container management. A separate
runtime Pod offers bounded authenticated shell/filesystem RPC. Only its broker
egress is allowed; the controller can reach only that runtime and the approved
literal-IP model gateway.

Configure `strix_runtime_image`, a pinned `images.strix`, `model`,
`model_gateway_url`, `model_gateway_ip` and `model_gateway_port`. Local keyless
OpenAI-compatible gateways are supported only on approved private addresses.
Optional `model_secret_name`/`model_secret_key` exposes a model credential only to
the controller, never the runtime. Hosted inference requires explicit operator
approval for cost and data egress. Turn/request limits are not a dollar budget.
No provider account or credential is provisioned automatically.

Raw model traces and scripts remain ephemeral. Normalized findings are bounded
and always incomplete. Model failure produces a structured failure report. A
protocol fixture or missing-model failure is not evidence of a successful model
assessment. Review each finding before treating exploit claims as established.

## Operations and retention

The Sources page separates report freshness from complete coverage. Runtime is
always `event_only`; incomplete reports cannot become green complete coverage.
Configured producers with no reports appear as `never`. Remote discovery uses
its `report_interval`, not the native source sync frequency.

Metrics include `deckard_ingest_last_report_timestamp`,
`deckard_ingest_report_expected_interval_seconds` and
`deckard_source_expected_interval_seconds`. Existing complete-success metrics
keep their original meaning. Optional collector rules use kube-state-metrics to
alert on failed, stale and never-successful scheduled Jobs.

Assessment status is controller-local and expires. Accepted findings remain in
PostgreSQL. A restart cannot recover an interrupted report as clean. Job owner
references, UID-checked deletion, TTL and bounded orphan cleanup remove session
resources. `cleanup_pending` means deletion failed; inspect the exact session
labels and UIDs before deleting resources. Keep the isolation namespace/default
deny even when disabling execution, until no Jobs/Pods remain.

Artifact inventory remains additive. Current source facts do not contain enough
provenance timestamps to safely expire image/package relationships. Do not prune
them merely because a workload disappears. Finding resolution still requires
comparable complete evidence; runtime and agentic incidents never use absence.

Before production enablement, verify allowed target traffic succeeds and DNS,
metadata, API, foreign-origin and direct-egress attempts fail from real runner
Pods. Check all replicas, scheduled Jobs, report acceptance and retained graph
joins. Helm rendering and local Docker tests do not prove live CNI enforcement.
