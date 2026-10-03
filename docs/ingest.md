# Ingesting findings from external scanners

deckard's built-in checks run per asset against targets it may probe. Account-level
posture scanners (Prowler, Kubescape) and secret scanners (trufflehog, gitleaks) do not
fit that model: they run elsewhere (Kubernetes CronJobs, CI), look at an AWS account, a
cluster or a GitHub org, and produce a list of findings. `POST /api/v1/ingest` brings
those results into the same lifecycle (dedup, open/resolved, acknowledge/suppress,
Alertmanager routing, UI, API, metrics) **without deckard ever executing those tools or
reaching their targets**.

The usual way to post is the `deckard ingest` command, which converts a tool's native
output into a request:

```sh
prowler aws --output-formats json-ocsf --output-directory out --output-filename prowler --ignore-exit-code-3
deckard ingest --tool prowler --scope aws:123456789012:us-west-2 --file out/prowler.ocsf.json \
  --url https://deckard.example.com --token-env DECKARD_TOKEN
```

Add `--dry-run` to print the request (validated locally with the server's rules) instead
of posting it.

## The model in one paragraph

A request is **one run of one tool over one scope**. Findings are stored under the check
`ext.<tool>` (so alerts are named `DeckardExt<Tool>`, for example `DeckardExtProwler`, and
metrics and the UI group them) with source `ingest:<tool>`. A finding's fingerprint is
derived from `(tool, scope, key)`, where `key` is the producer's stable id for the item, so
the same item is the same finding across runs. A run that says it is **complete** is the
full truth for its `(tool, scope)`: previously ingested findings of that pair that are
absent follow the normal resolution path. Anything less than a valid, complete, newer run
can only open and refresh, never resolve.

## Request

`POST /api/v1/ingest`, `Content-Type: application/json`, at most 10 MiB, parsed strictly
(unknown fields are a 400).

```json
{
  "tool": "prowler",
  "scope": "aws:123456789012:us-west-2",
  "complete": true,
  "observed_at": "2026-10-03T07:00:00Z",
  "findings": [
    { "key": "s3_bucket_public_access:arn:aws:s3:::example",
      "asset": { "kind": "cloud_resource", "key": "arn:aws:s3:::example" },
      "title": "S3 bucket allows public access",
      "description": "The bucket policy grants s3:GetObject to *.",
      "severity": "high",
      "remediation": "Enable S3 Block Public Access.",
      "tags": ["prowler", "s3_bucket_public_access"],
      "evidence": { "region": "us-west-2" } }
  ]
}
```

| Field | Rules |
| --- | --- |
| `tool` | `^[a-z0-9][a-z0-9-]{1,31}$` |
| `scope` | 1 to 200 bytes, no control characters or surrounding whitespace. What was scanned: `aws:<account>:<region>`, `k8s:<cluster>`, `github.com/<org>`. |
| `complete` | `true` asserts `findings` is everything the tool found in `scope`. Omitted means `false`. |
| `observed_at` | Required, RFC 3339, at most 5 minutes in the future. When the run happened; it identifies the run. |
| `findings` | Required (`[]` is an empty run), at most 5000 (or `ingest.tools.<tool>.max_findings`). |
| `findings[].key` | Required, 1 to 512 bytes, unique within the request. |
| `findings[].asset` | Either `{kind, key}` or `{ref: {kind, key}}`, see [Assets](#assets-and-the-safety-rules). |
| `findings[].title` | Required, at most 300 characters, one line. |
| `findings[].description` | Required (it becomes the alert description), at most 8000 bytes. |
| `findings[].severity` | `info`, `low`, `medium`, `high` or `critical`. |
| `findings[].remediation` | Optional, at most 4000 bytes. |
| `findings[].tags` | At most 20, each 1 to 64 bytes. |
| `findings[].evidence` | Optional JSON object, at most 16 KiB encoded and 8 levels deep. |

The request needs a **write-capable identity**, the same rule as acknowledge and suppress:
a bearer token in `auth.mode: token`, a session cookie plus `X-CSRF-Token` in OIDC mode.

## Response

`200` when the request was applied:

```json
{"accepted": 41, "opened": 2, "reopened": 0, "refreshed": 39, "resolved_pending": 3, "resolved": 1,
 "complete": true, "replay": false, "rejected": []}
```

| Field | Meaning |
| --- | --- |
| `accepted` | findings applied (not rejected); 0 for a replay |
| `opened`, `reopened`, `refreshed` | new findings, resolved findings seen again, known findings seen again (operator statuses such as acknowledged or suppressed are kept) |
| `resolved_pending` | absent findings that accrued a miss and will resolve after `findings.resolve_after` consecutive complete misses |
| `resolved` | findings this request resolved |
| `complete` | whether absence was applied; `note` says why not when you sent `complete: true` |
| `replay` | the body repeated the last accepted one for this `(tool, scope)`; nothing changed |
| `rejected` | `[{index, reason}]` items that were not applied (see below) |

Errors use the usual `{"error":{"code","message"}}` envelope:

| Status | When | Changed anything? |
| --- | --- | --- |
| 400 | malformed JSON, unknown field, trailing data, query parameters | no |
| 401 | no or wrong credentials | no |
| 403 | cookie session without `X-CSRF-Token` (`csrf`), or `ingest.enabled: false` (`ingest_disabled`) | no |
| 413 | body over 10 MiB | no |
| 415 | `Content-Type` is not `application/json` | no |
| 422 | validation failed; the body adds `rejected: [{index, reason}]` with every problem (index `-1` is the request itself) | **no**: the request is rejected whole |
| 429 | per-identity rate limit or too many concurrent ingests; honour `Retry-After` | no |

## Reconciliation semantics (and why)

For a given `(tool, scope)`, the reconciliation set is every finding previously stored
under `(ext.<tool>, scope)`, whatever asset it is attached to. One request is applied
atomically, in one transaction serialised per `(tool, scope)` (a transaction-scoped
Postgres advisory lock), with exactly the lifecycle code built-in checks use:

1. Every reported item **opens** (new fingerprint), **reopens** (it was resolved) or is
   **refreshed** (title, severity, evidence updated, the miss count reset, an operator's
   acknowledge, suppress or false-positive status kept).
2. **Absence is applied only if all of these hold**: the request says `complete: true`, no
   item was rejected, and `observed_at` is strictly newer than every run already accepted
   for the pair. Then each unresolved finding of the set that the run did not report
   accrues a miss, and resolves after `findings.resolve_after` consecutive complete misses,
   exactly like a built-in check that stopped reproducing. Suppressed and false-positive
   findings resolve the same way (their notes stay as history).
3. Otherwise the request **only opens and refreshes**; nothing accrues a miss and nothing
   resolves, and the response says `complete: false` with a `note`.

Why these rules:

- **Absence proves nothing unless the producer says it saw everything.** A scanner that
  timed out halfway, a filtered run or a single-account test run must not resolve the rest
  of the scope. Hence `complete` defaults to `false`, and `deckard ingest --incomplete`
  exists for partial runs.
- **A rejected item means the producer and deckard disagree about the run.** If an
  `asset.ref` no longer resolves, the finding is skipped; resolving the others as if the
  run were whole would treat a disagreement as proof of absence. The rest of the run is
  still applied (opens and refreshes are always safe).
- **An invalid request changes nothing.** Validation runs before any write and the store
  applies everything in one transaction; a 4xx never leaves a half-applied run behind.
- **Runs are ordered by `observed_at`.** A delayed delivery of an older run, or a second
  delivery of the same run with different content, carries no new information about
  absence, so it never counts misses (but its findings still open or refresh, which errs
  on the side of alerting).
- **Retries are free.** A body equal to the last accepted one for its pair (same digest:
  tool, scope, complete, `observed_at` and findings) is a no-op, so a client that lost the
  response can post again. `observed_at` is required so that two different runs never look
  like one. `deckard ingest` retries network errors, 429 and 5xx with the same body.
- **The usual resolution delay applies.** One complete run without a finding is a miss,
  not a resolution; flapping tools and transient permission problems get the same grace
  as built-in checks.

Keep a producer's scope and flags stable: "complete" means "everything this command
reports for this scope". Narrowing a filter (for example adding `--only-verified`) makes the
findings it no longer reports resolve after `resolve_after` runs.

## Assets and the safety rules

Every finding attaches to an asset:

- `{"kind": "cloud_resource", "key": "..."}` uses the asset if it exists and creates it
  otherwise, with source `ingest:<tool>` and scope class `external`, or `owned` only if an
  operator allow-listed the tool (`ingest.tools.<tool>.owned: true`). `cloud_resource` is the
  only kind an ingest may create: it is not network-addressable, the scope guard never
  classifies it owned, and no tier may probe it. A live asset of another source is
  attached to unchanged; a removed one is revived and claimed for `ingest:<tool>`.
- `{"ref": {"kind": "hostname", "key": "www.example.com"}}` attaches to an **existing,
  live, owned** asset of any kind (hostname, ip, zone, service, url, certificate,
  cloud_resource) and never modifies it. A ref that does not resolve to such an asset
  rejects the item (`rejected`) and keeps the run from resolving anything.

The invariants, each enforced in code and covered by tests:

- **deckard never probes anything an ingest names.** The scheduler, rescans and workers
  refuse every asset whose source is `ingest:<tool>` before any check runs, whatever its
  scope class or kind (`internal/engine/ingest_test.go` proves no scan is ever scheduled or
  run for one, with every tier enabled and a guard that says owned). Ingest cannot create a
  hostname, ip, url, service or zone asset, so it can never add to the owned scope.
- **Ingest cannot resolve anything on an incomplete or invalid request** (above).
- **Ingested assets are never removed by a source sync**: they are reported only by
  `ingest:<tool>`, and config validation reserves the `ingest:` source-name prefix (and the
  `ext.` plugin-name prefix) so nothing else can claim either.
- **Secrets are never stored.** The trufflehog and gitleaks parsers keep the detector or
  rule, where the secret is and a 12-hex SHA-256 prefix of it, never the value; see
  [Secrets](#secrets).

Ingested findings carry `ingest_scope` in the API. They are suppressed, acknowledged,
notified (above `notify.alertmanager.min_severity`), enriched with CISA KEV / EPSS (for
CVE ids in tags or evidence) and counted like any other finding; YAML suppressions match
them with `check=ext.<tool>`.

## `deckard ingest`

```text
deckard ingest --tool <name> --scope <scope> [--format <parser>] [--file <path> | stdin]
               [--url <deckard base URL> --token-env <VAR>] [--incomplete] [--observed-at <RFC 3339>]
               [--dry-run] [--timeout 2m] [-v]
```

- `--format` picks the parser and defaults to the tool name, so `--tool semgrep --format sarif`
  stores Semgrep's SARIF under `ext.semgrep`.
- `--observed-at` defaults to now. Pass the scan's own time if you post later.
- The token is read from the variable named by `--token-env`; a `--url` with credentials is
  refused and the token is scrubbed from everything the command prints.
- Exit codes: **0** posted and applied (a replay counts), **1** usage, input or validation
  error (nothing posted), **2** the server rejected the request or some items, or did not
  apply a complete run as complete, **3** deckard could not be reached.

| `--format` | Tool output | Findings | Key | Severity | Asset |
| --- | --- | --- | --- | --- | --- |
| `prowler` | `--output-formats json-ocsf` (v4+) or `-M json` (v3); array or one object per line | `FAIL` results; PASS and MANUAL are skipped | check id + resource uid | Prowler's | resource ARN (account/region key if none) |
| `kubescape` | `scan ... --format json` | failed controls per resource | control id + resource id | control severity or scoreFactor | `k8s://<cluster>/<resource id>` |
| `trufflehog` | `--json` lines | every result | detector + file + line + commit + secret hash | verified high, else medium | repository URL, else the scope |
| `gitleaks` | `--report-format json` | every leak | rule + file + line + commit + secret hash | medium (unverified) | repository from the link, else the scope |
| `s3scanner` | `--json` lines | each public permission of an existing bucket | provider + bucket + permission | everyone write: critical, everyone read: high, ... | bucket ARN or `<provider>://<bucket>` |
| `sarif` | SARIF 2.1.0 (Semgrep, CodeQL, Trivy, Checkov, tfsec, KICS, ...) | results of kind `fail`, not suppressed, not `absent` | rule + location + result fingerprint | `security-severity`, else level | repository from `versionControlProvenance`, else the scope |

Every parser tags findings with the tool name and the underlying rule id. Parsers are
pure (no network) and covered by golden-file and fuzz tests: any input either fails to
parse or yields a valid request.

**An empty or truncated output must not look like a clean run.** The prowler, gitleaks and
SARIF parsers refuse empty input (those tools always write at least `[]` or a log). trufflehog
and s3scanner print nothing when there is nothing to report, so for them an empty input is
a valid empty run: run the scanner so that a failed scan never reaches `deckard ingest` (the
CronJobs below run it as an init container, which stops the pod on failure). Mind the
tools' exit codes: Prowler exits 3 when checks fail unless `--ignore-exit-code-3`, gitleaks
exits 1 on leaks unless `--exit-code 0`, trufflehog exits 0 unless `--fail`.

### Secrets

The trufflehog parser decodes only the detector, verification flag and location fields;
`Raw` and `RawV2` are hashed and dropped, and `Redacted`, `ExtraData` and `StructuredData`
are never decoded. The gitleaks parser hashes `Secret` and never decodes `Match`, `Line`,
`Author`, `Email` or `Message`. Credentials in repository URLs are stripped and parse
errors never quote the input. Tests plant fake secrets in every one of those fields and fail
if any reaches the request. Do not post a secret scanner's SARIF through the `sarif` parser:
SARIF messages may contain the match; use the native parser.

## Configuration

```yaml
ingest:
  enabled: true            # default; false answers 403
  rate_limit: 60/m         # per identity (token bucket)
  burst: 10
  max_concurrent: 4        # ingest requests processed at once per API process; more get 429
  timeout: 2m              # per request (large runs write thousands of rows in one transaction)
  max_scopes_per_tool: 50  # cardinality cap of the scope label in metrics
  tools:
    prowler:
      owned: true          # label assets this tool creates as owned (never makes them probable)
      max_findings: 5000   # per request, 0..5000 (default 5000)
      expected_interval: 24h   # drives deckard_ingest_expected_interval_seconds and DeckardIngestStale
    kubescape: { expected_interval: 6h }
    trufflehog: { expected_interval: 24h }
```

Tools not listed may still ingest with the defaults (external assets, 5000 findings, no
staleness alert). Any identity that can acknowledge or suppress can ingest; set
`enabled: false` if that is not wanted.

## Metrics and alerts

| Metric | Labels | Meaning |
| --- | --- | --- |
| `deckard_ingest_requests_total` | `tool`, `result` = ok, partial, replay, rejected, invalid, too_large, rate_limited, disabled, error | ingest requests; unlisted tools share `tool="other"` past 32, unparseable bodies count as `tool="unknown"` |
| `deckard_ingest_findings` | `tool` | open ingested findings (from the store) |
| `deckard_ingest_last_success_timestamp` | `tool`, `scope` | last run applied as complete (from the store); scopes beyond `max_scopes_per_tool` (by first ingest) report together as `scope="other"` with the oldest timestamp, logged once |
| `deckard_ingest_expected_interval_seconds` | `tool` | `ingest.tools.<tool>.expected_interval`, only for tools that set it |

`deploy/examples/prometheus-rules.yml` adds `DeckardIngestStale` (no complete run for a
`(tool, scope)` in twice its expected interval) and `DeckardIngestRejected` (rejected,
invalid, too_large or partial requests in the last hour). A scope you stop scanning keeps
`DeckardIngestStale` firing until you silence it; its open findings stay open (absence of
a scope is not absence of its findings).

## Kubernetes CronJobs

Each example runs the scanner as an init container writing to an `emptyDir`, then
`deckard ingest` in a second container using the deckard image. A failed scan fails the
init container, so nothing is posted. Root filesystems are read-only (scratch space is an
`emptyDir` at `/tmp`), there are no CPU limits, and the token comes from a Secret through
`secretKeyRef`. Pin image tags or digests. Create the token Secret first:

```sh
kubectl -n security create secret generic deckard-ingest --from-literal=token="$DECKARD_TOKEN"
```

### Prowler (AWS, IRSA)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: prowler-ingest, namespace: security }
spec:
  schedule: "0 6 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          serviceAccountName: prowler   # IRSA: eks.amazonaws.com/role-arn with SecurityAudit + ViewOnlyAccess
          restartPolicy: Never
          securityContext: { runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532, seccompProfile: { type: RuntimeDefault } }
          volumes:
            - { name: out, emptyDir: {} }
            - { name: tmp, emptyDir: {} }
          initContainers:
            - name: prowler
              image: prowlercloud/prowler:5.0.0   # pin
              args: ["aws", "--region", "us-west-2", "--output-formats", "json-ocsf",
                     "--output-directory", "/out", "--output-filename", "prowler", "--ignore-exit-code-3"]
              env: [{ name: HOME, value: /tmp }]
              resources: { requests: { cpu: 500m, memory: 1Gi }, limits: { memory: 2Gi } }
              securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
              volumeMounts: [{ name: out, mountPath: /out }, { name: tmp, mountPath: /tmp }]
          containers:
            - name: ingest
              image: ghcr.io/chainseer-xyz/deckard:latest   # pin
              args: ["ingest", "--tool", "prowler", "--scope", "aws:123456789012:us-west-2",
                     "--file", "/out/prowler.ocsf.json", "--url", "http://deckard.deckard.svc:8080",
                     "--token-env", "DECKARD_TOKEN"]
              env:
                - name: DECKARD_TOKEN
                  valueFrom: { secretKeyRef: { name: deckard-ingest, key: token } }
              resources: { requests: { cpu: 50m, memory: 64Mi }, limits: { memory: 256Mi } }
              securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
              volumeMounts: [{ name: out, mountPath: /out, readOnly: true }]
```

One CronJob (or one `--region` and `--scope` pair) per account and region keeps scopes
small and their freshness visible per scope.

### Kubescape (in-cluster)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: { name: kubescape, namespace: security }
---
# Read-only view of the whole cluster, which Kubescape's controls need. It includes Secrets;
# narrow it if your policy requires (controls that cannot see a resource report nothing for it).
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: kubescape-read }
rules:
  - { apiGroups: ["*"], resources: ["*"], verbs: ["get", "list", "watch"] }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: kubescape-read }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kubescape-read }
subjects: [{ kind: ServiceAccount, name: kubescape, namespace: security }]
---
apiVersion: batch/v1
kind: CronJob
metadata: { name: kubescape-ingest, namespace: security }
spec:
  schedule: "15 */6 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          serviceAccountName: kubescape
          restartPolicy: Never
          securityContext: { runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532, seccompProfile: { type: RuntimeDefault } }
          volumes:
            - { name: out, emptyDir: {} }
            - { name: tmp, emptyDir: {} }
          initContainers:
            - name: kubescape
              image: quay.io/kubescape/kubescape-cli:v3.0.20   # pin
              args: ["scan", "framework", "nsa,mitre", "--format", "json", "--output", "/out/kubescape.json", "--keep-local"]
              env: [{ name: HOME, value: /tmp }]
              resources: { requests: { cpu: 250m, memory: 512Mi }, limits: { memory: 2Gi } }
              securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
              volumeMounts: [{ name: out, mountPath: /out }, { name: tmp, mountPath: /tmp }]
          containers:
            - name: ingest
              image: ghcr.io/chainseer-xyz/deckard:latest   # pin
              args: ["ingest", "--tool", "kubescape", "--scope", "k8s:prod-example",
                     "--file", "/out/kubescape.json", "--url", "http://deckard.deckard.svc:8080",
                     "--token-env", "DECKARD_TOKEN"]
              env:
                - name: DECKARD_TOKEN
                  valueFrom: { secretKeyRef: { name: deckard-ingest, key: token } }
              resources: { requests: { cpu: 50m, memory: 64Mi }, limits: { memory: 256Mi } }
              securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
              volumeMounts: [{ name: out, mountPath: /out, readOnly: true }]
```

### trufflehog (GitHub organisation)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: trufflehog-ingest, namespace: security }
spec:
  schedule: "30 2 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          automountServiceAccountToken: false
          securityContext: { runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532, seccompProfile: { type: RuntimeDefault } }
          volumes:
            - { name: out, emptyDir: { medium: Memory, sizeLimit: 64Mi } }
            - { name: tmp, emptyDir: {} }
          initContainers:
            - name: trufflehog
              image: trufflesecurity/trufflehog:3.82.0   # pin
              # trufflehog prints nothing when it finds nothing, so a failed scan must stop here:
              # sh propagates its exit status and the pod fails before anything is posted.
              command: ["sh", "-c", "trufflehog github --org=example --json --no-update > /out/trufflehog.jsonl"]
              env:
                - { name: HOME, value: /tmp }
                - name: GITHUB_TOKEN   # read-only, fine-grained token for the organisation
                  valueFrom: { secretKeyRef: { name: trufflehog-github, key: token } }
              resources: { requests: { cpu: 500m, memory: 512Mi }, limits: { memory: 2Gi } }
              securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
              volumeMounts: [{ name: out, mountPath: /out }, { name: tmp, mountPath: /tmp }]
          containers:
            - name: ingest
              image: ghcr.io/chainseer-xyz/deckard:latest   # pin
              args: ["ingest", "--tool", "trufflehog", "--scope", "github.com/example",
                     "--file", "/out/trufflehog.jsonl", "--url", "http://deckard.deckard.svc:8080",
                     "--token-env", "DECKARD_TOKEN"]
              env:
                - name: DECKARD_TOKEN
                  valueFrom: { secretKeyRef: { name: deckard-ingest, key: token } }
              resources: { requests: { cpu: 50m, memory: 64Mi }, limits: { memory: 256Mi } }
              securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
              volumeMounts: [{ name: out, mountPath: /out, readOnly: true }]
```

trufflehog's output file contains the raw secrets while the pod runs. It stays in the
pod's memory-backed `emptyDir` (gone with the pod, never on the node's disk), and `deckard
ingest` hashes the values before anything is sent.

## Limits and operational notes

- At most 5000 findings and 10 MiB per request. A larger run fails locally (exit 1); split
  the scope (per account, region, cluster or repository) rather than posting part of it as
  complete.
- Re-labelling a tool as owned (or not) re-asserts the class on its assets at its next run.
- Ingested assets stay in the inventory after their findings resolve.
- Run each producer with stable flags and scope (see [Reconciliation](#reconciliation-semantics-and-why)).
