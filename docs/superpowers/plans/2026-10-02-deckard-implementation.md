# deckard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build deckard, a containerised continuous external attack-surface monitor that discovers assets from Cloudflare/Route53/Kubernetes/static sources, probes them in tiers, tracks findings, and alerts through Alertmanager, with a UI, metrics and a Helm chart.

**Architecture:** Single Go binary (modular monolith). Postgres holds state and the River job queue. Sources feed an inventory graph; a scheduler enqueues tiered check jobs; a findings reconciler tracks lifecycle; a notifier pushes to Alertmanager. REST API plus embedded React UI.

**Tech Stack:** Go 1.26, pgx v5, goose, River, chi, koanf, slog (JSON), prometheus/client_golang, aws-sdk-go-v2, client-go, ProjectDiscovery libs / nuclei binary, testcontainers-go, React + Vite + TS + Tailwind, Helm.

**Spec:** `docs/superpowers/specs/2026-10-02-deckard-design.md`

## Global Constraints

- Go module path `github.com/chainseer-xyz/deckard`; Go 1.26; `CGO_ENABLED=0` builds.
- JSON logging to stdout via `log/slog`; no log files; config via YAML file plus `DECKARD_` env (`__` nesting), env wins.
- All network probes go through `scope.Guard`; no check creates its own dialer, resolver or HTTP client.
- Postgres required; migrations embedded and run by `deckard migrate` and at `serve` start.
- No CPU limits in Helm defaults.
- TDD: failing test first, table-driven, Arrange-Act-Assert. `go test -race ./...` green before every commit.
- Commits: concise, "why"-focused, **no AI attribution trailers of any kind**.
- Functions under ~50 lines; one responsibility per file.

## Review Focus

1. Hostname that CNAMEs to a third-party SaaS: must be fingerprinted by resolving/requesting the owned name only, never port-scanned. (Task 3, Task 9)
2. Source API outage or partial page: must not mark assets removed or resolve findings. (Task 4, Task 7)
3. Wildcard DNS zone: CT/brute results must not flood the inventory with phantom hosts. (Task 10)
4. Alertmanager unreachable: findings stay `open`, retry with backoff, no duplicate-alert storm on recovery. (Task 8)
5. CIDR in static source larger than `max_cidr_hosts`: reject with a clear config error, never expand. (Task 3, Task 4)

---

## Phase 1: Foundation (sequential, done by the lead)

### Task 1: Scaffold, contracts and CI
**Files:** `go.mod`, `cmd/deckard/main.go`, `internal/model/*.go`, `internal/config/*.go`, `internal/logging/*.go`, `Makefile`, `Dockerfile`, `.golangci.yml`, `.github/workflows/ci.yml`
**Produces:** compiling `model` types (Asset, Relation, Finding, Severity, Tier, inputs), `source.Source`, `check.Check`/`Target`/`Result`, `notify.Notifier`, `store.Store` interfaces; config loader with validation; JSON logger.
- [ ] Write config load/validate tests (defaults, env override, invalid duration, oversized CIDR)
- [ ] Implement `model`, interfaces, `config`, `logging`
- [ ] `go test -race ./...` green, commit

### Task 2: Postgres store and migrations
**Files:** `internal/store/store.go`, `internal/store/postgres/*.go`, `internal/store/postgres/migrations/*.sql`
**Consumes:** `model`, `store.Store`. **Produces:** pgx implementation, goose migrations, testcontainers harness `storetest.Run(t, factory)`.
- [ ] Contract test suite for upsert asset/relation, diff, findings lifecycle, baselines, suppressions
- [ ] Implement, run against testcontainers Postgres, commit

## Phase 2: Parallel build (subagents, isolated worktrees, one package each)

### Task 3: scope.Guard
`internal/scope/*`. Classification table (owned/shared/external/excluded), embedded shared-infra CIDR list, guarded dialer/resolver/HTTP client, recording-dialer invariant test.

### Task 4: Sources (cloudflare, route53, kubernetes, static)
`internal/source/<type>/*`. Recorded-fixture tests (Cloudflare fixtures captured from the signed-in `cf` CLI and sanitised), httptest servers, fake k8s clientset, aws smithy stubs.

### Task 5: Inventory + diff + baseline/learning
`internal/inventory/*`, `internal/finding/baseline*.go`.

### Task 6: Findings lifecycle, fingerprints, suppressions
`internal/finding/*`.

### Task 7: Engine (River workers, scheduler, cadence, rate limits, roles)
`internal/engine/*`.

### Task 8: Alertmanager notifier
`internal/notify/alertmanager/*`, `deploy/examples/alertmanager.yml`.

### Task 9: Passive checks
`internal/check/{dns,tls,http,origin,cloud}/*`.

### Task 10: Expansion (CT, SANs, wildcard detection, opt-in brute)
`internal/inventory/expand/*`.

### Task 11: Active checks + nuclei + exec plugins
`internal/check/{net,tlsconfig,exposed}/*`, `internal/nuclei/*`, `internal/plugin/*`.

### Task 12: API, auth (OIDC/token), SSE, metrics
`internal/api/*`, `internal/metrics/*`.

### Task 13: Web UI
`web/*`, embedded into `internal/api/ui/dist`.

### Task 14: Helm chart, compose, Grafana dashboard
`deploy/helm/deckard/*`, `docker-compose.yml`, `deploy/grafana/*`.

## Phase 3: Integration and hardening (lead)

### Task 15: Wire `serve`, `sync --once`, `scan --once`; end-to-end test
### Task 16: Live validation against the real Cloudflare account via `cf` (read-only), compose e2e
### Task 17: gosec, trivy, coverage gates, README, CONTRIBUTING, LICENSE

## Loop protocol

After each task or merge: `go build ./... && go vet ./... && go test -race ./...`. After each phase: independent review by a fresh subagent plus a peer CLI (`codex`/`agy`) on the diff; findings fixed before the next phase. Progress tracked in `docs/superpowers/plans/PROGRESS.md`; the loop ends only when every task is checked and Task 17 gates pass.
