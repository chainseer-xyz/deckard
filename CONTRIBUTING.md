# Contributing to deckard

Thanks for helping. deckard is a defensive tool, so two rules shape most review
feedback: **never weaken the scope guard**, and **a failure must never delete
data** (a failed source or check must not remove assets or resolve findings).

## Setup

- Go (see `go.mod`), Docker (the Postgres tests use testcontainers), Node 22 for
  the UI, Helm for the chart.
- `make test` runs `go test -race ./...`. On Colima set
  `DOCKER_HOST=unix://$HOME/.colima/default/docker.sock`,
  `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock` and
  `TESTCONTAINERS_RYUK_DISABLED=true`.
- UI: `cd web && nvm use && npm ci && npm test` (Node 22; see `web/README.md`).
- Chart: `deploy/helm/tests/render_test.sh`.

## Workflow

- Test first: write the failing test, watch it fail, then make it pass.
  Table-driven tests, Arrange-Act-Assert.
- Small, atomic commits with messages that explain *why*.
- `gofmt`, `go vet ./...` and the full test suite must pass. No secrets in
  commits or fixtures; use `example.com` and RFC 5737 addresses in test data.

## Adding things

- **A check**: implement `check.Check` in `internal/check/...`, use only the
  clients on `check.Target` (never open your own connections), register it in
  `internal/check/all` and add it to `internal/app/checks_test.go`. Give
  findings a stable `Key`, a clear remediation and redacted evidence.
- **A source**: implement `source.Source`; return an error (not a partial
  result) when a required call fails, and set `Discovery.Partial` when you
  skipped something because of permissions. Register it in
  `internal/source/all`.
- **A notifier**: implement `notify.Notifier` (Alertmanager is the built-in).
- **No-code checks**: nuclei templates or exec plugins, see `docs/plugins.md`.

## Pull requests

Describe the behaviour change and how you verified it. Anything touching
`internal/scope`, authentication or the store contract needs tests that show the
safety property still holds.
