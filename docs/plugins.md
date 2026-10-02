# Exec plugins

A plugin is any executable that deckard runs once per matching asset. It reads
one JSON request on stdin and writes one JSON response on stdout. Plugins show
up as checks named `plugin.<name>`.

## Configuration

```yaml
plugins:
  - name: my-check            # check name becomes plugin.my-check
    exec: ["/plugins/check.py"]   # argv, executed directly (no shell)
    tier: active              # passive | active | intrusive (invalid => intrusive)
    applies: { kind: url }    # asset kind: hostname, ip, service, url, ...
    timeout: 60s              # default 60s; the whole process group is killed on expiry
    config:                   # passed verbatim to the plugin as "config"
      threshold: 3
      passthrough_env: [MY_API_TOKEN]   # env var names forwarded to the plugin
```

Tiers follow the normal rules: an `intrusive` plugin only runs when the
intrusive profile is enabled for the asset.

## Execution environment

- argv comes from `exec`; there is no shell, so no quoting or expansion applies.
- Working directory is a fresh temporary directory, removed afterwards.
- The environment contains only `PATH` plus the names listed in
  `config.passthrough_env`. Secrets are not inherited implicitly.
- stdout is capped at 4 MiB (the process is killed beyond that).
- stderr is captured and logged (truncated to 1 KiB) at warn level.
- A non-zero exit, a timeout, invalid JSON or more than one JSON document on
  stdout is an error: **no** findings from that run are used.
- Only in-scope targets are sent. The asset (and every neighbour) must pass
  the scope verifier (`scope.Guard.VerifyOwnedTarget`): the name must be owned
  and must resolve (through the guard's resolver) only to owned addresses,
  because plugins run their own network stack. A name whose DNS points at a
  third party, a mixed answer, an excluded/special address or a resolution
  error is refused (fail closed); out-of-scope assets are never given to the
  plugin.

## Protocol v1

Request (one JSON object on stdin):

```json
{
  "version": 1,
  "check": "plugin.my-check",
  "asset": {"id": 12, "kind": "url", "key": "https://app.example.com/", "source": "prod-cf",
            "scope": "owned", "zone": "example.com", "attrs": {"tech": ["nginx"]},
            "first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-02T00:00:00Z"},
  "neighbours": [
    {"asset": {"kind": "hostname", "key": "app.example.com", "...": "..."}, "relation": "serves", "outbound": false}
  ],
  "config": {"threshold": 3}
}
```

Response (one JSON object on stdout; every key optional):

```json
{
  "observations": [{"check": "ignored", "data": {"latency_ms": 41}}],
  "findings": [{
    "key": "weak-banner",
    "severity": "medium",
    "title": "Weak banner",
    "description": "What was found and why it matters.",
    "evidence": {"header": "Server"},
    "remediation": "How to fix it.",
    "tags": ["custom"]
  }],
  "discovered": [{"kind": "hostname", "key": "new.example.com", "source": "my-check", "attrs": {}}],
  "relations": [{"from_kind": "hostname", "from_key": "new.example.com",
                 "to_kind": "ip", "to_key": "192.0.2.10", "type": "resolves_to"}]
}
```

Rules enforced by deckard:

- `severity` must be one of `info|low|medium|high|critical` and `title` must be
  non-empty; other findings are dropped and logged.
- The `check` field of observations and findings is overwritten with
  `plugin.<name>`. `key` distinguishes several findings on one asset; it
  defaults to the title.
- Discovered assets need a known `kind` and a non-empty `key`; relations need
  known kinds, keys and a known `type`. Invalid ones are dropped and logged.
  Discovered assets only enter the inventory if they fall within scope.
- Never put secret values in `evidence`; findings are stored and sent to
  alerting.

## Examples

- `examples/plugins/example.py` (Python 3, stdlib only)
- `examples/plugins/example.sh` (bash + jq)

Try one by hand:

```sh
echo '{"version":1,"check":"plugin.demo","asset":{"kind":"url","key":"http://example.com/"},"neighbours":[],"config":{}}' \
  | python3 examples/plugins/example.py
```
