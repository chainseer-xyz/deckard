#!/usr/bin/env bash
# Minimal deckard exec plugin (protocol v1): flags URLs served over plain HTTP.
# Requires jq. Reads one JSON request on stdin, writes one JSON object on stdout.
set -euo pipefail

req=$(cat)
key=$(jq -r '.asset.key' <<<"$req")

if [[ "$key" == http://* ]]; then
  jq -n --arg url "$key" '{
    findings: [{
      key: "plain-http",
      severity: "low",
      title: "URL is served over plain HTTP",
      description: ($url + " does not use TLS."),
      evidence: {url: $url},
      remediation: "Serve the site over HTTPS and redirect HTTP to HTTPS."
    }]
  }'
else
  echo '{"findings":[]}'
fi
