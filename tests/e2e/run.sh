#!/usr/bin/env zsh
# Runs the end-to-end suite in this directory against a deployed deckard.
#
# Required: E2E_CONTEXT, the kubectl context of the cluster running deckard.
# Optional environment variables:
#   E2E_NS        deckard namespace         (deckard)
#   E2E_SECRET    secret holding the token  (deckard-secrets, key DECKARD_ADMIN_TOKEN)
#   E2E_AM_NS     alertmanager namespace    (monitoring)
#   E2E_AM_PODS   space-separated Alertmanager pod names, ONE PER REPLICA; the alert-delivery
#                 test is skipped when empty (Alertmanager replicas do not share alerts, so
#                 every one must be queried)
#   DECKARD_E2E_MUTATE=1   also run the tests that change state (acknowledge/reopen/rescan/sync, ingest self-test)
#   DECKARD_NOTIFY_MIN_SEVERITY  the configured notification floor (default info)
# Extra arguments are passed to `go test` (for example: -run TestPagination -v).
set -eu
ctx=${E2E_CONTEXT:?set E2E_CONTEXT to the kubectl context running deckard}
ns=${E2E_NS:-deckard}
secret=${E2E_SECRET:-deckard-secrets}
am_ns=${E2E_AM_NS:-monitoring}
am_pods=${E2E_AM_PODS-}
here=${0:A:h}

pids=()
cleanup() { for p in $pids; do kill $p 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

token=$(kubectl --context $ctx -n $ns get secret $secret -o jsonpath='{.data.DECKARD_ADMIN_TOKEN}' | base64 -d)
kubectl --context $ctx -n $ns port-forward svc/deckard 18080:80 18090:9090 >/dev/null 2>&1 & pids+=($!)
am_urls=""
port=19100
for pod in ${=am_pods}; do
  port=$((port + 1))
  kubectl --context $ctx -n $am_ns port-forward pod/$pod $port:9093 >/dev/null 2>&1 & pids+=($!)
  am_urls="${am_urls:+$am_urls,}http://127.0.0.1:$port"
done
sleep 5

export DECKARD_URL=http://127.0.0.1:18080
export DECKARD_METRICS_URL=http://127.0.0.1:18090
export DECKARD_TOKEN=$token
export ALERTMANAGER_URLS=$am_urls
cd $here
go test -tags staging -count=1 -timeout 20m "$@" ./...
