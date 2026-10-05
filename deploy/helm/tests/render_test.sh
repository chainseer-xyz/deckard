#!/usr/bin/env zsh
# Renders the chart under several value sets and asserts key invariants.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
check() { # name, expected-substring, rendered
  if print -r -- "$3" | grep -qF -- "$2"; then print "ok   $1"; else print "FAIL $1 (missing: $2)"; fail=1; fi
}
absent() {
  if print -r -- "$3" | grep -qF -- "$2"; then print "FAIL $1 (unexpected: $2)"; fail=1; else print "ok   $1"; fi
}
expect_error() { # name, expected message, args...
  local name=$1 msg=$2; shift 2
  if out=$(helm template t deckard "$@" 2>&1); then print "FAIL $name (rendered but should fail)"; fail=1
  elif print -r -- "$out" | grep -qF -- "$msg"; then print "ok   $name"; else print "FAIL $name (wrong error: $out)"; fail=1; fi
}

# Inspect individual route documents/rules so another resource cannot make an
# assertion pass. Keep this dependency-free for the Helm CI job.
http_route() { # rendered, metadata.name
  print -r -- "$1" | awk -v name="$2" '
    function emit() { if (d ~ /kind: HTTPRoute/ && index(d, "\n  name: " name "\n")) print d }
    /^---/ { emit(); d=""; next } { d = d $0 "\n" } END { emit() }'
}
http_route_rule() { # route document, one-based rule index
  print -r -- "$1" | awk -v wanted="$2" '
    /^    - matches:/ { rule++ } rule == wanted { print }'
}
http_route_parents() { # route document
  print -r -- "$1" | awk '
    /^  parentRefs:/ { parents=1; next } /^  [a-zA-Z]/ { parents=0 } parents { print }'
}
check_count() { # name, line regex, expected count, rendered
  local count
  count=$(print -r -- "$4" | awk -v pattern="$2" '$0 ~ pattern { n++ } END { print n+0 }')
  if [[ $count == "$3" ]]; then print "ok   $1"; else print "FAIL $1 (count: $count, expected: $3)"; fail=1; fi
}

cnpg=$(helm template t deckard --set database.cnpg.enabled=true)
check "cnpg cluster rendered"        "postgresql.cnpg.io/v1" "$cnpg"
check "db url from cnpg secret"      "t-deckard-db-app" "$cnpg"
check "json logging in config"       "format: json" "$cnpg"
check "non-root"                     "runAsNonRoot: true" "$cnpg"
check "read-only rootfs"             "readOnlyRootFilesystem: true" "$cnpg"
absent "no cpu limit by default"     "cpu: " "$(print -r -- "$cnpg" | awk "/limits:/{f=1} f&&/cpu/{print} /requests:/{f=0}")"
check "roles env"                    "api,scheduler,worker" "$cnpg"
# deckard drains for 30s then cancels for up to ~12s; Kubernetes' default 30s
# grace would SIGKILL it mid-cancel and orphan running jobs.
check "termination grace default"    "terminationGracePeriodSeconds: 60" "$cnpg"
grace=$(helm template t deckard --set database.cnpg.enabled=true --set worker.enabled=true --set "roles={api,scheduler}" --set terminationGracePeriodSeconds=120)
if [[ $(print -r -- "$grace" | grep -c "terminationGracePeriodSeconds: 120") == 2 ]]; then print "ok   termination grace override on server and worker"; else print "FAIL termination grace override on server and worker"; fail=1; fi

# extraSpec may replace bootstrap (e.g. recovery from a backup) or storage:
# appending them after the defaults would render duplicate mapping keys.
cnpgrec=$(helm template t deckard --set database.cnpg.enabled=true \
  --set database.cnpg.extraSpec.bootstrap.recovery.source=old \
  --set database.cnpg.extraSpec.storage.size=20Gi)
if [[ $(print -r -- "$cnpgrec" | grep -c "^  bootstrap:") == 1 ]]; then print "ok   cnpg extraSpec bootstrap replaces the default"; else print "FAIL cnpg extraSpec bootstrap duplicated"; fail=1; fi
if [[ $(print -r -- "$cnpgrec" | grep -c "^  storage:") == 1 ]]; then print "ok   cnpg extraSpec storage replaces the default"; else print "FAIL cnpg extraSpec storage duplicated"; fail=1; fi
check  "cnpg recovery bootstrap kept"  "source: old" "$cnpgrec"
absent "cnpg no initdb with recovery"  "initdb:" "$cnpgrec"
check  "cnpg default bootstrap"        "initdb:" "$cnpg"

ext=$(helm template t deckard --set database.existingSecret=pg --set database.existingSecretKey=dsn)
absent "no cnpg when disabled"       "postgresql.cnpg.io/v1" "$ext"
check "external secret key"          "key: dsn" "$ext"

split=$(helm template t deckard --set database.cnpg.enabled=true --set worker.enabled=true --set "roles={api,scheduler}")
check "worker deployment"            "name: t-deckard-worker" "$split"
# Only the api role listens on the http port; a worker probing /healthz there
# is refused and restart-looped. Workers probe the metrics listener instead.
splitworker=$(print -r -- "$split" | awk 'function emit(){ if (d ~ /kind: Deployment/ && d ~ /name: t-deckard-worker\n/) print d }
  /^---/{ emit(); d=""; next } { d = d $0 "\n" } END { emit() }')
absent "worker does not probe the api port" "/healthz" "$splitworker"
check  "worker probes the metrics port" "tcpSocket" "$splitworker"
if [[ $(print -r -- "$split" | grep -c "path: /healthz") == 1 ]]; then print "ok   server keeps http probes"; else print "FAIL server keeps http probes"; fail=1; fi
noapi=$(helm template t deckard --set database.cnpg.enabled=true --set "roles={scheduler,worker}")
absent "api-less server does not probe the api port" "/healthz" "$noapi"

sm=$(helm template t deckard --set database.cnpg.enabled=true --set metrics.serviceMonitor.enabled=true)
check "servicemonitor"               "kind: ServiceMonitor" "$sm"

np=$(helm template t deckard --set database.cnpg.enabled=true)
check "networkpolicy on by default"  "kind: NetworkPolicy" "$np"
check "networkpolicy egress open"    "- {}" "$np"
check "networkpolicy same namespace" "podSelector: {}" "$np"
check "networkpolicy ingress ctrl"   "kubernetes.io/metadata.name: ingress-nginx" "$np"
check "networkpolicy prometheus"     "kubernetes.io/metadata.name: monitoring" "$np"
check "networkpolicy api port"       "port: 8080" "$np"
check "networkpolicy metrics port"   "port: 9090" "$np"
nppol=$(helm template t deckard --set database.cnpg.enabled=true \
  --set networkPolicy.ingressController.namespaceSelector.matchLabels.team=edge \
  --set networkPolicy.prometheus.namespaceSelector.matchLabels.team=obs)
check "networkpolicy custom ingress selector" "team: edge" "$nppol"
check "networkpolicy custom prometheus selector" "team: obs" "$nppol"
npoff=$(helm template t deckard --set database.cnpg.enabled=true --set networkPolicy.enabled=false)
absent "networkpolicy can be disabled" "kind: NetworkPolicy" "$npoff"

smtok=$(helm template t deckard --set database.cnpg.enabled=true --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.bearerTokenSecret.name=deckard-metrics --set metrics.serviceMonitor.bearerTokenSecret.key=token)
check "servicemonitor bearer secret" "bearerTokenSecret:" "$smtok"
check "servicemonitor bearer secret name" "name: deckard-metrics" "$smtok"
absent "servicemonitor no bearer by default" "bearerTokenSecret" "$sm"

expect_error "cpu limit rejected"    "resources.limits.cpu must not be set" --set database.cnpg.enabled=true --set resources.limits.cpu=1
expect_error "worker cpu limit rejected" "worker.resources.limits.cpu" --set database.cnpg.enabled=true --set worker.enabled=true --set "roles={api}" --set worker.resources.limits.cpu=2
expect_error "no database rejected"  "no database configured"
# The DSN is a secret: supplying it the ways values.yaml recommends must render.
for args in "--set secretEnv.DECKARD_DATABASE__URL=postgres://x" \
            "--set extraEnv[0].name=DECKARD_DATABASE__URL --set extraEnv[0].valueFrom.secretKeyRef.name=pg --set extraEnv[0].valueFrom.secretKeyRef.key=dsn" \
            "--set config.database.url=postgres://x"; do
  if helm template t deckard ${(z)args} >/dev/null 2>&1; then print "ok   database via $args"; else print "FAIL database via $args rejected"; fail=1; fi
done
expect_error "worker+worker role rejected" "remove \"worker\" from roles" --set database.cnpg.enabled=true --set worker.enabled=true

dash=$(helm template t deckard --set database.cnpg.enabled=true --set metrics.dashboard.enabled=true)
check "dashboard configmap" "grafana_dashboard: \"1\"" "$dash"
check "dashboard json embedded" "deckard-surface" "$dash"
absent "dashboard has no annotations by default" "grafana_folder" "$dash"
dashf=$(helm template t deckard --set database.cnpg.enabled=true --set metrics.dashboard.enabled=true \
  --set metrics.dashboard.annotations.grafana_folder=Security)
check "dashboard folder annotation" "grafana_folder: Security" "$dashf"

# Gateway API route: off by default, needs a parentRef, wires the Service and the NetworkPolicy.
absent "no HTTPRoute by default" "kind: HTTPRoute" "$cnpg"
expect_error "httpRoute without parentRefs rejected" "httpRoute.enabled needs httpRoute.parentRefs" \
  --set database.cnpg.enabled=true --set httpRoute.enabled=true
gwargs=(--set database.cnpg.enabled=true --set httpRoute.enabled=true
  --set 'httpRoute.parentRefs[0].name=gw' --set 'httpRoute.parentRefs[0].namespace=gateway-system'
  --set 'httpRoute.parentRefs[0].sectionName=https' --set 'httpRoute.hostnames[0]=deckard.example.com'
  --set 'httpRoute.annotations.external-dns\.alpha\.kubernetes\.io/hostname=deckard.example.com')
gw=$(helm template t deckard "${gwargs[@]}")
check "httproute rendered"            "kind: HTTPRoute" "$gw"
check "httproute parent gateway"      "sectionName: https" "$gw"
check "httproute hostname"            "- deckard.example.com" "$gw"
check "httproute backend is service"  "name: t-deckard" "$gw"
check "httproute backend port"        "port: 80" "$gw"
check "httproute annotations"         "external-dns.alpha.kubernetes.io/hostname: deckard.example.com" "$gw"
check "netpol admits the gateway ns"  'kubernetes.io/metadata.name: "gateway-system"' "$gw"
absent "no redirect route by default" "-redirect" "$gw"
gwroute=$(http_route "$gw" t-deckard)
gwparents=$(http_route_parents "$gwroute")
check "parent group defaults explicitly" "group: gateway.networking.k8s.io" "$gwparents"
check "parent kind defaults explicitly" "kind: Gateway" "$gwparents"
check "parent namespace preserved" "namespace: gateway-system" "$gwparents"
check "parent listener preserved" "sectionName: https" "$gwparents"
check "backend core group explicit" 'group: ""' "$gwroute"
check "backend service kind explicit" "kind: Service" "$gwroute"
check "backend weight explicit" "weight: 1" "$gwroute"
check_count "one normal route rule by default" '^    - matches:' 1 "$gwroute"
absent "SSE route opt-in by default" "/api/v1/events" "$gwroute"
absent "normal route keeps default timeouts" "timeouts:" "$gwroute"
expect_error "redirect without parentRefs rejected" "httpRedirect.enabled needs httpRoute.httpRedirect.parentRefs" \
  "${gwargs[@]}" --set httpRoute.httpRedirect.enabled=true
gwr=$(helm template t deckard "${gwargs[@]}" --set httpRoute.httpRedirect.enabled=true \
  --set 'httpRoute.httpRedirect.parentRefs[0].name=gw' --set 'httpRoute.httpRedirect.parentRefs[0].sectionName=http')
check "redirect route rendered"       "name: t-deckard-redirect" "$gwr"
check "redirect is to https"          "scheme: https" "$gwr"
check "redirect status"               "statusCode: 301" "$gwr"
gwredirect=$(http_route "$gwr" t-deckard-redirect)
check "redirect parent group explicit" "group: gateway.networking.k8s.io" "$gwredirect"
check "redirect parent kind explicit" "kind: Gateway" "$gwredirect"
check "redirect listener preserved" "sectionName: http" "$gwredirect"
check "redirect default match explicit" 'type: PathPrefix
            value: "/"' "$gwredirect"
absent "redirect keeps default timeouts" "timeouts:" "$gwredirect"

# Only the exact events endpoint may disable request timeouts; ordinary API
# routes and the plaintext redirect must retain the controller's defaults.
gwsse=$(helm template t deckard "${gwargs[@]}" --set httpRoute.sse.enabled=true \
  --set httpRoute.httpRedirect.enabled=true --set 'httpRoute.httpRedirect.parentRefs[0].name=gw')
gwsseroute=$(http_route "$gwsse" t-deckard)
gwssefirst=$(http_route_rule "$gwsseroute" 1)
gwsseother=$(http_route_rule "$gwsseroute" 2)
check_count "SSE adds exactly one rule" '^    - matches:' 2 "$gwsseroute"
check "SSE exact events rule comes first" 'type: Exact
            value: "/api/v1/events"' "$gwssefirst"
check "SSE request timeout disabled" "request: 0s" "$gwssefirst"
check "SSE backend request timeout disabled" "backendRequest: 0s" "$gwssefirst"
check "SSE backend core group explicit" 'group: ""' "$gwssefirst"
check "SSE backend service kind explicit" "kind: Service" "$gwssefirst"
check "SSE backend weight explicit" "weight: 1" "$gwssefirst"
check "normal rule follows SSE" 'type: PathPrefix
            value: "/"' "$gwsseother"
absent "non-SSE rule keeps default timeouts" "timeouts:" "$gwsseother"
absent "events endpoint not repeated in normal rule" "/api/v1/events" "$gwsseother"
gwsseredirect=$(http_route "$gwsse" t-deckard-redirect)
absent "SSE opt-in leaves redirect timeouts alone" "timeouts:" "$gwsseredirect"
absent "SSE opt-in leaves redirect matches alone" "/api/v1/events" "$gwsseredirect"

gwcustom=$(helm template t deckard "${gwargs[@]}" --set httpRoute.sse.enabled=true \
  --set service.port=8088 --set httpRoute.path.type=Exact --set httpRoute.path.value=/api/v1/stats \
  --set-json 'httpRoute.parentRefs=[{"name":"core-parent","group":"","kind":"Service","namespace":"core-ns","sectionName":"https","port":443},{"name":"custom-parent","group":"example.net","kind":"CustomGateway","namespace":"custom-ns","sectionName":"blue","port":8443}]' \
  --set httpRoute.httpRedirect.enabled=true \
  --set-json 'httpRoute.httpRedirect.parentRefs=[{"name":"core-redirect","group":"","kind":"Service","namespace":"redirect-ns","sectionName":"http","port":80}]')
gwcustomroute=$(http_route "$gwcustom" t-deckard)
gwcustomparents=$(http_route_parents "$gwcustomroute")
check "explicit empty parent group preserved" 'group: ""' "$gwcustomparents"
check "explicit core parent kind preserved" "kind: Service" "$gwcustomparents"
check "explicit custom parent group preserved" "group: example.net" "$gwcustomparents"
check "explicit custom parent kind preserved" "kind: CustomGateway" "$gwcustomparents"
check "custom parent namespace preserved" "namespace: custom-ns" "$gwcustomparents"
check "custom parent section preserved" "sectionName: blue" "$gwcustomparents"
check "custom parent port preserved" "port: 8443" "$gwcustomparents"
absent "explicit parent group not overwritten" "group: gateway.networking.k8s.io" "$gwcustomparents"
check_count "both SSE and normal backends keep the custom port" 'port: 8088' 2 "$gwcustomroute"
gwcustomother=$(http_route_rule "$gwcustomroute" 2)
check "custom normal route match preserved" 'type: Exact
            value: "/api/v1/stats"' "$gwcustomother"
absent "custom normal route keeps default timeouts" "timeouts:" "$gwcustomother"
gwcustomredirect=$(http_route "$gwcustom" t-deckard-redirect)
gwcustomredirectparents=$(http_route_parents "$gwcustomredirect")
check "redirect explicit empty parent group preserved" 'group: ""' "$gwcustomredirectparents"
check "redirect explicit parent kind preserved" "kind: Service" "$gwcustomredirectparents"
check "redirect explicit parent namespace preserved" "namespace: redirect-ns" "$gwcustomredirectparents"
check "redirect explicit parent port preserved" "port: 80" "$gwcustomredirectparents"
absent "custom redirect keeps default timeouts" "timeouts:" "$gwcustomredirect"

# Refreshed reference data lives under /var/lib/deckard: a volume is always mounted
# (emptyDir without persistence, the PVC with it) so the root FS can stay read-only.
check "data dir mounted by default"  "mountPath: /var/lib/deckard" "$cnpg"
check "data dir is an emptyDir"      "- { name: data, emptyDir: {} }" "$cnpg"
absent "no PVC by default"           "persistentVolumeClaim" "$cnpg"
pvc=$(helm template t deckard --set database.cnpg.enabled=true --set persistence.enabled=true)
check "data dir PVC when persistent" "claimName: t-deckard-data" "$pvc"
check "data dir mounted with PVC"    "mountPath: /var/lib/deckard" "$pvc"
absent "no emptyDir data with PVC"   "- { name: data, emptyDir: {} }" "$pvc"
splitdata=$(helm template t deckard --set database.cnpg.enabled=true --set worker.enabled=true --set "roles={api,scheduler}")
check "worker mounts data dir"       "mountPath: /var/lib/deckard" "$(print -r -- "$splitdata" | awk '/name: t-deckard-worker/{f=1} f')"

# --- nuclei template updater: writable state volume on a read-only root --------
nu=$(helm template t deckard --set database.cnpg.enabled=true)
check  "nuclei volume mounted at the update dir"  'mountPath: "/var/lib/deckard/nuclei-templates"' "$nu"
check  "nuclei volume is an emptyDir by default"  "name: nuclei-templates
          emptyDir:
            sizeLimit: 2Gi" "$nu"
absent "no nuclei PVC by default"                 "t-deckard-nuclei" "$nu"
check  "root filesystem stays read-only (updater on)" "readOnlyRootFilesystem: true" "$nu"
check  "HOME points at a writable path"           "name: HOME, value: /tmp" "$nu"
check  "updater enabled in the rendered config"   "    nuclei:
      update:
        enabled: true
        interval: 6h" "$nu"
check  "new-template scans enabled in config"     "run_new_templates: true" "$nu"

nupvc=$(helm template t deckard --set database.cnpg.enabled=true --set nuclei.persistence.enabled=true --set nuclei.persistence.size=5Gi)
check  "nuclei PVC rendered"                      "name: t-deckard-nuclei" "$nupvc"
check  "nuclei PVC size"                          "storage: 5Gi" "$nupvc"
check  "nuclei volume uses the claim"             "claimName: t-deckard-nuclei" "$nupvc"
check  "read-only rootfs with persistence"        "readOnlyRootFilesystem: true" "$nupvc"

nuex=$(helm template t deckard --set database.cnpg.enabled=true --set nuclei.persistence.enabled=true --set nuclei.persistence.existingClaim=mine)
absent "existing claim: no PVC created"           "name: t-deckard-nuclei" "$nuex"
check  "existing claim used"                      "claimName: mine" "$nuex"

nucm=$(helm template t deckard --set database.cnpg.enabled=true --set nuclei.customTemplates.configMap=custom-pack)
check  "custom ConfigMap mounted"                 "configMap: { name: custom-pack }" "$nucm"
check  "custom path configured"                    "/var/lib/deckard/custom-templates" "$nucm"
nupack=$(helm template t deckard --set database.cnpg.enabled=true --set nuclei.customTemplates.existingClaim=custom-pvc)
check  "custom PVC mounted"                        "claimName: custom-pvc" "$nupack"
expect_error "custom sources mutually exclusive"   "mutually exclusive" --set database.cnpg.enabled=true --set nuclei.customTemplates.configMap=custom-pack --set nuclei.customTemplates.existingClaim=custom-pvc

# A ReadWriteOnce claim cannot back several worker replicas: workers keep an emptyDir.
nuw=$(helm template t deckard --set database.cnpg.enabled=true --set worker.enabled=true --set "roles={api,scheduler}" --set nuclei.persistence.enabled=true)
if [[ $(print -r -- "$nuw" | grep -c "claimName: t-deckard-nuclei") == 1 ]]; then print "ok   nuclei claim backs the main Deployment only"; else print "FAIL nuclei claim must back the main Deployment only"; fail=1; fi
if [[ $(print -r -- "$nuw" | grep -c "name: nuclei-templates$") == 2 ]]; then print "ok   both Deployments mount a nuclei volume"; else print "FAIL both Deployments need a nuclei volume"; fail=1; fi

nuoff=$(helm template t deckard --set database.cnpg.enabled=true --set config.nuclei.update.enabled=false)
absent "opt-out: no nuclei volume"                "name: nuclei-templates" "$nuoff"
absent "opt-out: no nuclei PVC"                   "t-deckard-nuclei" "$(helm template t deckard --set database.cnpg.enabled=true --set config.nuclei.update.enabled=false --set nuclei.persistence.enabled=true)"
check  "opt-out reaches the config"               "    nuclei:
      update:
        enabled: false" "$nuoff"
check  "opt-out keeps the rootfs read-only"       "readOnlyRootFilesystem: true" "$nuoff"

nudir=$(helm template t deckard --set database.cnpg.enabled=true --set config.nuclei.update.dir=/data/nt)
check  "custom update dir is the mount path"      'mountPath: "/data/nt"' "$nudir"

# --- every writable default directory lives under a mounted volume --------------
# The root filesystem is read-only. The defaults in internal/config are the
# source of truth, so read them from there: a new writable dir whose default is
# not covered by a mount fails here instead of at runtime.
cfgsrc=../../internal/config/config.go
default_dir() { grep -E "^[[:space:]]*\"$1\":" $cfgsrc | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)",?$/\1/'; }
mounts=$(print -r -- "$cnpg" | awk '/volumeMounts:/{f=1;next} /^  volumes:/{f=0} f' | grep -oE 'mountPath: "?[^" ,}]+' | sed -E 's/mountPath: "?//' | grep -vE '^(/etc/deckard|/tmp)$')
for key in nuclei.update.dir refdata.dir vulnintel.dir; do
  d=$(default_dir $key)
  if [[ -z $d ]]; then print "FAIL default for $key not found in $cfgsrc"; fail=1; continue; fi
  covered=0
  for m in ${(f)mounts}; do [[ $d == $m || $d == $m/* ]] && covered=1; done
  if (( covered )); then print "ok   default $key ($d) is under a mounted volume"; else print "FAIL default $key ($d) is not under a mounted volume"; fail=1; fi
done

exit $fail
