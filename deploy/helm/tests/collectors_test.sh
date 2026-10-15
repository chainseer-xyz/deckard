#!/usr/bin/env zsh
# Real Helm renders; requires Helm, yq v4 and jq. No cluster or scanner is used.
# ShellCheck has no zsh parser; this script deliberately uses its Bash-compatible subset.
# Expected-error assertions call render in conditions; render returns explicitly on failure.
# shellcheck shell=bash disable=SC2310
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in helm yq jq; do command -v "$tool" >/dev/null || { print -u2 "missing dependency: $tool"; exit 1; }; done
fail=0
assert() {
  if jq -e "$2" >/dev/null <<< "$3"; then print -r -- "ok   $1";
  else print -u2 -r -- "FAIL $1"; fail=1; fi
}
render() {
  local rendered
  rendered=$(helm template collectors deckard --namespace security --set database.cnpg.enabled=true -f - <<< "$1") || return
  yq -o=json -I=0 eval-all '[.]' - <<< "$rendered"
}
render_mutation() {
  local changed
  changed=$(jq -e "$1" <<< "$2") || return
  render "$changed"
}
reject() { # name, expected message, jq mutation, base values JSON
  local output changed
  changed=$(jq -e "$3" <<< "$4") || return
  if output=$(render "$changed" 2>&1); then print -u2 -r -- "FAIL $1 (unexpectedly rendered)"; fail=1
  elif [[ $output == *"$2"* ]]; then print -r -- "ok   $1"
  else print -u2 -r -- "FAIL $1 (wrong error: $output)"; fail=1; fi
}
values=$(jq -n '{collectors:{enabled:true,ingest:{image:"ghcr.io/chainseer-xyz/deckard@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",tokenSecretRef:{name:"collector-ingest",key:"token"}},jobs:[{name:"web-image",type:"trivy",schedule:"0 */6 * * *",scope:"image:web:linux-amd64",platform:"linux/amd64",image:"ghcr.io/aquasecurity/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222",target:"registry.example.com/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}}')
default_render=$(render '{}')
assert 'collectors are disabled by default' '[.[]|select(.kind=="CronJob")]|length==0' "$default_render"
trivy=$(render "$values")
assert 'Trivy scheduled collector is opt-in' '[.[]|select(.kind=="CronJob" and .metadata.name=="collectors-deckard-collect-web-image")]|length==1' "$trivy"
job=$(jq '.[]|select(.kind=="CronJob")' <<< "$trivy")
assert 'scheduled work is bounded and never overlaps' '.spec.concurrencyPolicy=="Forbid" and .spec.startingDeadlineSeconds==600 and .spec.jobTemplate.spec.backoffLimit==0 and .spec.jobTemplate.spec.activeDeadlineSeconds==1800 and .spec.jobTemplate.spec.ttlSecondsAfterFinished==86400 and .spec.successfulJobsHistoryLimit==2 and .spec.failedJobsHistoryLimit==2' "$job"
assert 'scanner succeeds before ingest can start' '.spec.jobTemplate.spec.template.spec|(.initContainers|length)==1 and (.containers|length)==1 and .initContainers[0].name=="scanner" and .containers[0].name=="ingest" and .restartPolicy=="Never"' "$job"
assert 'Trivy uses registry only, complete vulnerability scan and immutable target' '.spec.jobTemplate.spec.template.spec.initContainers[0].args|index("remote")!=null and index("vuln")!=null and index("--severity")==null and index("--ignore-unfixed")==null and index("--exit-code")!=null and .[-1]=="registry.example.com/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$job"
# shellcheck disable=SC2016 # Assert the literal scanner script, not shell expansion.
assert 'oversized or empty reports never upload' '.spec.jobTemplate.spec.template.spec.initContainers[0].args[0]|contains("test -s /report/result.json") and contains("test \"$bytes\" -le 67108864")' "$job"
assert 'reports are fresh per pod and read-only in uploader' '.spec.jobTemplate.spec.template.spec|(.volumes[]|select(.name=="report").emptyDir.sizeLimit)=="64Mi" and (.containers[0].volumeMounts[]|select(.name=="report").readOnly)==true and ([.volumes[]|has("hostPath") or has("persistentVolumeClaim")]|any|not)' "$job"
assert 'scanner never receives ingest credentials' '.spec.jobTemplate.spec.template.spec|.automountServiceAccountToken==false and (.initContainers[0].env|map(.name))==["HOME"] and .containers[0].env[0].valueFrom.secretKeyRef.name=="collector-ingest" and ([.initContainers[],.containers[]]|all(has("envFrom")|not))' "$job"
assert 'collector containers are restricted with no CPU limits' '.spec.jobTemplate.spec.template.spec|.securityContext.runAsNonRoot and .securityContext.runAsUser==65532 and .securityContext.seccompProfile.type=="RuntimeDefault" and ([.initContainers[],.containers[]]|all(.securityContext.readOnlyRootFilesystem and (.securityContext.allowPrivilegeEscalation|not) and .securityContext.capabilities.drop==["ALL"] and (.resources.limits|has("cpu")|not)))' "$job"
assert 'collector policy cannot inherit Deckard open egress' '.spec.jobTemplate.spec.template.metadata.labels."app.kubernetes.io/name"=="deckard-collector"' "$job"
assert 'each collector gets a separate network policy' '[.[]|select(.kind=="NetworkPolicy" and .metadata.name=="collectors-deckard-collect-web-image" and .spec.podSelector.matchLabels."app.kubernetes.io/name"=="deckard-collector")]|length==1' "$trivy"
kube_values=$(jq '.collectors.jobs=[{name:"cluster-posture",type:"kubescape",schedule:"15 */6 * * *",scope:"k8s:example",image:"quay.io/kubescape/kubescape-cli@sha256:d575d4f2281473ce539d41053d63482a4e9e07f35d987206b2bac79b2c9ad4bc"}]' <<< "$values")
if kube=$(render "$kube_values"); then
  assert 'Kubescape collector renders' '[.[]|select(.kind=="CronJob")]|length==1' "$kube"
  kube_job=$(jq '.[]|select(.kind=="CronJob")' <<< "$kube")
  assert 'Kubescape uses bundled policies and never submits or probes hosts/images' '.spec.jobTemplate.spec.template.spec.initContainers[0].args|index("--use-default")!=null and index("--keep-local")!=null and index("--submit=false")!=null and index("--host-scan=false")!=null and index("--scan-images=false")!=null and index("Secret,ConfigMap")!=null and index("v2")!=null' "$kube_job"
  assert 'restricted Kubescape assessment can never resolve absent findings' '.spec.jobTemplate.spec.template.spec.containers[0].args|index("--incomplete")!=null' "$kube_job"
  assert 'Kubescape defaults to both approved frameworks' '.spec.jobTemplate.spec.template.spec.initContainers[0].args|.[index("framework")+1]=="nsa,mitre"' "$kube_job"
  for framework in nsa mitre; do
    framework_values=$(jq --arg framework "$framework" '.collectors.jobs[0].frameworks=[$framework]' <<< "$kube_values")
    selected=$(render "$framework_values")
    assert "Kubescape selects only $framework and remains incomplete" "[.[]|select(.kind==\"CronJob\").spec.jobTemplate.spec.template.spec]|all((.initContainers[0].args|.[index(\"framework\")+1]==\"$framework\") and (.containers[0].args|index(\"--incomplete\")!=null))" "$selected"
  done
  assert 'Kubernetes token is projected and mounted only in scanner' '.spec.jobTemplate.spec.template.spec|.automountServiceAccountToken==false and (.volumes[]|select(.name=="kube-api").projected.sources[0].serviceAccountToken.expirationSeconds)==3600 and ([.initContainers[0].volumeMounts[]|select(.name=="kube-api")]|length)==1 and ([.containers[0].volumeMounts[]|select(.name=="kube-api")]|length)==0' "$kube_job"
  assert 'Kubescape RBAC excludes secrets, proxy, exec and mutation' '[.[]|select(.kind=="ClusterRole" and .metadata.labels."app.kubernetes.io/component"=="collector").rules[]]|all(.verbs==["get","list"] and (.apiGroups|index("*")==null) and (.resources|index("*")==null and index("secrets")==null and index("configmaps")==null and index("pods/exec")==null and index("nodes/proxy")==null))' "$kube"
  scoped=$(render_mutation '.collectors.jobs[0].namespaces=["apps","edge"]' "$kube_values")
  assert 'namespace-scoped RBAC never grants global workload reads' '[.[]|select(.kind=="RoleBinding")|.metadata.namespace]|sort==["apps","edge"]' "$scoped"
  assert 'namespace scope still keeps separate read-only cluster metadata' '[.[]|select(.kind=="ClusterRoleBinding" and .metadata.labels."app.kubernetes.io/component"=="collector")]|length==1' "$scoped"
  assert 'namespace scope reaches actual Kubescape invocation' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec.initContainers[0].args[]]|index("apps,edge")!=null' "$scoped"
else
  print -u2 'FAIL Kubescape collector renders'; fail=1
fi
both_frameworks=$(render_mutation '.collectors.jobs[0].frameworks=["mitre","nsa"]' "$kube_values")
assert 'Kubescape accepts both approved frameworks in explicit order' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec.initContainers[0].args]|all(.[index("framework")+1]=="mitre,nsa")' "$both_frameworks"
reject 'Kubescape refuses an empty framework list' 'Kubescape frameworks must be a nonempty unique subset of nsa, mitre' '.collectors.jobs[0].frameworks=[]' "$kube_values"
reject 'Kubescape refuses unknown frameworks' 'Kubescape frameworks must be a nonempty unique subset of nsa, mitre' '.collectors.jobs[0].frameworks=["cis"]' "$kube_values"
reject 'Kubescape refuses duplicate frameworks' 'Kubescape frameworks must be a nonempty unique subset of nsa, mitre' '.collectors.jobs[0].frameworks=["nsa","nsa"]' "$kube_values"
reject 'Kubescape refuses scalar framework values' 'Kubescape frameworks must be a nonempty unique subset of nsa, mitre' '.collectors.jobs[0].frameworks="nsa"' "$kube_values"
reject 'Kubescape refuses null framework values' 'Kubescape frameworks must be a nonempty unique subset of nsa, mitre' '.collectors.jobs[0].frameworks=null' "$kube_values"
other_frameworks=$(render_mutation '.collectors.jobs[0].frameworks=["not-a-kubescape-framework"]' "$values")
assert 'Kubescape framework settings never change another collector command' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec.initContainers[0].args]|all(index("framework")==null and index("image")!=null)' "$other_frameworks"
prowler_values=$(jq '.collectors.jobs=[{name:"prowler-pull",type:"prowler-app",schedule:"0 */6 * * *",apiURL:"http://prowler-api.prowler.svc:8080",apiKeySecretRef:{name:"prowler-reader",key:"api-key"},providerTypes:["aws","gcp"],providerUIDs:["123456789012"],maxScanAge:"24h",minSeverity:"low"}]' <<< "$values")
if prowler=$(render "$prowler_values"); then
  assert 'existing Prowler App is pulled without a cloud scanner' '[.[]|select(.kind=="CronJob")]|length==1' "$prowler"
else
  print -u2 'FAIL existing Prowler App is pulled without a cloud scanner'; fail=1
fi
alerts=$(render_mutation '.collectors.alerts={enabled:true,maxAgeSeconds:90000}' "$values")
assert 'optional collector freshness alerts render' '[.[]|select(.kind=="PrometheusRule")]|length==1' "$alerts"
assert 'Trivy assessment platform cannot depend on scheduled node' '.spec.jobTemplate.spec.template.spec.initContainers[0].args|index("--platform")!=null and index("linux/amd64")!=null' "$job"
assert 'Prowler pulls only selected providers and keeps credentials on uploader' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|all((has("initContainers")|not) and .automountServiceAccountToken==false and (.containers[0].args|index("aws,gcp")!=null and index("123456789012")!=null and index("24h")!=null and index("low")!=null) and (.containers[0].env|map(.name)|sort)==["DECKARD_TOKEN","PROWLER_API_KEY"])' "$prowler"
assert 'Trivy freshness refers only to this CronJob and handles never-successful runs' '[.[]|select(.kind=="PrometheusRule").spec.groups[].rules[]|select(.alert=="DeckardCollectorStale").expr]|all(contains("90000") and contains("kube_cronjob_created") and contains("collectors-deckard-collect-web-image") and contains("kube_cronjob_spec_suspend"))' "$alerts"
reject 'mutable scanner tags are refused' 'immutable repository@sha256' '.collectors.jobs[0].image="ghcr.io/aquasecurity/trivy:latest"' "$values"
reject 'mutable target tags are refused' 'immutable repository@sha256' '.collectors.jobs[0].target="registry.example.com/web:latest"' "$values"
reject 'mutable upload images are refused' 'immutable repository@sha256' '.collectors.ingest.image="ghcr.io/chainseer-xyz/deckard:latest"' "$values"
reject 'missing upload secret is refused' 'tokenSecretRef.name is required' 'del(.collectors.ingest.tokenSecretRef)' "$values"
reject 'duplicate collector names are refused' 'collector names must be unique' '.collectors.jobs += .collectors.jobs' "$values"
reject 'scanner CPU limits are refused including zero' 'resources.limits.cpu must not be set' '.collectors.jobs[0].resources.limits.cpu=0' "$values"
reject 'uploader CPU limits are refused' 'resources.limits.cpu must not be set' '.collectors.jobs[0].ingestResources.limits.cpu="100m"' "$values"
reject 'missing scan platform is refused' 'Trivy collector platform is required' 'del(.collectors.jobs[0].platform)' "$values"
reject 'invalid scan platform is refused' 'Trivy platform must be linux/amd64 or linux/arm64' '.collectors.jobs[0].platform="garbage"' "$values"
reject 'credentials in upload URLs are refused at render time' 'collector URLs must use http(s) without credentials' '.collectors.ingest.url="https://user:password@example.com"' "$values"
reject 'nonpositive job deadlines are refused' 'collector deadlines and TTL must be positive' '.collectors.jobs[0].activeDeadlineSeconds=-1' "$values"
off=$(render_mutation '.collectors.jobs[0].enabled=false' "$values")
assert 'disabled jobs create no collector resources' '[.[]|select(.metadata.labels."app.kubernetes.io/component"=="collector")]|length==0' "$off"
custom=$(render_mutation '.collectors.networkPolicy.egress=[{to:[{ipBlock:{cidr:"192.0.2.10/32"}}],ports:[{protocol:"TCP",port:443}]}]|.collectors.jobs[0].egress=[{to:[{ipBlock:{cidr:"198.51.100.10/32"}}],ports:[{protocol:"TCP",port:6443}]}]' "$values")
assert 'collector egress defaults stay bounded; explicit operator rules are retained' '[.[]|select(.kind=="NetworkPolicy" and .metadata.labels."app.kubernetes.io/component"=="collector").spec.egress[]]|length==4 and all(has("to") and has("ports")) and (.[2].to[0].ipBlock.cidr=="192.0.2.10/32") and (.[3].ports[0].port==6443)' "$custom"
assert 'collector instance label cannot match the server open-egress selector' '([.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.metadata.labels."app.kubernetes.io/instance"]|first)!=([.[]|select(.kind=="Deployment").spec.selector.matchLabels."app.kubernetes.io/instance"]|first)' "$trivy"
long_a=$(render_mutation '.fullnameOverride="abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz-one"' "$values")
long_b=$(render_mutation '.fullnameOverride="abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz-two"' "$values")
name_a=$(jq -r '.[]|select(.kind=="CronJob").metadata.name' <<< "$long_a")
name_b=$(jq -r '.[]|select(.kind=="CronJob").metadata.name' <<< "$long_b")
if [[ $name_a != "$name_b" && ${#name_a} -le 52 && ${#name_b} -le 52 ]]; then print 'ok   long release identities remain distinct within CronJob name limits'
else print -u2 'FAIL long release identities remain distinct within CronJob name limits'; fail=1; fi
per_job=$(render_mutation '.collectors.jobs[0].tokenSecretRef={name:"trivy-only",key:"ingest-token"}|.collectors.ingest.tokenSecretRef={}' "$values")
assert 'per-job credentials work without a shared cross-tool token' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec.containers[0].env[]|select(.name=="DECKARD_TOKEN").valueFrom.secretKeyRef]|first=={name:"trivy-only",key:"ingest-token"}' "$per_job"
bbot_values=$(jq '.collectors.jobs=[{name:"passive-discovery",type:"bbot",schedule:"30 */12 * * *",image:"blacklanternsecurity/bbot@sha256:40ed0733e0163feee844d49346eb15e40872fa7008f621358eed9b9a7807382e",source:"bbot-external",targets:["example.com"],modules:["crt","certspotter","hackertarget"]}]' <<< "$values")
if bbot=$(render "$bbot_values"); then
  assert 'BBOT discovery routes only to registered remote source CLI' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec.containers[0].args]|first|.[0:6]==["discovery","ingest","--source","bbot-external","--file","/report/output.json"]' "$bbot"
  assert 'BBOT upstream image is scheduled only on its published architecture' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|first|.nodeSelector=={"kubernetes.io/os":"linux","kubernetes.io/arch":"amd64"}' "$bbot"
  assert 'BBOT has no Kubernetes credential and only uploader has ingest credential' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|first|.automountServiceAccountToken==false and ([.volumes[]|select(.name=="kube-api")]|length)==0 and (.initContainers[0].env|map(.name))==["HOME"] and (.containers[0].env|map(.name))==["DECKARD_TOKEN"]' "$bbot"
  assert 'BBOT config contains only explicit bounded passive modules and targets' '[.[]|select(.kind=="ConfigMap" and .metadata.labels."app.kubernetes.io/component"=="collector").data."config.json"|fromjson]|first=={targets:["example.com"],modules:["crt","certspotter","hackertarget"]}' "$bbot"
  assert 'BBOT final report requires real scan completion, provider success and byte bound' '[.[]|select(.kind=="ConfigMap" and .metadata.labels."app.kubernetes.io/component"=="collector").data."collect.py"]|first|contains("scan.status != \"FINISHED\"") and contains("api_failed") and contains("10 * 1024 * 1024") and contains("os.replace")' "$bbot"
else print -u2 'FAIL BBOT discovery collector renders'; fail=1; fi
reject 'BBOT active or brute force modules are refused' 'BBOT modules must be a nonempty subset of crt, certspotter, hackertarget' '.collectors.jobs[0].modules=["httpx"]' "$bbot_values"
reject 'BBOT URL or IP scan targets are refused' 'BBOT targets must be DNS names' '.collectors.jobs[0].targets=["https://example.com/"]' "$bbot_values"
reject 'BBOT unbounded target sets are refused' 'BBOT requires 1 to 16 explicit DNS targets' '.collectors.jobs[0].targets=[range(0;17)|"target\(.).example.com"]' "$bbot_values"
reject 'BBOT registered source identity is required' 'BBOT collector source is required' 'del(.collectors.jobs[0].source)' "$bbot_values"
reject 'explicit empty per-job secret cannot fall back to global credential' 'tokenSecretRef.name is required' '.collectors.jobs[0].tokenSecretRef={}' "$values"
runtime_values=$(jq '.collectors.jobs=[{name:"runtime-images",type:"trivy-runtime",schedule:"0 */6 * * *",image:"ghcr.io/chainseer-xyz/deckard-trivy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",clusterScope:"k8s:uid:11111111-1111-4111-8111-111111111111:runtime-images",allNamespaces:true,registryAuthSecretRef:{name:"registry-readonly",key:".dockerconfigjson"}}]' <<< "$values")
if runtime=$(render "$runtime_values"); then
  assert 'runtime image collector uses credentialless native scanner then isolated uploader' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|first|.initContainers[0].command==["/usr/local/bin/deckard"] and .initContainers[0].args[0:2]==["images","collect"] and (.initContainers[0].args|index("--all-namespaces")!=null and index("--token-env")==null and index("/report/request.json")!=null) and .containers[0].args[0:2]==["images","upload"] and (.containers[0].args|index("--cluster-scope")!=null)' "$runtime"
  assert 'runtime collector deadline allows bounded 45 minute scan plus upload' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec]|first|.activeDeadlineSeconds==3000' "$runtime"
  assert 'runtime collector reads only Pods and Nodes, never kube secrets or writes' '[.[]|select(.kind=="ClusterRole" and .metadata.labels."app.kubernetes.io/component"=="collector").rules[]]|length==2 and all(.apiGroups==[""] and .verbs==["list"] and (.resources==["pods"] or .resources==["nodes"]))' "$runtime"
  assert 'runtime registry and projected API credentials are scanner-only' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|first|(.volumes[]|select(.name=="registry-auth").secret.secretName)=="registry-readonly" and (.initContainers[0].volumeMounts|map(.name)|sort)==["kube-api","registry-auth","report","scratch"] and (.containers[0].volumeMounts|map(.name))==["report"] and (.initContainers[0].args|index("--registry-auth-dir")!=null)' "$runtime"
  namespace_runtime=$(render_mutation '.collectors.jobs[0].allNamespaces=false|.collectors.jobs[0].namespaces=["apps","edge"]' "$runtime_values")
  assert 'runtime namespace grants stay namespaced with separate Node-only grant' '[.[]|select(.kind=="RoleBinding").metadata.namespace]|sort==["apps","edge"]' "$namespace_runtime"
else print -u2 'FAIL runtime image collector renders'; fail=1; fi
reject 'runtime collector requires explicit namespace authority' 'trivy-runtime requires namespaces or allNamespaces, never both' 'del(.collectors.jobs[0].allNamespaces)' "$runtime_values"
reject 'runtime collector requires immutable cluster UID scope' 'trivy-runtime clusterScope must use k8s:uid:<UUID>:runtime-images' '.collectors.jobs[0].clusterScope="k8s:mutable-name:runtime-images"' "$runtime_values"
tetragon_values=$(jq '.collectors.jobs=[{name:"tetragon-events",type:"tetragon",schedule:"*/5 * * * *",sensorNamespace:"tetragon",sensorSelector:"app.kubernetes.io/name=tetragon",clusterScope:"k8s:uid:11111111-1111-4111-8111-111111111111",maxAgeSeconds:900}]' <<< "$values")
if tetragon=$(render "$tetragon_values"); then
  assert 'Tetragon uses native credentialless collection followed by incomplete-only upload' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|first|.initContainers[0].command==["/usr/local/bin/deckard"] and .initContainers[0].args[0:2]==["runtime","collect"] and (.initContainers[0].args|index("export-stdout")!=null and index("6m")!=null and index("/report/request.json")!=null and index("--token-env")==null) and .containers[0].args[0:2]==["runtime","upload"] and .initContainers[0].image==.containers[0].image' "$tetragon"
  assert 'Tetragon collection expires within its five-minute schedule' '[.[]|select(.kind=="CronJob")]|first|.spec.schedule=="*/5 * * * *" and .spec.concurrencyPolicy=="Forbid" and .spec.jobTemplate.spec.activeDeadlineSeconds==300' "$tetragon"
  assert 'Tetragon RBAC allows only Pod listing and Pod log reads in sensor namespace' '[.[]|select(.kind=="Role" and .metadata.labels."app.kubernetes.io/component"=="collector")]|length==1 and (.[0].metadata.namespace=="tetragon") and (.[0].rules==[{apiGroups:[""],resources:["pods"],verbs:["list"]},{apiGroups:[""],resources:["pods/log"],verbs:["get"]}])' "$tetragon"
  assert 'Tetragon creates no global permissions or sensor workloads' '[.[]|select(.metadata.labels."app.kubernetes.io/component"=="collector" and (.kind=="ClusterRole" or .kind=="ClusterRoleBinding" or .kind=="DaemonSet"))]|length==0' "$tetragon"
  assert 'Tetragon raw log reader has projected API token but never uploader credential' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|first|(.initContainers[0].env|map(.name))==["HOME"] and (.initContainers[0].volumeMounts|map(.name)|sort)==["kube-api","report","scratch"] and (.containers[0].volumeMounts|map(.name))==["report"] and .containers[0].volumeMounts[0].readOnly==true and (.volumes[]|select(.name=="kube-api").projected.sources[0].serviceAccountToken.expirationSeconds)==3600' "$tetragon"
else print -u2 'FAIL Tetragon collector renders'; fail=1; fi
reject 'Tetragon requires explicit sensor namespace' 'Tetragon sensorNamespace must be an explicit DNS label' 'del(.collectors.jobs[0].sensorNamespace)' "$tetragon_values"
reject 'Tetragon requires explicit sensor label selector' 'Tetragon sensorSelector is required' 'del(.collectors.jobs[0].sensorSelector)' "$tetragon_values"
reject 'Tetragon cannot collect arbitrary sensor container logs' 'Tetragon sensorContainer must be export-stdout' '.collectors.jobs[0].sensorContainer="tetragon"' "$tetragon_values"
reject 'Tetragon requires immutable cluster UID scope' 'Tetragon clusterScope must use k8s:uid:<UUID>' '.collectors.jobs[0].clusterScope="k8s:mutable-name"' "$tetragon_values"
for retries in 0 1 2; do
  retried=$(render_mutation ".collectors.jobs[0].backoffLimit=$retries" "$tetragon_values")
  assert "Tetragon permits exactly $retries bounded whole-Pod retries" "[.[]|select(.kind==\"CronJob\")]|first|.spec.jobTemplate.spec.backoffLimit==$retries and .spec.jobTemplate.spec.activeDeadlineSeconds==300 and .spec.concurrencyPolicy==\"Forbid\" and .spec.jobTemplate.spec.template.spec.restartPolicy==\"Never\"" "$retried"
done
for retries in '-1' '3' '1.5' '"2"' 'true' 'null' '[]' '{}'; do
  reject "invalid Tetragon retry limit $retries is refused" 'collector backoffLimit must be an integer from 0 to 2' ".collectors.jobs[0].backoffLimit=$retries" "$tetragon_values"
done
reject 'posture collectors cannot opt into runtime retries' 'only Tetragon collectors support nonzero backoffLimit' '.collectors.jobs[0].backoffLimit=1' "$kube_values"
for placement_base in "$values" "$kube_values" "$tetragon_values" "$runtime_values" "$prowler_values"; do
  platform_values=$(jq '.nodeSelector={nodegroup:"infrastructure"}|.tolerations=[{key:"nodegroup",operator:"Equal",value:"infrastructure",effect:"NoSchedule"}]|.affinity={nodeAffinity:{requiredDuringSchedulingIgnoredDuringExecution:{nodeSelectorTerms:[{matchExpressions:[{key:"nodegroup",operator:"In",values:["infrastructure"]}]}]}}}' <<< "$placement_base")
  platform=$(render "$platform_values")
  assert 'collectors inherit global platform placement' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|all(.nodeSelector=={nodegroup:"infrastructure"} and .tolerations==[{key:"nodegroup",operator:"Equal",value:"infrastructure",effect:"NoSchedule"}] and .affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms==[{matchExpressions:[{key:"nodegroup",operator:"In",values:["infrastructure"]}]}])' "$platform"
  override=$(render_mutation '.collectors.jobs[0].nodeSelector={nodegroup:"default"}|.collectors.jobs[0].tolerations=[{key:"dedicated",operator:"Equal",value:"scanner",effect:"NoSchedule"}]|.collectors.jobs[0].affinity={podAntiAffinity:{preferredDuringSchedulingIgnoredDuringExecution:[{weight:50,podAffinityTerm:{topologyKey:"kubernetes.io/hostname",labelSelector:{matchLabels:{app:"scanner"}}}}]}}' "$platform_values")
  assert 'per-job placement replaces each inherited global field' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|all(.nodeSelector=={nodegroup:"default"} and .tolerations==[{key:"dedicated",operator:"Equal",value:"scanner",effect:"NoSchedule"}] and .affinity=={podAntiAffinity:{preferredDuringSchedulingIgnoredDuringExecution:[{weight:50,podAffinityTerm:{topologyKey:"kubernetes.io/hostname",labelSelector:{matchLabels:{app:"scanner"}}}}]}})' "$override"
  cleared=$(render_mutation '.collectors.jobs[0].nodeSelector={}|.collectors.jobs[0].tolerations=[]|.collectors.jobs[0].affinity={}' "$platform_values")
  assert 'explicit empty job placement clears global defaults' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|all((has("nodeSelector")|not) and (has("tolerations")|not) and (has("affinity")|not))' "$cleared"
done
bbot_platform_values=$(jq '.nodeSelector={nodegroup:"infrastructure"}|.tolerations=[{key:"nodegroup",operator:"Equal",value:"infrastructure",effect:"NoSchedule"}]|.affinity={podAntiAffinity:{preferredDuringSchedulingIgnoredDuringExecution:[{weight:50,podAffinityTerm:{topologyKey:"kubernetes.io/hostname",labelSelector:{matchLabels:{app:"scanner"}}}}]}}' <<< "$bbot_values")
bbot_platform=$(render "$bbot_platform_values")
assert 'BBOT retains platform placement plus mandatory Linux amd64 selectors' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|all(.nodeSelector=={nodegroup:"infrastructure","kubernetes.io/os":"linux","kubernetes.io/arch":"amd64"} and .tolerations==[{key:"nodegroup",operator:"Equal",value:"infrastructure",effect:"NoSchedule"}] and .affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].weight==50)' "$bbot_platform"
bbot_override=$(render_mutation '.collectors.jobs[0].nodeSelector={nodegroup:"default"}|.collectors.jobs[0].tolerations=[]|.collectors.jobs[0].affinity={}' "$bbot_platform_values")
assert 'BBOT job overrides cannot clear its image architecture constraints' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|all(.nodeSelector=={nodegroup:"default","kubernetes.io/os":"linux","kubernetes.io/arch":"amd64"} and (has("tolerations")|not) and (has("affinity")|not))' "$bbot_override"
bbot_empty=$(render_mutation '.collectors.jobs[0].nodeSelector={}' "$bbot_platform_values")
assert 'BBOT empty job selector clears only inherited platform constraints' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|all(.nodeSelector=={"kubernetes.io/os":"linux","kubernetes.io/arch":"amd64"})' "$bbot_empty"
reject 'BBOT refuses conflicting inherited architecture' 'BBOT placement requires kubernetes.io/os=linux and kubernetes.io/arch=amd64' '.nodeSelector={"kubernetes.io/arch":"arm64"}' "$bbot_values"
reject 'BBOT refuses conflicting inherited OS' 'BBOT placement requires kubernetes.io/os=linux and kubernetes.io/arch=amd64' '.nodeSelector={"kubernetes.io/os":"windows"}' "$bbot_values"
reject 'BBOT refuses conflicting job architecture' 'BBOT placement requires kubernetes.io/os=linux and kubernetes.io/arch=amd64' '.collectors.jobs[0].nodeSelector={"kubernetes.io/arch":"arm64"}' "$bbot_values"
reject 'BBOT refuses conflicting job OS' 'BBOT placement requires kubernetes.io/os=linux and kubernetes.io/arch=amd64' '.collectors.jobs[0].nodeSelector={"kubernetes.io/os":"windows"}' "$bbot_values"
bbot_compatible=$(render_mutation '.nodeSelector={"kubernetes.io/arch":"arm64"}|.collectors.jobs[0].nodeSelector={nodegroup:"infrastructure","kubernetes.io/arch":"amd64"}' "$bbot_values")
assert 'BBOT compatible job selector can replace an incompatible global default' '[.[]|select(.kind=="CronJob").spec.jobTemplate.spec.template.spec]|all(.nodeSelector=={nodegroup:"infrastructure","kubernetes.io/os":"linux","kubernetes.io/arch":"amd64"})' "$bbot_compatible"
posture_job=$(jq '.collectors.jobs[0]' <<< "$kube_values")
tetragon_job=$(jq '.collectors.jobs[0]' <<< "$tetragon_values")
mixed_values=$(jq --argjson posture "$posture_job" '.collectors.jobs+=[$posture]' <<< "$bbot_platform_values")
mixed=$(render "$mixed_values")
assert 'BBOT mandatory selectors never mutate other collector defaults' '[.[]|select(.kind=="CronJob" and .metadata.labels."deckard.io/collector"=="cluster-posture").spec.jobTemplate.spec.template.spec]|all(.nodeSelector=={nodegroup:"infrastructure"})' "$mixed"
multi_values=$(jq --argjson posture "$posture_job" --argjson runtime "$tetragon_job" '.collectors.jobs+=[$posture,$runtime]|.collectors.jobs+=[.collectors.jobs[]|.name=(.name[0:14]+"-copy")]|.collectors.alerts={enabled:true}' <<< "$bbot_platform_values")
multi=$(render "$multi_values")
assert 'multiple collectors preserve every YAML resource document' '[.[]|select(.metadata.labels."app.kubernetes.io/component"=="collector")]|group_by(.kind)|map({key:.[0].kind,value:length})|from_entries|.CronJob==6 and .ServiceAccount==6 and .NetworkPolicy==6 and .ConfigMap==2 and .Role==2 and .RoleBinding==2 and .ClusterRole==4 and .ClusterRoleBinding==4' "$multi"
assert 'multiple collectors keep distinct scheduling and alert identities' '([.[]|select(.kind=="CronJob").metadata.name]|unique|length)==6 and ([.[]|select(.kind=="PrometheusRule").spec.groups[].rules[]]|length)==12' "$multi"
multiple_runtime=$(render_mutation '.collectors.jobs+=[.collectors.jobs[0]|.name="runtime-images-copy"]' "$runtime_values")
assert 'multiple runtime collectors preserve separate RBAC documents' '[.[]|select(.metadata.labels."app.kubernetes.io/component"=="collector")]|group_by(.kind)|map({key:.[0].kind,value:length})|from_entries|.CronJob==2 and .ServiceAccount==2 and .NetworkPolicy==2 and .ClusterRole==4 and .ClusterRoleBinding==4' "$multiple_runtime"
if [[ ${DECKARD_BBOT_FIXTURE:-0} == 1 ]]; then
  command -v docker >/dev/null || { print -u2 'missing dependency: docker'; exit 1; }
  # Real BBOT SDK/module/lifecycle/JSON writer; only provider and DNS responses
  # are fixtures. No targets or upstream providers are contacted by this test.
  print -r -- "$bbot" | docker run --rm -i --platform linux/amd64 \
    --read-only --network none --user 65532 --cap-drop ALL \
    --security-opt no-new-privileges --tmpfs /tmp:mode=1777 \
    --tmpfs /report:mode=1777 --workdir /tmp --env HOME=/tmp \
    --mount "type=bind,source=$PWD/tests/bbot_collector_test.py,target=/test_bbot.py,readonly" \
    --entrypoint python \
    blacklanternsecurity/bbot@sha256:40ed0733e0163feee844d49346eb15e40872fa7008f621358eed9b9a7807382e \
    /test_bbot.py || fail=1
fi
exit "$fail"
