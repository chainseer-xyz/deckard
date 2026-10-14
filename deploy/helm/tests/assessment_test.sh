#!/usr/bin/env zsh
# Real Helm contracts. Requires Helm, yq v4 and jq; never contacts Kubernetes.
# ShellCheck lacks a zsh parser; assertions use the Bash-compatible subset.
# jq variables deliberately remain single-quoted; they are not shell variables.
# shellcheck shell=bash disable=SC2310,SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in helm yq jq; do
  command -v "$tool" >/dev/null || { print -u2 "missing dependency: $tool"; exit 1; }
done
fail=0
assert() {
  if jq -e "$2" >/dev/null <<< "$3"; then print -r -- "ok   $1"
  else print -u2 -r -- "FAIL $1"; fail=1; fi
}
render() {
  local rendered
  rendered=$(helm template assessments deckard --namespace security --set database.cnpg.enabled=true -f - <<< "$1") || return
  yq -o=json -I=0 eval-all '[.]' - <<< "$rendered"
}
reject() { # name, expected message, jq mutation, base values
  local changed output
  changed=$(jq -e "$3" <<< "$4") || return
  if output=$(render "$changed" 2>&1); then print -u2 -r -- "FAIL $1 (unexpectedly rendered)"; fail=1
  elif [[ $output == *"$2"* ]]; then print -r -- "ok   $1"
  else print -u2 -r -- "FAIL $1 (wrong error: $output)"; fail=1; fi
}
values=$(jq -n '{deploymentStrategy:{type:"Recreate"},worker:{enabled:true},roles:["api","scheduler"],config:{assessment:{enabled:true,network_policy_enforced:true,images:{zap:"ghcr.io/example/zap@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},uploader_image:"ghcr.io/example/deckard@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}')
off=$(render '{}')
assert 'assessments stay off without the config flag' '[.[]|select(.metadata.labels."app.kubernetes.io/component"=="assessment")]|length==0' "$off"
assert 'disabled assessments expose no broker port or PodIP env' '[.[]|select(.kind=="Deployment").spec.template.spec.containers[]|(.ports[]?|select(.containerPort==9092)),(.env[]?|select(.valueFrom.fieldRef.fieldPath=="status.podIP"))]|length==0' "$off"
if enabled=$(render "$values"); then
  isolation=$(jq '[.[]|select(.metadata.labels."app.kubernetes.io/component"=="assessment")]' <<< "$enabled")
  assert 'dedicated namespace carries restricted PSA and explicit isolation label' '[.[]|select(.kind=="Namespace")]|length==1 and .[0].metadata.name=="deckard-assessments" and .[0].metadata.labels."deckard.io/assessment-isolated"=="true" and .[0].metadata.labels."pod-security.kubernetes.io/enforce"=="restricted" and .[0].metadata.labels."pod-security.kubernetes.io/audit"=="restricted" and .[0].metadata.labels."pod-security.kubernetes.io/warn"=="restricted"' "$isolation"
  assert 'namespace precedes policy and API waves' '[.[]|select(.kind=="Namespace")][0].metadata.annotations."argocd.argoproj.io/sync-wave"=="-3" and ([.[]|select(.kind=="NetworkPolicy")][0].metadata.annotations."argocd.argoproj.io/sync-wave"=="-2")' "$isolation"
  assert 'isolation survives disable while old jobs expire' '[.[]|select(.kind=="Namespace" or .kind=="NetworkPolicy")]|length==2 and all(.metadata.annotations."helm.sh/resource-policy"=="keep" and .metadata.annotations."argocd.argoproj.io/sync-options"=="Prune=false")' "$isolation"
  assert 'assessment defaultdeny rejects ingress and egress for every pod' '[.[]|select(.kind=="NetworkPolicy")]|length==1 and .[0].metadata.name=="deckard-assessment-deny-all" and .[0].metadata.namespace=="deckard-assessments" and .[0].spec.podSelector=={} and (.[0].spec.policyTypes|sort)==["Egress","Ingress"] and (.[0].spec.ingress//[])==[] and (.[0].spec.egress//[])==[]' "$isolation"
  assert 'runner identity has no token or inherited cloud annotation' '[.[]|select(.kind=="ServiceAccount" and .metadata.namespace=="deckard-assessments")]|length==1 and .[0].metadata.name=="deckard-assessment-runner" and .[0].automountServiceAccountToken==false and (.[0].metadata.annotations//{}|keys|map(select(test("eks.amazonaws.com|iam.gke.io|azure.workload.identity")))|length)==0' "$isolation"
  assert 'namespace permissions are one named read only' '[.[]|select(.kind=="ClusterRole")]|length==1 and .[0].rules==[{apiGroups:[""],resources:["namespaces"],resourceNames:["deckard-assessments"],verbs:["get"]}]' "$isolation"
  assert 'manager mutation authority is namespace scoped' '[.[]|select(.kind=="Role")]|length==1 and .[0].metadata.namespace=="deckard-assessments" and ([.[0].rules[].resources[]]|sort)==["configmaps","jobs","networkpolicies","pods","secrets","serviceaccounts"]' "$isolation"
  assert 'RBAC cannot exec, proxy, bind, impersonate or read unrelated secrets' '([.[]|select(.kind=="Role" or .kind=="ClusterRole").rules[]]|length==6 and all((.resources|all(.!="*" and .!="pods/exec" and .!="pods/attach" and .!="nodes/proxy")) and (.verbs|all(.!="*" and .!="bind" and .!="escalate" and .!="impersonate")))) and ([.[]|select(.kind=="Role").rules[]|select(.resources|index("secrets"))][0].verbs|sort)==["create","delete","list","patch"]' "$isolation"
  assert 'only API manager identity receives assessment RBAC' '([.[]|select(.kind=="Deployment" and .metadata.labels."app.kubernetes.io/component"=="server")][0].spec.template.spec.serviceAccountName) as $api | [.[]|select(.metadata.labels."app.kubernetes.io/component"=="assessment" and (.kind=="RoleBinding" or .kind=="ClusterRoleBinding"))]|length==2 and all(.subjects==[{kind:"ServiceAccount",name:$api,namespace:"security"}])' "$enabled"
  assert 'API manager identity is distinct from workers' '[.[]|select(.kind=="Deployment")|{component:.metadata.labels."app.kubernetes.io/component",sa:.spec.template.spec.serviceAccountName}]|sort_by(.component)|.[0].sa!=.[1].sa and .[1].sa=="assessments-deckard"' "$enabled"
  assert 'both identities retain existing source-read RBAC' '([.[]|select(.kind=="Deployment" and .metadata.labels."app.kubernetes.io/component"=="server")][0].spec.template.spec.serviceAccountName) as $api | [.[]|select(.kind=="ClusterRoleBinding" and .metadata.name=="assessments-deckard")][0].subjects|sort_by(.name)==([{kind:"ServiceAccount",name:"assessments-deckard",namespace:"security"},{kind:"ServiceAccount",name:$api,namespace:"security"}]|sort_by(.name))' "$enabled"
  assert 'API alone receives literal PodIP downwardAPI value' '[.[]|select(.kind=="Deployment")|{component:.metadata.labels."app.kubernetes.io/component",env:[.spec.template.spec.containers[0].env[]|select(.name=="DECKARD_POD_IP")]}]|sort_by(.component)|.[0].component=="server" and .[0].env==[{name:"DECKARD_POD_IP",valueFrom:{fieldRef:{fieldPath:"status.podIP"}}}] and .[1].env==[]' "$enabled"
  assert 'broker port belongs only to API role and is absent from Services' '[.[]|select(.kind=="Deployment")|{component:.metadata.labels."app.kubernetes.io/component",ports:[.spec.template.spec.containers[0].ports[]|select(.containerPort==9092)]}]|sort_by(.component)|.[0].ports==[{name:"assessment",containerPort:9092,protocol:"TCP"}] and .[1].ports==[]' "$enabled"
  assert 'broker is never exposed by a Service' '[.[]|select(.kind=="Service").spec.ports[]|select(.port==9092 or .targetPort==9092 or .targetPort=="assessment")]|length==0' "$enabled"
  assert 'main broker ingress grants only the isolated namespace and managed runner labels' '[.[]|select(.kind=="NetworkPolicy" and .metadata.namespace!="deckard-assessments").spec.ingress[]|select(any(.ports[]; .port==9092))]|length==1 and .[0].ports==[{port:9092,protocol:"TCP"}] and .[0].from==[{namespaceSelector:{matchLabels:{"kubernetes.io/metadata.name":"deckard-assessments","deckard.io/assessment-isolated":"true"}},podSelector:{matchLabels:{"app.kubernetes.io/name":"deckard-assessment"}}}]' "$enabled"
  assert 'only one API writer can exist during a chart rollout' '[.[]|select(.kind=="Deployment" and .metadata.labels."app.kubernetes.io/component"=="server")][0]|.spec.replicas==1 and .spec.strategy.type=="Recreate" and (.spec.strategy|has("rollingUpdate")|not)' "$enabled"
  assert 'all chart pods still prohibit CPU limits' '[.[]|select(.kind=="Deployment").spec.template.spec.containers[].resources.limits//{}]|all(has("cpu")|not)' "$enabled"
else print -u2 'FAIL assessment enabled render'; fail=1; fi
reject 'unverified network enforcement is refused' 'requires verified network_policy_enforced=true' '.config.assessment.network_policy_enforced=false' "$values"
reject 'multiple API replicas are refused' 'requires replicaCount=1' '.replicaCount=2' "$values"
reject 'API-less configuration is refused' 'requires the api role' '.roles=["scheduler"]' "$values"
reject 'rolling-update overlap is refused' 'requires deploymentStrategy.type=Recreate' '.deploymentStrategy={type:"RollingUpdate"}' "$values"
reject 'missing Recreate is refused' 'requires deploymentStrategy.type=Recreate' 'del(.deploymentStrategy)' "$values"
reject 'empty rollingUpdate is still incompatible with Recreate' 'Recreate cannot include rollingUpdate' '.deploymentStrategy.rollingUpdate={}' "$values"
reject 'disabled main NetworkPolicy is refused' 'requires networkPolicy.enabled=true' '.networkPolicy.enabled=false' "$values"
reject 'metrics cannot broaden broker ingress on the same port' 'assessment broker port 9092 cannot be used for metrics' '.metrics.port=9092' "$values"
reject 'runner namespace cannot share API credentials' 'requires a dedicated namespace' '.config.assessment.namespace="security"' "$values"
reject 'default namespace is not isolated' 'requires a dedicated namespace' '.config.assessment.namespace="default"' "$values"
reject 'system namespaces are refused' 'requires a dedicated namespace' '.config.assessment.namespace="kube-system"' "$values"
reject 'invalid namespace cannot change rendered metadata' 'requires a dedicated namespace' '.config.assessment.namespace="invalid/name"' "$values"
reject 'untemplated broker ports are refused' 'chart requires assessment.broker_addr on port 9092' '.config.assessment.broker_addr="0.0.0.0:9999"' "$values"
reject 'manual PodIP override is refused' 'assessment Pod IP environment variable is reserved' '.env.DECKARD_POD_IP="10.0.0.1"' "$values"
reject 'extraEnv cannot replace downwardAPI PodIP' 'assessment Pod IP environment variable is reserved' '.extraEnv=[{name:"DECKARD_POD_IP",value:"10.0.0.1"}]' "$values"
custom_values=$(jq '.config.assessment.namespace="custom-assessments"|.config.assessment.broker_ip_env="CUSTOM_BROKER_POD_IP"|.serviceAccount.annotations={"eks.amazonaws.com/role-arn":"arn:aws:iam::123456789012:role/inventory"}' <<< "$values")
if custom=$(render "$custom_values"); then
  assert 'custom namespace reaches both RBAC and broker ingress' '[.[]|select(.kind=="Role")][0].metadata.namespace=="custom-assessments" and ([.[]|select(.kind=="ClusterRole" and .metadata.labels."app.kubernetes.io/component"=="assessment")][0].rules[0].resourceNames==["custom-assessments"]) and ([.[]|select(.kind=="NetworkPolicy" and .metadata.namespace!="custom-assessments").spec.ingress[]|select(any(.ports[]; .port==9092))][0].from[0].namespaceSelector.matchLabels."kubernetes.io/metadata.name"=="custom-assessments")' "$custom"
  assert 'configured PodIP name still comes only from downwardAPI' '[.[]|select(.kind=="Deployment" and .metadata.labels."app.kubernetes.io/component"=="server").spec.template.spec.containers[0].env[]|select(.name=="CUSTOM_BROKER_POD_IP")][0].valueFrom.fieldRef.fieldPath=="status.podIP"' "$custom"
  assert 'controller IRSA annotation never propagates to runner identity' '[.[]|select(.kind=="ServiceAccount" and .metadata.name=="deckard-assessment-runner")]|length==1 and (.[0].metadata.annotations//{}|has("eks.amazonaws.com/role-arn")|not)' "$custom"
  assert 'configured IRSA annotation is copied to the new API identity' '([.[]|select(.kind=="Deployment" and .metadata.labels."app.kubernetes.io/component"=="server")][0].spec.template.spec.serviceAccountName) as $api | [.[]|select(.kind=="ServiceAccount" and .metadata.name==$api)]|length==1 and .[0].metadata.annotations."eks.amazonaws.com/role-arn"=="arn:aws:iam::123456789012:role/inventory"' "$custom"
else print -u2 'FAIL custom assessment namespace render'; fail=1; fi
explicit_null=$(jq '.deploymentStrategy.rollingUpdate=null' <<< "$values")
if preserved=$(render "$explicit_null"); then
  assert 'explicit null rollingUpdate stays compatible with Recreate' '[.[]|select(.kind=="Deployment")]|all(.spec.strategy.type=="Recreate" and .spec.strategy.rollingUpdate==null)' "$preserved"
else print -u2 'FAIL explicit null Recreate render'; fail=1; fi
external_values=$(jq '.rbac.create=false|.serviceAccount={create:false,name:"external-worker"}' <<< "$values")
if external=$(render "$external_values"); then
  assert 'external worker identity never gains assessment mutation authority' '[.[]|select(.kind=="Deployment" and .metadata.labels."app.kubernetes.io/component"=="worker")][0].spec.template.spec.serviceAccountName=="external-worker" and ([.[]|select(.kind=="RoleBinding" or .kind=="ClusterRoleBinding").subjects[].name]|index("external-worker")==null)' "$external"
else print -u2 'FAIL external worker identity render'; fail=1; fi
exit "$fail"
