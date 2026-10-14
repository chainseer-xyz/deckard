{{- define "deckard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "deckard.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "deckard.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "deckard.labels" -}}
helm.sh/chart: {{ include "deckard.chart" . }}
{{ include "deckard.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "deckard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "deckard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "deckard.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "deckard.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Render API defaults explicitly to avoid Gateway API admission/Argo drift.
     Presence, not truthiness, matters: group: "" is a valid core API reference. */}}
{{- define "deckard.httpRouteParentRefs" -}}
{{- $refs := list -}}
{{- range . -}}
{{- $ref := deepCopy . -}}
{{- if not (hasKey $ref "group") -}}
{{- $_ := set $ref "group" "gateway.networking.k8s.io" -}}
{{- end -}}
{{- if not (hasKey $ref "kind") -}}
{{- $_ := set $ref "kind" "Gateway" -}}
{{- end -}}
{{- $refs = append $refs $ref -}}
{{- end -}}
{{- toYaml $refs -}}
{{- end }}

{{- define "deckard.httpRouteBackendRefs" -}}
- group: ""
  kind: Service
  name: {{ include "deckard.fullname" . }}
  port: {{ .Values.service.port }}
  weight: 1
{{- end }}

{{/* Name of the CNPG Cluster (and its generated app secret prefix). */}}
{{- define "deckard.dbClusterName" -}}
{{- printf "%s-db" (include "deckard.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Guard: CPU limits are forbidden by platform policy. */}}
{{- define "deckard.validate" -}}
{{- include "deckard.assessmentValidate" . -}}
{{- if and .Values.resources .Values.resources.limits .Values.resources.limits.cpu }}
{{- fail "resources.limits.cpu must not be set: CPU limits cause throttling and are disallowed" }}
{{- end }}
{{- if and .Values.worker.enabled .Values.worker.resources .Values.worker.resources.limits .Values.worker.resources.limits.cpu }}
{{- fail "worker.resources.limits.cpu must not be set: CPU limits cause throttling and are disallowed" }}
{{- end }}
{{- $dbEnv := or (hasKey .Values.env "DECKARD_DATABASE__URL") (hasKey (.Values.secretEnv | default dict) "DECKARD_DATABASE__URL") (dig "database" "url" "" .Values.config) -}}
{{- range .Values.extraEnv }}{{ if eq (toString .name) "DECKARD_DATABASE__URL" }}{{ $dbEnv = true }}{{ end }}{{ end -}}
{{- if and (not .Values.database.cnpg.enabled) (not .Values.database.existingSecret) (not $dbEnv) }}
{{- fail "no database configured: set database.cnpg.enabled=true, database.existingSecret, or DECKARD_DATABASE__URL (env, secretEnv or extraEnv)" }}
{{- end }}
{{- if and .Values.worker.enabled (has "worker" .Values.roles) }}
{{- fail "worker.enabled=true: remove \"worker\" from roles so scanning runs only in the worker Deployment" }}
{{- end }}
{{- if and .Values.nuclei.customTemplates.configMap .Values.nuclei.customTemplates.existingClaim }}
{{- fail "nuclei.customTemplates.configMap and existingClaim are mutually exclusive" }}
{{- end }}
{{- end }}

{{/* Assessment execution changes controller authority. Keep the config flag as
     the only Helm switch and reject rollout overlap or incomplete isolation. */}}
{{- define "deckard.assessmentValidate" -}}
{{- if dig "assessment" "enabled" false .Values.config -}}
{{- $assessment := get .Values.config "assessment" -}}
{{- $namespace := dig "namespace" "deckard-assessments" $assessment -}}
{{- $podIPEnv := dig "broker_ip_env" "DECKARD_POD_IP" $assessment -}}
{{- if not (dig "network_policy_enforced" false $assessment) -}}
{{- fail "assessment execution requires verified network_policy_enforced=true" -}}
{{- end -}}
{{- if ne (int .Values.replicaCount) 1 -}}{{ fail "assessment execution requires replicaCount=1" }}{{- end -}}
{{- if not (has "api" .Values.roles) -}}{{ fail "assessment execution requires the api role" }}{{- end -}}
{{- if ne (dig "type" "" .Values.deploymentStrategy) "Recreate" -}}{{ fail "assessment execution requires deploymentStrategy.type=Recreate" }}{{- end -}}
{{- if and (hasKey .Values.deploymentStrategy "rollingUpdate") (ne (toJson .Values.deploymentStrategy.rollingUpdate) "null") -}}{{ fail "assessment Recreate cannot include rollingUpdate" }}{{- end -}}
{{- if not .Values.networkPolicy.enabled -}}{{ fail "assessment execution requires networkPolicy.enabled=true" }}{{- end -}}
{{- if eq (int .Values.metrics.port) 9092 -}}{{ fail "assessment broker port 9092 cannot be used for metrics" }}{{- end -}}
{{- if or (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $namespace)) (gt (len $namespace) 63) (eq $namespace .Release.Namespace) (eq $namespace "default") (hasPrefix "kube-" $namespace) -}}
{{- fail "assessment execution requires a dedicated namespace distinct from the API and system namespaces" -}}
{{- end -}}
{{- if not (has (dig "broker_addr" "0.0.0.0:9092" $assessment) (list "0.0.0.0:9092" "[::]:9092")) -}}
{{- fail "chart requires assessment.broker_addr on port 9092" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z_][A-Za-z0-9_]*$" $podIPEnv) -}}{{ fail "assessment broker_ip_env must be a valid environment variable name" }}{{- end -}}
{{- if or (hasKey .Values.env $podIPEnv) (hasKey (.Values.secretEnv | default dict) $podIPEnv) -}}{{ fail "assessment Pod IP environment variable is reserved for downwardAPI" }}{{- end -}}
{{- range .Values.extraEnv -}}
{{- if eq (toString .name) $podIPEnv -}}{{ fail "assessment Pod IP environment variable is reserved for downwardAPI" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{- define "deckard.assessmentName" -}}
{{- $identity := printf "%s/%s" .Release.Namespace (include "deckard.fullname" .) -}}
{{- printf "%s-assessment-%s" ((include "deckard.fullname" .) | trunc 42 | trimSuffix "-") ($identity | sha256sum | trunc 8) -}}
{{- end }}

{{- define "deckard.assessmentLabels" -}}
helm.sh/chart: {{ include "deckard.chart" . }}
app.kubernetes.io/name: deckard-assessment
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: assessment
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* True unless config.nuclei.update.enabled is explicitly false (air-gapped installs). */}}
{{- define "deckard.nucleiUpdateEnabled" -}}
{{- if ne (toString (dig "nuclei" "update" "enabled" true .Values.config)) "false" }}true{{ end }}
{{- end }}

{{/* Where the nuclei template updater keeps its state (config.nuclei.update.dir). */}}
{{- define "deckard.nucleiUpdateDir" -}}
{{- dig "nuclei" "update" "dir" "/var/lib/deckard/nuclei-templates" .Values.config }}
{{- end }}

{{/* Pod template shared by the main and worker Deployments. Pass a dict: root, roles, resources, component, nucleiPVC. */}}
{{- define "deckard.podTemplate" -}}
{{- $root := .root -}}
{{- $nucleiUpdate := include "deckard.nucleiUpdateEnabled" $root -}}
metadata:
  annotations:
    checksum/config: {{ include (print $root.Template.BasePath "/configmap.yaml") $root | sha256sum }}
    {{- with $root.Values.podAnnotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  labels:
    {{- include "deckard.selectorLabels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ .component }}
    {{- with $root.Values.podLabels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  {{- if and (dig "assessment" "enabled" false $root.Values.config) (has "api" .roles) }}
  serviceAccountName: {{ include "deckard.assessmentName" $root }}
  {{- else }}
  serviceAccountName: {{ include "deckard.serviceAccountName" $root }}
  {{- end }}
  terminationGracePeriodSeconds: {{ $root.Values.terminationGracePeriodSeconds }}
  {{- with $root.Values.imagePullSecrets }}
  imagePullSecrets: {{- toYaml . | nindent 4 }}
  {{- end }}
  securityContext: {{- toYaml $root.Values.podSecurityContext | nindent 4 }}
  containers:
    - name: deckard
      image: "{{ $root.Values.image.repository }}:{{ default $root.Chart.AppVersion $root.Values.image.tag }}"
      imagePullPolicy: {{ $root.Values.image.pullPolicy }}
      args: ["serve", "--config", "/etc/deckard/deckard.yaml"]
      securityContext: {{- toYaml $root.Values.securityContext | nindent 8 }}
      ports:
        - { name: http, containerPort: 8080, protocol: TCP }
        - { name: metrics, containerPort: {{ $root.Values.metrics.port }}, protocol: TCP }
        {{- if and (dig "assessment" "enabled" false $root.Values.config) (has "api" .roles) }}
        - { name: assessment, containerPort: 9092, protocol: TCP }
        {{- end }}
      env:
        - { name: DECKARD_SERVER__ROLES, value: {{ join "," .roles | quote }} }
        - { name: DECKARD_SERVER__METRICS_ADDR, value: {{ printf ":%v" $root.Values.metrics.port | quote }} }
        # The root filesystem is read-only. With the template updater on, deckard
        # gives every nuclei run its own HOME/XDG directories under the update
        # volume; HOME=/tmp covers a nuclei run when the updater is off.
        - { name: HOME, value: /tmp }
        {{- if and (dig "assessment" "enabled" false $root.Values.config) (has "api" .roles) }}
        - name: {{ dig "assessment" "broker_ip_env" "DECKARD_POD_IP" $root.Values.config }}
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        {{- end }}
        {{- if $root.Values.database.cnpg.enabled }}
        - name: DECKARD_DATABASE__URL
          valueFrom:
            secretKeyRef:
              name: {{ include "deckard.dbClusterName" $root }}-app
              key: uri
        {{- else if $root.Values.database.existingSecret }}
        - name: DECKARD_DATABASE__URL
          valueFrom:
            secretKeyRef:
              name: {{ $root.Values.database.existingSecret }}
              key: {{ $root.Values.database.existingSecretKey }}
        {{- end }}
        {{- range $k, $v := $root.Values.env }}
        - { name: {{ $k }}, value: {{ $v | quote }} }
        {{- end }}
        {{- with $root.Values.extraEnv }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      envFrom:
        {{- if $root.Values.secretEnv }}
        - secretRef: { name: {{ include "deckard.fullname" $root }}-env }
        {{- end }}
        {{- with $root.Values.extraEnvFrom }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- if has "api" .roles }}
      livenessProbe: {{- toYaml $root.Values.livenessProbe | nindent 8 }}
      readinessProbe: {{- toYaml $root.Values.readinessProbe | nindent 8 }}
      {{- else }}
      {{- /* Only the api role serves /healthz and /readyz on the http port; a
           pod without it listens on the metrics port alone. */}}
      livenessProbe:
        tcpSocket: { port: metrics }
        periodSeconds: {{ default 20 $root.Values.livenessProbe.periodSeconds }}
      readinessProbe:
        tcpSocket: { port: metrics }
        periodSeconds: {{ default 10 $root.Values.readinessProbe.periodSeconds }}
      {{- end }}
      resources: {{- toYaml .resources | nindent 8 }}
      volumeMounts:
        - { name: config, mountPath: /etc/deckard, readOnly: true }
        - { name: tmp, mountPath: /tmp }
        - { name: data, mountPath: /var/lib/deckard }
        {{- if $nucleiUpdate }}
        - { name: nuclei-templates, mountPath: {{ include "deckard.nucleiUpdateDir" $root | quote }} }
        {{- end }}
        {{- if or $root.Values.nuclei.customTemplates.configMap $root.Values.nuclei.customTemplates.existingClaim }}
        - { name: custom-templates, mountPath: "/var/lib/deckard/custom-templates", readOnly: true }
        {{- end }}
        {{- with $root.Values.extraVolumeMounts }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
  volumes:
    - name: config
      configMap: { name: {{ include "deckard.fullname" $root }} }
    - { name: tmp, emptyDir: {} }
    {{- if $root.Values.persistence.enabled }}
    - name: data
      persistentVolumeClaim:
        claimName: {{ default (printf "%s-data" (include "deckard.fullname" $root)) $root.Values.persistence.existingClaim }}
    {{- else }}
    - { name: data, emptyDir: {} }
    {{- end }}
    {{- if $nucleiUpdate }}
    {{- /* A ReadWriteOnce claim cannot be shared by several worker replicas: the
         PVC (when enabled) backs the main Deployment only; workers use an
         emptyDir and keep themselves fresh with the per-node catch-up loop. */}}
    {{- if and .nucleiPVC $root.Values.nuclei.persistence.enabled }}
    - name: nuclei-templates
      persistentVolumeClaim:
        claimName: {{ default (printf "%s-nuclei" (include "deckard.fullname" $root)) $root.Values.nuclei.persistence.existingClaim }}
    {{- else }}
    - name: nuclei-templates
      emptyDir:
        sizeLimit: {{ $root.Values.nuclei.emptyDirSizeLimit }}
    {{- end }}
    {{- end }}
    {{- if $root.Values.nuclei.customTemplates.configMap }}
    - name: custom-templates
      configMap: { name: {{ $root.Values.nuclei.customTemplates.configMap }} }
    {{- else if $root.Values.nuclei.customTemplates.existingClaim }}
    - name: custom-templates
      persistentVolumeClaim:
        claimName: {{ $root.Values.nuclei.customTemplates.existingClaim }}
    {{- end }}
    {{- with $root.Values.extraVolumes }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- with $root.Values.nodeSelector }}
  nodeSelector: {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $root.Values.affinity }}
  affinity: {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $root.Values.tolerations }}
  tolerations: {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $root.Values.topologySpreadConstraints }}
  topologySpreadConstraints: {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
