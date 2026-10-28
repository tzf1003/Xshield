{{- define "xshield.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "xshield.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "xshield.selector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Every Xshield process runs as the image's uid 10001 with nothing else. */}}
{{- define "xshield.containerSecurity" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
{{- end -}}

{{/*
Pod-level settings shared by both workloads. fsGroup lets uid 10001 read the
Secret files (mode 0440) and create its 0700 state directories on a fresh
volume; OnRootMismatch keeps the kubelet from adding group bits to the
journals afterwards, which the audit readers refuse.
*/}}
{{- define "xshield.podSecurity" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  fsGroupChangePolicy: OnRootMismatch
  seccompProfile:
    type: RuntimeDefault
automountServiceAccountToken: false
enableServiceLinks: false
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.priorityClassName }}
priorityClassName: {{ . }}
{{- end }}
{{- end -}}

{{/*
A volume exposing only the named keys of the Secret, so each container sees
the secrets it uses and nothing else (as the compose deployment does).
Arguments: root, name, keys.
*/}}
{{- define "xshield.secretVolume" -}}
- name: secrets-{{ .name }}
  secret:
    secretName: {{ .root.Values.existingSecret }}
    defaultMode: 0440
    items:
      {{- range .keys }}
      - key: {{ . }}
        path: {{ . }}
      {{- end }}
{{- end -}}

{{- define "xshield.clickhouseEnv" -}}
- name: XSHIELD_CLICKHOUSE_URL
  value: {{ .Values.clickhouse.url | quote }}
- name: XSHIELD_CLICKHOUSE_DATABASE
  value: {{ .Values.clickhouse.database | quote }}
- name: XSHIELD_CLICKHOUSE_USER
  value: {{ .Values.clickhouse.user | quote }}
- name: XSHIELD_CLICKHOUSE_PASSWORD_FILE
  value: /run/secrets/clickhouse_password
- name: XSHIELD_AUDIT_METADATA_RETENTION_DAYS
  value: {{ .Values.clickhouse.metadataRetentionDays | quote }}
{{- end -}}

{{/*
Liveness of a resident job that records each successful pass in a heartbeat
file (docs/19 19.3): after the grace for its first success, the job is
restarted when its heartbeat is older than three intervals plus a minute,
because a job that keeps failing never exits on its own. Deliberately no
startup or readiness probe: those would hold the whole pod, and with it the
data plane, out of rotation while ClickHouse is unavailable.
Arguments: root, name, interval.
*/}}
{{- define "xshield.heartbeatProbes" -}}
{{- $file := printf "/var/lib/xshield/heartbeat/%s" .name -}}
{{- $limit := add (mul 3 .interval) 60 -}}
livenessProbe:
  initialDelaySeconds: {{ .root.Values.jobs.firstSuccessGraceSeconds }}
  exec:
    command:
      - /bin/sh
      - -c
      - 'beat=$(cat {{ $file }}) && [ $(( $(date +%s) - beat )) -lt {{ $limit }} ]'
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 2
{{- end -}}

{{- define "xshield.jobResources" -}}
resources:
  {{- toYaml .Values.jobs.resources | nindent 2 }}
{{- end -}}
