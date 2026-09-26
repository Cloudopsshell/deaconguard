{{- define "opsarmor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "opsarmor.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "opsarmor.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "opsarmor.labels" -}}
app.kubernetes.io/name: {{ include "opsarmor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "opsarmor.safeHostID" -}}
{{- $slug := regexReplaceAll "[^a-z0-9-]+" (. | lower) "-" | trimAll "-" | trunc 34 | trimSuffix "-" -}}
{{- printf "%s-%s" $slug (sha256sum . | trunc 8) -}}
{{- end -}}