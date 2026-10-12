{{- define "deaconguard.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "deaconguard.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: deaconguard
{{- end -}}

{{- define "deaconguard.selector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "deaconguard.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "deaconguard.adminSecret" -}}
{{- .Values.server.admin.existingSecret | default (printf "%s-admin" (include "deaconguard.fullname" .)) -}}
{{- end -}}

{{- define "deaconguard.enrollmentSecret" -}}
{{- .Values.agent.enrollment.existingSecret | default (printf "%s-enrollment" (include "deaconguard.fullname" .)) -}}
{{- end -}}

{{- /* The agent DaemonSet: the release's name when it already ends in "agent". */ -}}
{{- define "deaconguard.agentName" -}}
{{- $name := include "deaconguard.fullname" . -}}
{{- if hasSuffix "agent" $name -}}
{{- $name -}}
{{- else -}}
{{- printf "%s-agent" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
