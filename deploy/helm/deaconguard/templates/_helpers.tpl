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

{{- /*
Enrollment: each agent uses its own enrollment values when they name a
secret or a token, else the shared top-level enrollment. With neither set
anywhere, the secret names are those of releases before 1.20.2, so a secret
created then still works.
*/ -}}
{{- define "deaconguard.ownEnrollment" -}}
{{- if or .existingSecret .token }}true{{ end -}}
{{- end -}}

{{- define "deaconguard.sharedEnrollmentSecret" -}}
{{- .Values.enrollment.existingSecret | default (printf "%s-agents-enrollment" (include "deaconguard.fullname" .)) -}}
{{- end -}}

{{- define "deaconguard.sharedEnrollmentSet" -}}
{{- if or .Values.enrollment.existingSecret .Values.enrollment.token }}true{{ end -}}
{{- end -}}

{{- define "deaconguard.enrollmentSecret" -}}
{{- if include "deaconguard.ownEnrollment" .Values.agent.enrollment -}}
{{- .Values.agent.enrollment.existingSecret | default (printf "%s-enrollment" (include "deaconguard.fullname" .)) -}}
{{- else if include "deaconguard.sharedEnrollmentSet" . -}}
{{- include "deaconguard.sharedEnrollmentSecret" . -}}
{{- else -}}
{{- printf "%s-enrollment" (include "deaconguard.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "deaconguard.enrollmentKey" -}}
{{- if or (include "deaconguard.ownEnrollment" .Values.agent.enrollment) (not (include "deaconguard.sharedEnrollmentSet" .)) -}}
{{- .Values.agent.enrollment.secretKey -}}
{{- else -}}
{{- .Values.enrollment.secretKey -}}
{{- end -}}
{{- end -}}

{{- define "deaconguard.clusterEnrollmentSecret" -}}
{{- if include "deaconguard.ownEnrollment" .Values.cluster.enrollment -}}
{{- .Values.cluster.enrollment.existingSecret | default (printf "%s-cluster-enrollment" (include "deaconguard.fullname" .)) -}}
{{- else if include "deaconguard.sharedEnrollmentSet" . -}}
{{- include "deaconguard.sharedEnrollmentSecret" . -}}
{{- else -}}
{{- printf "%s-cluster-enrollment" (include "deaconguard.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "deaconguard.clusterEnrollmentKey" -}}
{{- if or (include "deaconguard.ownEnrollment" .Values.cluster.enrollment) (not (include "deaconguard.sharedEnrollmentSet" .)) -}}
{{- .Values.cluster.enrollment.secretKey -}}
{{- else -}}
{{- .Values.enrollment.secretKey -}}
{{- end -}}
{{- end -}}

{{- /* Whether an agent of this release has any token configured. */ -}}
{{- define "deaconguard.agentHasToken" -}}
{{- if or (include "deaconguard.ownEnrollment" .Values.agent.enrollment) (include "deaconguard.sharedEnrollmentSet" .) }}true{{ end -}}
{{- end -}}

{{- define "deaconguard.clusterHasToken" -}}
{{- if or (include "deaconguard.ownEnrollment" .Values.cluster.enrollment) (include "deaconguard.sharedEnrollmentSet" .) }}true{{ end -}}
{{- end -}}

{{- define "deaconguard.clusterName" -}}
{{- printf "%s-cluster" (include "deaconguard.fullname" .) | trunc 63 | trimSuffix "-" -}}
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

{{/*
withDefaults fills in every setting the release's values lack from
files/defaults.yaml, a copy of values.yaml (CI checks they match). Helm
upgrade --reuse-values renders a new chart with the values of the release
it upgrades, which lack the settings added since; without this, a template
reading one, such as server.agentService.enabled, fails. Only missing keys
are added: a value the release set, such as server.enabled=false, is kept.
Every template includes it first; it prints nothing.
*/}}
{{- define "deaconguard.withDefaults" -}}
{{- include "deaconguard.fill" (list .Values (.Files.Get "files/defaults.yaml" | fromYaml)) -}}
{{- end -}}

{{- define "deaconguard.fill" -}}
{{- $values := index . 0 -}}
{{- range $key, $default := index . 1 -}}
{{- if not (hasKey $values $key) -}}
{{- $_ := set $values $key (deepCopy $default) -}}
{{- else if and (kindIs "map" $default) (kindIs "map" (index $values $key)) -}}
{{- include "deaconguard.fill" (list (index $values $key) $default) -}}
{{- end -}}
{{- end -}}
{{- end -}}
