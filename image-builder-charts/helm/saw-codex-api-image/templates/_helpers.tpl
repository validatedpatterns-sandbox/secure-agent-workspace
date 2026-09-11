{{- define "saw-codex-api-image.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "saw-codex-api-image.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "saw-codex-api-image.labels" -}}
app.kubernetes.io/name: {{ include "saw-codex-api-image.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "saw-codex-api-image.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- end }}
