{{- define "codex-openshell-image.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "codex-openshell-image.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "codex-openshell-image.labels" -}}
app.kubernetes.io/name: {{ include "codex-openshell-image.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "codex-openshell-image.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- end }}
