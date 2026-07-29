{{- define "nemoclaw-cli-imagestream.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nemoclaw-cli-imagestream.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "nemoclaw-cli-imagestream.labels" -}}
app.kubernetes.io/name: {{ include "nemoclaw-cli-imagestream.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "nemoclaw-cli-imagestream.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- end }}
