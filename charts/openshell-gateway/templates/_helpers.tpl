{{- define "openshell-gateway.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "openshell-gateway.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "openshell-gateway.labels" -}}
app.kubernetes.io/name: {{ include "openshell-gateway.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "openshell-gateway.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- end }}

{{- define "openshell-gateway.selectorLabels" -}}
vm.kubevirt.io/name: {{ include "openshell-gateway.fullname" . }}
{{- end }}
