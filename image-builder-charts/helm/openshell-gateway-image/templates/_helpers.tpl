{{- define "openshell-gateway-image.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "openshell-gateway-image.imageName" -}}
{{- if and .Values.gpu.enabled (eq .Values.containerRuntime "docker") -}}
{{- fail "gpu.enabled requires containerRuntime=podman" -}}
{{- else if .Values.gpu.enabled -}}
openshell-gateway-gpu
{{- else if eq .Values.containerRuntime "docker" -}}
openshell-gateway-docker
{{- else -}}
openshell-gateway
{{- end -}}
{{- end }}

{{- define "openshell-gateway-image.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "openshell-gateway-image.labels" -}}
app.kubernetes.io/name: {{ include "openshell-gateway-image.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "openshell-gateway-image.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- end }}
