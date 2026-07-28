{{- define "openshell-keycloak.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "openshell-keycloak.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "openshell-keycloak.labels" -}}
app.kubernetes.io/name: {{ include "openshell-keycloak.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "openshell-keycloak.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- end }}

{{- define "openshell-keycloak.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openshell-keycloak.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
