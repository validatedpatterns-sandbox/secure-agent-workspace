{{- define "saw-codex-api.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "saw-codex-api.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "saw-codex-api.labels" -}}
app.kubernetes.io/name: {{ include "saw-codex-api.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "saw-codex-api.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- end }}

{{- define "saw-codex-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "saw-codex-api.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resolve the OIDC issuer URL.
Priority: explicit oidc.issuerUrl > computed from global.clusterDomain.
*/}}
{{- define "saw-codex-api.oidcIssuerUrl" -}}
{{- if .Values.oidc.issuerUrl -}}
  {{- .Values.oidc.issuerUrl -}}
{{- else if .Values.global -}}
  {{- if .Values.global.clusterDomain -}}
    {{- printf "https://openshell-keycloak-ingress-%s.apps.%s/realms/openshell" .Release.Namespace .Values.global.clusterDomain -}}
  {{- end -}}
{{- end -}}
{{- end }}
