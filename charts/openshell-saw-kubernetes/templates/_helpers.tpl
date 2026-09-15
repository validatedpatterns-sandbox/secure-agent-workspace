{{- define "openshell-k8s.fullname" -}}
{{- .Values.sessionName | default .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "openshell-k8s.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "openshell-k8s.labels" -}}
app.kubernetes.io/name: {{ include "openshell-k8s.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "openshell-k8s.chart" . }}
app.kubernetes.io/part-of: codex-saw
{{- if .Values.owner }}
openshell.pattern/owner: {{ .Values.owner | quote }}
{{- end }}
{{- end }}

{{- define "openshell-k8s.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openshell-k8s.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "openshell-k8s.gatewaySA" -}}
{{ include "openshell-k8s.fullname" . }}-gateway
{{- end }}

{{- define "openshell-k8s.sandboxSA" -}}
{{ include "openshell-k8s.fullname" . }}-sandbox
{{- end }}

{{/*
Auto-derive OIDC issuer URL from global.clusterDomain if available.
*/}}
{{- define "openshell-k8s.oidcIssuerUrl" -}}
{{- if .Values.oidc.issuerUrl -}}
  {{- .Values.oidc.issuerUrl -}}
{{- else if .Values.global -}}
  {{- if .Values.global.clusterDomain -}}
    {{- printf "https://openshell-keycloak-ingress-openshell-agents.apps.%s/realms/openshell" .Values.global.clusterDomain -}}
  {{- end -}}
{{- end -}}
{{- end }}
