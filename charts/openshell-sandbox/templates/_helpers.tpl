{{/*
Fullname: release name, truncated to 63 chars (K8s label limit).
*/}}
{{- define "openshell-sandbox.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Chart label value.
*/}}
{{- define "openshell-sandbox.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "openshell-sandbox.labels" -}}
app.kubernetes.io/name: {{ include "openshell-sandbox.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "openshell-sandbox.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- end }}

{{/*
Selector labels for Service → VMI matching.
*/}}
{{- define "openshell-sandbox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openshell-sandbox.fullname" . }}
vm.kubevirt.io/name: {{ include "openshell-sandbox.fullname" . }}
{{- end }}

{{/*
Resolve the OIDC issuer URL.
Priority: explicit oidc.issuerUrl > computed from global.clusterDomain.
*/}}
{{- define "openshell-sandbox.oidcIssuerUrl" -}}
{{- if .Values.oidc.issuerUrl -}}
  {{- .Values.oidc.issuerUrl -}}
{{- else if .Values.global -}}
  {{- if .Values.global.clusterDomain -}}
    {{- printf "https://%s-ingress-%s.apps.%s/realms/%s" .Values.oidc.keycloakName .Release.Namespace .Values.global.clusterDomain .Values.oidc.realm -}}
  {{- end -}}
{{- end -}}
{{- end }}
