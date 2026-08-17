{{/*
Compute Keycloak hostname from global.clusterDomain.
Priority: explicit keycloak.host > computed from global.clusterDomain.
*/}}
{{- define "openshell-rhdh.keycloakHost" -}}
  {{- if .Values.keycloak.host -}}
    {{- .Values.keycloak.host -}}
  {{- else if .Values.global -}}
    {{- if .Values.global.clusterDomain -}}
      {{- printf "%s-ingress-%s.apps.%s" .Values.keycloak.keycloakName (.Values.keycloak.keycloakNamespace | default .Values.pipelines.namespace) .Values.global.clusterDomain -}}
    {{- end -}}
  {{- end -}}
{{- end -}}

{{/*
Compute apps domain.
Priority: explicit appsDomain > computed from global.clusterDomain.
*/}}
{{- define "openshell-rhdh.appsDomain" -}}
  {{- if .Values.appsDomain -}}
    {{- .Values.appsDomain -}}
  {{- else if .Values.global -}}
    {{- if .Values.global.clusterDomain -}}
      {{- printf "apps.%s" .Values.global.clusterDomain -}}
    {{- end -}}
  {{- end -}}
{{- end -}}

{{/*
Compute RHDH base URL.
Priority: explicit baseUrl > computed from appsDomain.
*/}}
{{- define "openshell-rhdh.baseUrl" -}}
  {{- if .Values.baseUrl -}}
    {{- .Values.baseUrl -}}
  {{- else -}}
    {{- printf "https://backstage-developer-hub-%s.%s" .Values.namespace (include "openshell-rhdh.appsDomain" .) -}}
  {{- end -}}
{{- end -}}
