{{- define "openshell-rhdh.labels" -}}
app.kubernetes.io/part-of: openshell-rhdh
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "openshell-rhdh.domain" -}}
{{- required "global.clusterDomain is required" .Values.global.clusterDomain -}}
{{- end -}}

{{- define "openshell-rhdh.host" -}}
{{- .Values.rhdh.host | default (printf "backstage-%s-%s.apps.%s" .Values.rhdh.name .Values.rhdh.namespace (include "openshell-rhdh.domain" .)) -}}
{{- end -}}

{{- define "openshell-rhdh.url" -}}
{{- printf "https://%s" (include "openshell-rhdh.host" .) -}}
{{- end -}}

{{- define "openshell-rhdh.keycloakHost" -}}
{{- .Values.keycloak.host | default (printf "%s-ingress-%s.apps.%s" .Values.keycloak.name .Values.keycloak.namespace (include "openshell-rhdh.domain" .)) -}}
{{- end -}}

{{- define "openshell-rhdh.issuer" -}}
{{- printf "https://%s/realms/%s" (include "openshell-rhdh.keycloakHost" .) .Values.keycloak.realm -}}
{{- end -}}

{{/* The in-cluster RHDH service the pipeline fetches the JWKS from. */}}
{{- define "openshell-rhdh.internalUrl" -}}
{{- printf "http://backstage-%s.%s.svc:80" .Values.rhdh.name .Values.rhdh.namespace -}}
{{- end -}}

{{- define "openshell-rhdh.argoNamespace" -}}
{{- .Values.applicationSet.namespace | default .Values.global.vpArgoNamespace | default "vp-gitops" -}}
{{- end -}}

{{/*
Token the ApplicationSet controller sends to the plugin generator. It only
guards a read-only list of workspace names and profiles, so a value derived
from the release is enough and keeps renders stable.
*/}}
{{- define "openshell-rhdh.generatorToken" -}}
{{- printf "%s/%s/%s" .Release.Namespace .Release.Name .Values.portal.namespace | sha256sum -}}
{{- end -}}

{{/* saw-users values every portal workspace starts from. */}}
{{- define "openshell-rhdh.sawUsersValues" -}}
{{- $v := deepCopy (.Values.sawUsers | default dict) -}}
{{- $g := dict "repoURL" .Values.global.repoURL "targetRevision" .Values.global.targetRevision
      "clusterDomain" .Values.global.clusterDomain "pattern" (.Values.global.pattern | default "secure-agent-workspace")
      "vpArgoNamespace" (.Values.global.vpArgoNamespace | default "vp-gitops") -}}
{{- if .Values.global.sshPublicKey -}}{{- $_ := set $g "sshPublicKey" .Values.global.sshPublicKey -}}{{- end -}}
{{- $_ := set $v "global" $g -}}
{{- $labels := deepCopy (index $v "namespaceLabels" | default dict) -}}
{{- $_ := set $labels "saw.redhat.com/portal" "true" -}}
{{- $_ := set $v "namespaceLabels" $labels -}}
{{- toJson $v -}}
{{- end -}}

{{/* The Backstage CR's apiVersion: rhdh.apiVersion, or the newest served. */}}
{{- define "openshell-rhdh.backstageApiVersion" -}}
{{- if .Values.rhdh.apiVersion -}}
{{- .Values.rhdh.apiVersion -}}
{{- else -}}
{{- $found := "" -}}
{{- range list "v1alpha5" "v1alpha4" "v1alpha3" -}}
{{- if and (not $found) ($.Capabilities.APIVersions.Has (printf "rhdh.redhat.com/%s/Backstage" .)) -}}
{{- $found = printf "rhdh.redhat.com/%s" . -}}
{{- end -}}
{{- end -}}
{{- $found | default "rhdh.redhat.com/v1alpha5" -}}
{{- end -}}
{{- end -}}
