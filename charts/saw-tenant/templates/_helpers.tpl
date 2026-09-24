{{- define "saw-tenant.identity" -}}
{{- list .spec.owner.issuer .spec.owner.subject .metadata.name | toRawJson | sha256sum -}}
{{- end -}}

{{- define "saw-tenant.namespace" -}}
{{- printf "saw-%s-%s" (.metadata.name | trunc 33) (include "saw-tenant.identity" . | trunc 24) -}}
{{- end -}}
