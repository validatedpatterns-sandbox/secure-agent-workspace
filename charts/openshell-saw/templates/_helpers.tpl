{{- define "openshell-saw.identity" -}}
{{- list .platform.issuer .tenant.subject .tenant.name | toRawJson | sha256sum -}}
{{- end -}}

{{- define "openshell-saw.namespace" -}}
{{- printf "saw-%s-%s" (.tenant.name | trunc 33) (include "openshell-saw.identity" . | trunc 24) -}}
{{- end -}}
