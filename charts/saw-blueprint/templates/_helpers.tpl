{{- define "saw-blueprint.identity" -}}
{{- list .issuer .subject .name | toRawJson | sha256sum -}}
{{- end -}}

{{- define "saw-blueprint.namespace" -}}
{{- printf "saw-%s-%s" (.name | trunc 33) (include "saw-blueprint.identity" . | trunc 24) -}}
{{- end -}}

{{- define "saw-blueprint.imageName" -}}
{{- printf "%s-%s" (.name | trunc 25) (. | toRawJson | sha256sum | trunc 24) -}}
{{- end -}}

{{- define "saw-blueprint.retain" -}}
argocd.argoproj.io/sync-options: Prune=false,Delete=false
{{- end -}}
