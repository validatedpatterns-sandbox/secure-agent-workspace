{{/* Targets are derived from the selected BOM, never a fixed profile. */}}
{{- define "portal.targets" -}}
{{- $s := .Values.site | default dict -}}
{{ required "BOM-derived sandbox targets are required" $s.targets | toJson }}
{{- end -}}
{{- define "portal.claims" -}}
{{- $claims := list -}}
{{- range $slot := include "portal.targets" . | fromJson -}}
{{- range $prefix := list "workspace-" "saw-gate-" "saw-audit-" -}}
{{- $claims = append $claims (printf "%s%s" $prefix $slot.base) -}}
{{- end -}}{{- end -}}
{{ $claims | toJson }}
{{- end -}}
