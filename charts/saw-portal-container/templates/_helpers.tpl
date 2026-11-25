{{/* Targets are derived from the selected BOM, never a fixed profile. */}}
{{- define "portal.targets" -}}
{{- $s := include "portal.site" . | fromJson -}}
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

{{/* The namespace whose ImageStreams the runtime image is pulled from: the
site's buildNamespace when the image is in the OpenShift internal registry,
else "" (a published image needs no pull grant, and the namespace need not
exist). Takes the enrollment or automaticEnrollment dict. */}}
{{- define "portal.pullNamespace" -}}
{{- if hasPrefix "image-registry.openshift-image-registry.svc:5000/" (.image | default "") -}}{{ .buildNamespace }}{{- end -}}
{{- end -}}

{{/* Chart revisions a site may use. Reviewed sites pin every chart to a full
commit SHA; an autoApprove (development) site may follow a branch. The
portal and installer preflight apply the same rule (preflight.py). */}}
{{- define "portal.revisionPattern" -}}
{{- $a := (include "portal.site" . | fromJson).automaticEnrollment | default dict -}}
{{- if eq (toString ($a.autoApprove | default false)) "true" -}}^[A-Za-z0-9][A-Za-z0-9._/-]*${{- else -}}^[a-f0-9]{40}${{- end -}}
{{- end -}}

{{/* Recursive merge of .over into .base by key presence (as saw-users.deepMerge):
a false, 0 or "" in .over replaces the base value. Maps merge; every other
value (lists included) is replaced. Returns JSON. */}}
{{- define "portal.deepMerge" -}}
{{- $out := deepCopy (.base | default dict) -}}
{{- range $key, $value := (.over | default dict) -}}
{{- $current := index $out $key -}}
{{- if and (kindIs "map" $value) (kindIs "map" $current) -}}
{{- $_ := set $out $key (include "portal.deepMerge" (dict "base" $current "over" $value) | fromJson) -}}
{{- else -}}
{{- $_ := set $out $key $value -}}
{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/* The site layered over siteDefaults. A published enrollment carries the
site's relay settings and build namespace; fill what the site left to the
defaults, and let the relay follow the enrollment revision. Returns JSON. */}}
{{- define "portal.site" -}}
{{- $site := include "portal.deepMerge" (dict "base" .Values.siteDefaults "over" (.Values.site | default dict)) | fromJson -}}
{{- with $site.enrollment -}}
{{- $a := $site.automaticEnrollment -}}
{{- $_ := set . "relay" (include "portal.deepMerge" (dict "base" ($a.relay | default dict) "over" (.relay | default dict)) | fromJson) -}}
{{- if not .relay.revision }}{{ $_ := set .relay "revision" .revision }}{{ end -}}
{{- if not .buildNamespace }}{{ $_ := set . "buildNamespace" $a.buildNamespace }}{{ end -}}
{{- end -}}
{{- toJson $site -}}
{{- end -}}
