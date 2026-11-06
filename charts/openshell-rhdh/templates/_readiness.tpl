{{/* Keep the UI's bounded status polling aligned with the Tekton wait. */}}
{{- define "openshell-rhdh.readinessTemplate" -}}
{{- $template := .template -}}
{{- $minutes := int .root.Values.portal.sandboxReadyTimeoutMinutes -}}
{{- range $step := $template.spec.steps -}}
{{- if eq $step.id "task-sandboxes" -}}
{{- $_ := set $step "each" (untilStep 1 (int (add (mul (add $minutes 2) 3) 1)) 1) -}}
{{- $_ := set $step "name" "Install OpenShell and wait for sandbox readiness" -}}
{{- end -}}
{{- end -}}
{{- toYaml $template | replace "__PROVISIONER_SA__" .root.Values.portal.provisionerServiceAccount -}}
{{- end -}}
