{{/* Match the duration returned by Tekton's Go API for GitOps comparison. */}}
{{- define "openshell-rhdh.minutesDuration" -}}
{{- if ge (int .) 60 -}}{{ printf "%dh%dm0s" (div (int .) 60) (mod (int .) 60) }}{{- else -}}{{ printf "%dm0s" (int .) }}{{- end -}}
{{- end -}}
{{/* Keep the UI's bounded status polling aligned with the Tekton wait. */}}
{{- define "openshell-rhdh.readinessTemplate" -}}
{{- $template := .template -}}
{{- $minutes := int .root.Values.portal.sandboxReadyTimeoutMinutes -}}
{{- $container := or (has "container" .root.Values.portal.deploymentModes) (has "kata" .root.Values.portal.deploymentModes) -}}
{{- $enrollmentTaskMinutes := add (max 10 $minutes) 2 -}}
{{- range $step := $template.spec.steps -}}
{{- if and $container (eq $step.id "task-vm") -}}
{{- $_ := set $step "each" (untilStep 1 (int (add (mul $enrollmentTaskMinutes 3) 1)) 1) -}}
{{- end -}}
{{- if and $container (eq $step.id "run") (eq $step.input.body.spec.pipelineRef.name "saw-workspace-create") -}}
{{- /* Register (5), apps (12), running (17), ready (+2), plus two minutes to schedule. */ -}}
{{- $_ := set $step.input.body.spec.timeouts "pipeline" (include "openshell-rhdh.minutesDuration" (max 90 (add 38 $enrollmentTaskMinutes $minutes))) -}}
{{- end -}}
{{- if eq $step.id "task-sandboxes" -}}
{{- $_ := set $step "each" (untilStep 1 (int (add (mul (add $minutes 2) 3) 1)) 1) -}}
{{- $_ := set $step "name" "Install OpenShell and wait for sandbox readiness" -}}
{{- end -}}
{{- end -}}
{{- toYaml $template | replace "__PROVISIONER_SA__" .root.Values.portal.provisionerServiceAccount -}}
{{- end -}}
