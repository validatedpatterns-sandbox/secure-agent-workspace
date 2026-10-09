{{/* interceptor or apf; global.governance.engine (the pattern's switch) wins. */}}
{{- define "governance.engine" -}}
{{- $global := .Values.global | default dict -}}
{{- $engine := (($global.governance | default dict).engine | default .Values.engine) | toString -}}
{{- if not (has $engine (list "interceptor" "apf")) -}}
{{- fail (printf "governance engine must be interceptor or apf, not %q" $engine) -}}
{{- end -}}
{{- $engine -}}
{{- end -}}

{{/* Labels the serving pod carries: the APF chart names them after itself. */}}
{{- define "governance.podSelector" -}}
{{- if eq (include "governance.engine" .) "apf" -}}
app.kubernetes.io/name: {{ .Values.apf.chart.name }}
app.kubernetes.io/instance: {{ .Values.apf.values.fullnameOverride }}
{{- else -}}
app.kubernetes.io/name: governance-interceptor
{{- end -}}
{{- end -}}

{{- define "governance.argoNamespace" -}}
{{- $global := .Values.global | default dict -}}
{{- $global.vpArgoNamespace | default .Values.argo.namespace -}}
{{- end -}}

{{/* The APF chart's values, pointed at the Secrets and ConfigMaps this chart provides. */}}
{{- define "governance.apfValues" -}}
{{- $v := deepCopy .Values.apf.values -}}
{{- $_ := set $v "image" (dict "pullSecrets" (list (dict "name" .Values.apf.pullSecret))) -}}
{{- $bundle := deepCopy ($v.bundle | default dict) -}}
{{- $_ := set $bundle "existingConfigMap" .Values.apf.bundleConfigMap -}}
{{- $_ := set $v "bundle" $bundle -}}
{{- $_ := set $v "trustRoot" (dict "existingConfigMap" .Values.apf.trustConfigMap) -}}
{{- $_ := set $v "signing" (dict "existingSecret" .Values.apf.signingSecret) -}}
{{- /* The APF chart only restarts its pod for inputs it renders itself. */ -}}
{{- $sum := printf "%s%s" (.Files.Get "files/apf/bundle.tar.gz") (.Files.Get "files/apf/apf.pub") | sha256sum -}}
{{- $ann := deepCopy ($v.podAnnotations | default dict) -}}
{{- $_ := set $ann "governance.openshell.pattern/bundle-checksum" $sum -}}
{{- $_ := set $v "podAnnotations" $ann -}}
{{- toYaml $v -}}
{{- end -}}
