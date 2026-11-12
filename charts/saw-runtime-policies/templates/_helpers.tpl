{{- define "saw-runtime-policies.name" -}}
{{- printf "saw-%s-runtime" .Values.targetNamespace | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "saw-runtime-policies.validate" -}}
{{- if .Values.enabled -}}
{{- $ns := required "targetNamespace is required" .Values.targetNamespace -}}
{{- if or (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $ns)) (gt (len $ns) 50) (has $ns (list "default" "kube-system" "kube-public" "kube-node-lease")) (hasPrefix "openshift" $ns) (hasPrefix "kube-" $ns) -}}
{{- fail "targetNamespace must be an explicit non-system DNS label of at most 50 characters" -}}
{{- end -}}
{{- range $key := list "gatewayId" "gatewayServiceAccount" "sandboxServiceAccount" -}}
{{- $value := required (printf "%s is required" $key) (get $.Values $key) -}}
{{- if or (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $value)) (gt (len $value) 63) -}}
{{- fail (printf "%s must be a DNS label" $key) -}}
{{- end -}}
{{- end -}}
{{- if ne .Values.mode "container" -}}{{- fail "mode must be container" -}}{{- end -}}
{{- if eq .Values.network.priority nil -}}{{- fail "network.priority must be explicitly allocated by the administrator" -}}{{- end -}}
{{- $priority := toString .Values.network.priority -}}
{{- if or (not (regexMatch "^[0-9]+$" $priority)) (gt (int $priority) 99) -}}{{- fail "network.priority must be an integer from 0 to 99" -}}{{- end -}}
{{- if not .Values.network.egress -}}{{- fail "network.egress must declare the required supervisor destinations" -}}{{- end -}}
{{- if not (.Capabilities.APIVersions.Has "policy.networking.k8s.io/v1alpha1/AdminNetworkPolicy") -}}{{- fail "AdminNetworkPolicy API is required; install/reuse supported OVN-Kubernetes enforcement first" -}}{{- end -}}
{{- if not (.Capabilities.APIVersions.Has "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy") -}}{{- fail "native ValidatingAdmissionPolicy API is required" -}}{{- end -}}
{{- $names := dict "deny-other-egress" true -}}
{{- range $rule := .Values.network.egress -}}
{{- if hasKey $names $rule.name -}}{{- fail "network.egress rule names must be unique and must not use deny-other-egress" -}}{{- end -}}
{{- $_ := set $names $rule.name true -}}
{{- if or (not $rule.to) (not $rule.ports) -}}{{- fail "each network.egress rule requires explicit to and ports" -}}{{- end -}}
{{- range $peer := $rule.to -}}
{{- if eq (len $peer) 0 -}}{{- fail "network.egress cannot contain an empty peer" -}}{{- end -}}
{{- if hasKey $peer "namespaces" -}}
{{- if and (empty $peer.namespaces.matchLabels) (empty $peer.namespaces.matchExpressions) -}}{{- fail "network.egress namespace selectors must be explicit" -}}{{- end -}}
{{- end -}}
{{- if hasKey $peer "pods" -}}
{{- if and (empty $peer.pods.namespaceSelector.matchLabels) (empty $peer.pods.namespaceSelector.matchExpressions) -}}{{- fail "network.egress pod peers need explicit namespace selectors" -}}{{- end -}}
{{- if and (empty $peer.pods.podSelector.matchLabels) (empty $peer.pods.podSelector.matchExpressions) -}}{{- fail "network.egress pod peers need explicit pod selectors" -}}{{- end -}}
{{- end -}}
{{- range $cidr := $peer.networks | default list -}}
{{- if has $cidr (list "0.0.0.0/0" "::/0") -}}{{- fail "network.egress cannot pass every destination; use approved explicit CIDRs" -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
