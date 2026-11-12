{{- define "saw-kubernetes.name" -}}
{{- .Release.Name -}}
{{- end -}}
{{- define "saw-kubernetes.labels" -}}
app.kubernetes.io/name: {{ include "saw-kubernetes.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: secure-agent-workspace
{{- end -}}
{{- define "saw-kubernetes.validate" -}}
{{- $k := .Values.kubernetes -}}
{{- if not $k.experimental -}}{{- fail "Kubernetes integration is experimental; set kubernetes.experimental=true only for qualification" -}}{{- end -}}
{{- if not (has .Values.deployment.mode (list "container" "kata")) -}}{{- fail "unsupported Kubernetes workspace mode" -}}{{- end -}}
{{- if or (gt (len .Release.Name) 19) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" .Release.Name)) -}}{{- fail "release name must be a DNS label of at most 19 characters" -}}{{- end -}}
{{- $ns := .Release.Namespace -}}
{{- if or (gt (len $ns) 50) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $ns)) (eq $ns "default") (hasPrefix "openshift" $ns) (hasPrefix "kube-" $ns) -}}{{- fail "gateway requires a dedicated non-system namespace of at most 50 characters" -}}{{- end -}}
{{- if not (or (.Capabilities.APIVersions.Has "agents.x-k8s.io/v1beta1/Sandbox") (.Capabilities.APIVersions.Has "agents.x-k8s.io/v1beta1")) -}}{{- fail "install the pinned Agent Sandbox v1beta1 CRD/controller before this chart" -}}{{- end -}}
{{- if not (.Capabilities.APIVersions.Has "policy.networking.k8s.io/v1alpha1/AdminNetworkPolicy") -}}{{- fail "OpenShift AdminNetworkPolicy is required for supervisor egress isolation" -}}{{- end -}}
{{- range $name, $image := dict "gateway" $k.gateway.image "supervisor" $k.supervisor.image "workload" $k.workload.image "runtime" $k.workload.runtimeImage -}}
{{- if not (regexMatch "^.+@sha256:[0-9a-f]{64}$" $image) -}}{{- fail (printf "%s image must be pinned by sha256 digest" $name) -}}{{- end -}}
{{- end -}}
{{- range $name, $secret := $k.identity -}}
{{- if or (not $secret) (gt (len $secret) 253) (not (regexMatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" $secret)) -}}{{- fail (printf "kubernetes.identity.%s requires an existing retained Secret name" $name) -}}{{- end -}}
{{- end -}}
{{- if not $k.storage.className -}}{{- fail "kubernetes.storage.className must be explicit" -}}{{- end -}}
{{- if and (eq .Values.deployment.mode "container") $k.workload.runtimeClassName -}}{{- fail "container mode must use the default workload runtime" -}}{{- end -}}
{{- if and (eq .Values.deployment.mode "kata") (not (regexMatch "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$" $k.workload.runtimeClassName)) -}}{{- fail "kata requires an approved workload RuntimeClass name" -}}{{- end -}}
{{- if not (regexMatch "^https://[^/?#@[:space:]]+(/[^?#[:space:]]*)?$" .Values.oidc.issuerUrl) -}}{{- fail "oidc.issuerUrl must be explicit HTTPS without userinfo, query or fragment" -}}{{- end -}}
{{- if not (or (regexMatch "^https://[^/?#@[:space:]]+/?$" $k.governance.endpoint) (regexMatch "^http://[a-z0-9-]+\\.[a-z0-9-]+\\.svc(\\.cluster\\.local)?:[0-9]+$" $k.governance.endpoint)) -}}{{- fail "governance endpoint must be HTTPS without userinfo or the explicitly selected in-cluster HTTP gRPC Service" -}}{{- end -}}
{{- if or (not (regexMatch "^https?://[^/?#@[:space:]]+:[0-9]+$" $k.proxy.url)) (not $k.proxy.caConfigMap) -}}{{- fail "configure the trusted credential proxy URL without userinfo and public CA ConfigMap" -}}{{- end -}}
{{- if or (not $k.network.reconcilerNamespace) (not $k.network.reconcilerLabels) -}}{{- fail "trusted reconciler namespace and exact Pod labels are required" -}}{{- end -}}
{{- if eq $k.network.reconcilerNamespace .Release.Namespace -}}{{- fail "trusted reconciler identity must be outside the runtime namespace" -}}{{- end -}}
{{- if not $k.network.gatewayEgress -}}{{- fail "explicit gateway API/DNS/OIDC/governance/proxy egress rules are required" -}}{{- end -}}
{{- range $rule := $k.network.gatewayEgress -}}
{{- if or (not $rule.to) (not $rule.ports) -}}{{- fail "gateway egress rules need nonempty destinations and ports" -}}{{- end -}}
{{- range $peer := $rule.to -}}
{{- if not $peer -}}{{- fail "gateway egress must not contain an empty peer" -}}{{- end -}}
{{- if hasKey $peer "namespaceSelector" -}}
{{- if and (empty $peer.namespaceSelector.matchLabels) (empty $peer.namespaceSelector.matchExpressions) -}}{{- fail "gateway egress must not select all namespaces" -}}{{- end -}}
{{- end -}}
{{- if and $peer.ipBlock (has $peer.ipBlock.cidr (list "0.0.0.0/0" "::/0")) (not $peer.ipBlock.except) -}}{{- fail "gateway egress must not allow all addresses" -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
