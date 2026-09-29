{{/*
Fullname: release name, truncated to 63 chars (K8s label limit).
*/}}
{{- define "openshell-sandbox.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Chart label value.
*/}}
{{- define "openshell-sandbox.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "openshell-sandbox.labels" -}}
app.kubernetes.io/name: {{ include "openshell-sandbox.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "openshell-sandbox.chart" . }}
app.kubernetes.io/part-of: openshell-cnv-fedora
{{- if .Values.spiffe.testMode }}
saw.redhat.com/identity-test-run: {{ required "spiffe.testRunID is required for testMode" .Values.spiffe.testRunID | quote }}
{{- end }}
{{- end }}

{{/*
Selector labels for Service → VMI matching.
*/}}
{{- define "openshell-sandbox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openshell-sandbox.fullname" . }}
vm.kubevirt.io/name: {{ include "openshell-sandbox.fullname" . }}
{{- end }}

{{/*
Resolve the OIDC issuer URL.
Priority: explicit oidc.issuerUrl > computed from global.clusterDomain.
*/}}
{{- define "openshell-sandbox.oidcIssuerUrl" -}}
{{- if .Values.oidc.issuerUrl -}}
  {{- .Values.oidc.issuerUrl -}}
{{- else if .Values.global -}}
  {{- if .Values.global.clusterDomain -}}
    {{- printf "https://%s-ingress-%s.apps.%s/realms/%s" .Values.oidc.keycloakName (.Values.oidc.keycloakNamespace | default .Release.Namespace) .Values.global.clusterDomain .Values.oidc.realm -}}
  {{- end -}}
{{- end -}}
{{- end }}

{{/*
Validate a Kubernetes secret name (RFC 1123 subdomain).
*/}}
{{- define "openshell-sandbox.validateSecretName" -}}
{{- if and . (not (regexMatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" .)) -}}
  {{- fail (printf "invalid secret name %q — must match ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" .) -}}
{{- end -}}
{{- end }}

{{/*
Validate sandbox name does not exceed OpenShell's 19-character limit.
OpenShell rejects names longer than 19 chars with "name exceeds maximum length".
*/}}
{{- define "openshell-sandbox.validateSandboxName" -}}
{{- if gt (len .) 19 -}}
  {{- fail (printf "sandbox name %q is %d characters — OpenShell enforces a 19-character maximum" . (len .)) -}}
{{- end -}}
{{- end }}

{{/*
Resolve the external Route hostname for the gateway.
Priority: explicit route.host > computed from global.clusterDomain.
Used to add the route FQDN to the gateway TLS certificate SANs.
*/}}
{{- define "openshell-sandbox.routeHost" -}}
{{- if .Values.route.host -}}
  {{- .Values.route.host -}}
{{- else if .Values.global -}}
  {{- if .Values.global.clusterDomain -}}
    {{- printf "%s-gateway-%s.apps.%s" (include "openshell-sandbox.fullname" .) .Release.Namespace .Values.global.clusterDomain -}}
  {{- end -}}
{{- end -}}
{{- end }}

{{/*
Resolve the golden image DataSource name.
Priority: explicit source.dataSource > derived from containerRuntime.
*/}}
{{- define "openshell-sandbox.dataSourceName" -}}
{{- if .Values.source.dataSource -}}
{{- .Values.source.dataSource -}}
{{- else if eq .Values.containerRuntime "docker" -}}
openshell-gateway-docker
{{- else -}}
openshell-gateway
{{- end -}}
{{- end }}

{{/*
Secret with the operator SSH public key(s) for KubeVirt accessCredentials:
sshPublicKeySecret if set, else the chart-created <name>-ssh-pubkey (empty
until `make openshell-saw-vm-ssh` adds a key).
*/}}
{{- define "openshell-sandbox.sshKeySecretName" -}}
{{- .Values.sshPublicKeySecret | default (printf "%s-ssh-pubkey" (include "openshell-sandbox.fullname" .)) -}}
{{- end }}

{{/*
Resolve the SSH public key.
Priority: explicit sshPublicKey > global.sshPublicKey.
*/}}
{{- define "openshell-sandbox.sshPublicKey" -}}
{{- if .Values.sshPublicKey -}}
  {{- .Values.sshPublicKey -}}
{{- else if .Values.global -}}
  {{- if .Values.global.sshPublicKey -}}
    {{- .Values.global.sshPublicKey -}}
  {{- end -}}
{{- end -}}
{{- end }}

{{/*
Hostname of an auxiliary route (webui/dashboard). Priority: explicit value >
computed from global.clusterDomain (OpenShift's default <name>-<ns>.apps.<domain>).
Call with (list $ "webui" .Values.route.webuiHost).
*/}}
{{- define "openshell-sandbox.auxRouteHost" -}}
{{- $root := index . 0 -}}
{{- $suffix := index . 1 -}}
{{- $explicit := index . 2 -}}
{{- if $explicit -}}
  {{- $explicit -}}
{{- else if $root.Values.global -}}
  {{- if $root.Values.global.clusterDomain -}}
    {{- printf "%s-%s-%s.apps.%s" (include "openshell-sandbox.fullname" $root) $suffix $root.Release.Namespace $root.Values.global.clusterDomain -}}
  {{- end -}}
{{- end -}}
{{- end }}

{{/*
Governance interceptor gRPC endpoint reachable from the VM.
*/}}
{{- define "openshell-sandbox.governanceEndpoint" -}}
{{- .Values.governance.endpoint | default (printf "http://governance-interceptor.%s.svc.cluster.local:%v" (.Values.governance.namespace | default .Release.Namespace) (.Values.governance.port | default 18081)) -}}
{{- end }}

{{/*
Namespace of Keycloak's "<keycloakName>-initial-admin" Secret.
*/}}
{{- define "openshell-sandbox.keycloakNamespace" -}}
{{- .Values.dashboard.keycloakNamespace | default .Values.oidc.keycloakNamespace | default .Release.Namespace -}}
{{- end }}

{{/*
Namespace of the golden image DataSource.
*/}}
{{- define "openshell-sandbox.goldenNamespace" -}}
{{- .Values.source.dataSourceNamespace | default .Release.Namespace -}}
{{- end }}

{{/*
Provider credential Secrets attached to the VM, de-duplicated, as JSON list.
*/}}
{{- define "openshell-sandbox.providerSecrets" -}}
{{- $names := list -}}
{{- if .Values.inference.secretName -}}{{- $names = append $names .Values.inference.secretName -}}{{- end -}}
{{- range .Values.additionalProviderSecrets -}}
  {{- if and . (not (has . $names)) -}}{{- $names = append $names . -}}{{- end -}}
{{- end -}}
{{- toJson $names -}}
{{- end }}

{{/*
Gateway environment file. Written by cloud-init on first boot (the golden
image's first-boot setup copies it) and re-synced by the installer on every
boot, so later chart changes reach existing VMs after a restart.
*/}}
{{- define "openshell-sandbox.gatewayEnv" -}}
{{- $routeHost := include "openshell-sandbox.routeHost" . -}}
OPENSHELL_BIND_ADDRESS={{ .Values.openshell.bindAddress | quote }}
OPENSHELL_SERVER_PORT=17670
OPENSHELL_DRIVERS=podman
OPENSHELL_SSH_GATEWAY_PORT=17670
OPENSHELL_TLS_CERT=/home/cloud-user/.local/state/openshell/tls/server/tls.crt
OPENSHELL_TLS_KEY=/home/cloud-user/.local/state/openshell/tls/server/tls.key
OPENSHELL_TLS_CLIENT_CA=/home/cloud-user/.local/state/openshell/tls/ca.crt
OPENSHELL_CONFIG_FILE=/etc/openshell/gateway.toml
# The in-VM installer authenticates with the local mTLS client
# certificate. End users authenticate with OIDC bearer tokens.
OPENSHELL_ENABLE_MTLS_AUTH=true
{{- if .Values.spiffe.enabled }}
OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET=/spiffe-workload-api/agent.sock
{{- end }}
{{- if $routeHost }}
OPENSHELL_ROUTE_FQDN={{ $routeHost }}
{{- end }}
{{- end }}

{{/*
Gateway TOML: OIDC for users (roles from the token), podman supervisor image
from the BOM, governance interceptor.
*/}}
{{- define "openshell-sandbox.gatewayToml" -}}
{{- $oidcIssuer := include "openshell-sandbox.oidcIssuerUrl" . -}}
{{- if $oidcIssuer }}
[openshell.gateway.oidc]
issuer = {{ $oidcIssuer | quote }}
audience = {{ .Values.oidc.clientId | quote }}
roles_claim = {{ .Values.oidc.rolesClaim | quote }}
admin_role = {{ .Values.oidc.adminRole | quote }}
user_role = {{ .Values.oidc.userRole | quote }}

[openshell.gateway.auth]
allow_unauthenticated_users = false

{{ end -}}
[openshell.drivers.podman]
supervisor_image = {{ .Values.bom.spec.openshell.supervisor.image | quote }}
{{- if .Values.spiffe.enabled }}
provider_spiffe_workload_api_socket = "/spiffe-workload-api/agent.sock"
{{- end }}
{{- if .Values.governance.enabled }}

[openshell.gateway]
provider_profile_sources = [
  { type = "interceptor", name = "governance" },
]

[[openshell.gateway.interceptors]]
name           = "governance"
grpc_endpoint  = {{ include "openshell-sandbox.governanceEndpoint" . | quote }}
allow_insecure_transport = {{ .Values.governance.allowInsecureTransport }}
order          = 10
failure_policy = {{ .Values.governance.failurePolicy | quote }}
binding_policy = "allowlist"
timeout        = {{ .Values.governance.timeout | quote }}

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["modify_operation", "validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateProvider"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateConfig"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/SubmitPolicyAnalysis"
phases = ["validate"]
{{- end }}
{{- end }}
