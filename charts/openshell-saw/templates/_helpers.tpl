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
OPENSHELL_COMPUTE_DRIVER=podman
OPENSHELL_TLS_CERT=/home/cloud-user/.local/state/openshell/tls/server/tls.crt
OPENSHELL_TLS_KEY=/home/cloud-user/.local/state/openshell/tls/server/tls.key
OPENSHELL_TLS_CLIENT_CA=/home/cloud-user/.local/state/openshell/tls/ca.crt
# The copy the installer keeps in the runtime user's config dir (also the
# gateway's XDG default); /etc/openshell holds the chart's copy.
OPENSHELL_GATEWAY_CONFIG=/home/cloud-user/.config/openshell/gateway.toml
# The in-VM installer authenticates with the local mTLS client
# certificate. End users authenticate with OIDC bearer tokens.
OPENSHELL_ENABLE_MTLS_AUTH=true
{{- if $routeHost }}
OPENSHELL_ROUTE_FQDN={{ $routeHost }}
{{- end }}
{{- end }}

{{/*
Gateway TOML, schema version 2 (OpenShell 0.1.x): OIDC for users (roles from
the token), the podman compute driver with the supervisor and sandbox runtime
images from the BOM, and the governance interceptor as the only provider
profile source. 0.1.x rejects a file without `[openshell] version = 2`, and a
v2 file on a 0.0.x gateway, so this must match the BOM's gateway version.
TOML allows each table once: everything for [openshell.gateway] stays in the
one table below, before its sub-tables.
*/}}
{{- define "openshell-sandbox.gatewayToml" -}}
{{- $oidcIssuer := include "openshell-sandbox.oidcIssuerUrl" . -}}
[openshell]
version = 2

[openshell.gateway]
compute_driver = "podman"
{{- if .Values.governance.enabled }}
# Only the governance interceptor vends provider profiles; imported
# profiles are not used.
provider_profile_sources = [
  { type = "interceptor", name = "governance" },
]
{{- end }}
{{- if $oidcIssuer }}

[openshell.gateway.oidc]
issuer = {{ $oidcIssuer | quote }}
audience = {{ .Values.oidc.clientId | quote }}
roles_claim = {{ .Values.oidc.rolesClaim | quote }}
admin_role = {{ .Values.oidc.adminRole | quote }}
user_role = {{ .Values.oidc.userRole | quote }}

[openshell.gateway.auth]
allow_unauthenticated_users = false
{{- end }}

[openshell.drivers.podman]
supervisor_image = {{ .Values.bom.spec.openshell.supervisor.image | quote }}
sandbox_runtime_image = {{ .Values.bom.spec.openshell.sandbox.image | quote }}
{{- if .Values.governance.enabled }}

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


{{/*
Sandbox UI routes: sandboxUi entries with the route host filled in,
<vm>-<workspace>-<sandbox>-ui.apps.<clusterDomain> (at most 62 characters
in its first label with 19-character names), or entry.host when set.
*/}}
{{- define "openshell-sandbox.sandboxUi" -}}
{{- $root := . -}}
{{- $out := list -}}
{{- $seen := dict -}}
{{- range $e := .Values.sandboxUi | default list -}}
{{- $ws := $e.workspace | default "" | toString -}}
{{- $sb := $e.sandbox | default "" | toString -}}
{{- if not (and (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $ws) (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $sb)) -}}
{{- fail (printf "sandboxUi: workspace %q and sandbox %q must be lowercase DNS labels" $ws $sb) -}}
{{- end -}}
{{- if not (and $e.proxyPort $e.forwardPort) -}}
{{- fail (printf "sandboxUi %s/%s needs proxyPort and forwardPort" $ws $sb) -}}
{{- end -}}
{{- $label := printf "%s-%s-%s-ui" (include "openshell-sandbox.fullname" $root) $ws $sb -}}
{{- if gt (len $label) 63 -}}
{{- fail (printf "sandboxUi route label %q is %d characters; DNS labels allow 63" $label (len $label)) -}}
{{- end -}}
{{- $host := $e.host | default "" -}}
{{- if and (not $host) $root.Values.global -}}
{{- if $root.Values.global.clusterDomain -}}
{{- $host = printf "%s.apps.%s" $label $root.Values.global.clusterDomain -}}
{{- end -}}
{{- end -}}
{{- $port := int $e.proxyPort -}}
{{- if hasKey $seen (toString $port) -}}
{{- fail (printf "sandboxUi proxyPort %d is used twice" $port) -}}
{{- end -}}
{{- $_ := set $seen (toString $port) true -}}
{{- $out = append $out (dict "workspace" $ws "sandbox" $sb "name" $label "host" $host
      "proxyPort" $port "forwardPort" (int $e.forwardPort)
      "portName" (printf "ui-%d" $port)) -}}
{{- end -}}
{{- toJson $out -}}
{{- end }}
