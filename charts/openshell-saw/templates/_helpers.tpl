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
    {{- printf "https://%s-ingress-%s.apps.%s/realms/%s" .Values.oidc.keycloakName .Release.Namespace .Values.global.clusterDomain .Values.oidc.realm -}}
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
