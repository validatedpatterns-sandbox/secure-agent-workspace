{{- define "openshell-rhdh.labels" -}}
app.kubernetes.io/part-of: openshell-rhdh
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "openshell-rhdh.domain" -}}
{{- required "global.clusterDomain is required" .Values.global.clusterDomain -}}
{{- end -}}

{{- define "openshell-rhdh.host" -}}
{{- .Values.rhdh.host | default (printf "backstage-%s-%s.apps.%s" .Values.rhdh.name .Values.rhdh.namespace (include "openshell-rhdh.domain" .)) -}}
{{- end -}}

{{- define "openshell-rhdh.url" -}}
{{- printf "https://%s" (include "openshell-rhdh.host" .) -}}
{{- end -}}

{{- define "openshell-rhdh.keycloakHost" -}}
{{- .Values.keycloak.host | default (printf "%s-ingress-%s.apps.%s" .Values.keycloak.name .Values.keycloak.namespace (include "openshell-rhdh.domain" .)) -}}
{{- end -}}

{{- define "openshell-rhdh.issuer" -}}
{{- printf "https://%s/realms/%s" (include "openshell-rhdh.keycloakHost" .) .Values.keycloak.realm -}}
{{- end -}}

{{/* The in-cluster RHDH service the pipeline fetches the JWKS from. */}}
{{- define "openshell-rhdh.internalUrl" -}}
{{- printf "http://backstage-%s.%s.svc:80" .Values.rhdh.name .Values.rhdh.namespace -}}
{{- end -}}

{{- /* The init container that writes the CA bundle (files/ca-bundle.py)
to the saw-ca volume, and the volumes it needs; see tls in values.yaml.
Each pod mounts saw-ca at /opt/saw-ca and reads /opt/saw-ca/ca-bundle.crt. */ -}}
{{- define "openshell-rhdh.caInitContainer" -}}
- name: saw-ca-bundle
  image: {{ .Values.portal.image }}
  command: ["python3", "/opt/saw-ca-sources/ca-bundle.py", "/opt/saw-ca/ca-bundle.crt"]
  env:
    - name: TRUSTED_CA_FILE
      value: /opt/saw-trusted-ca/ca-bundle.crt
    - name: EXTRA_CA_FILE
      value: /opt/saw-ca-sources/extra-ca.crt
    - name: SA_DIR
      value: /opt/saw-ca-sa
  volumeMounts:
    - name: saw-ca
      mountPath: /opt/saw-ca
    - name: saw-ca-sources
      mountPath: /opt/saw-ca-sources
      readOnly: true
    - name: saw-trusted-ca
      mountPath: /opt/saw-trusted-ca
      readOnly: true
    - name: saw-ca-sa
      mountPath: /opt/saw-ca-sa
      readOnly: true
  resources:
    requests: { cpu: 10m, memory: 32Mi }
    limits: { memory: 64Mi }
  securityContext:
    allowPrivilegeEscalation: false
    runAsNonRoot: true
    capabilities: { drop: [ALL] }
    seccompProfile: { type: RuntimeDefault }
{{- end -}}

{{- define "openshell-rhdh.caVolumes" -}}
- name: saw-ca
  emptyDir: {}
- name: saw-ca-sources
  configMap:
    name: saw-ca-sources
- name: saw-trusted-ca
  configMap:
    name: saw-trusted-ca
    optional: true
# The service account's token, the Kubernetes API's CA and the service CA,
# for the init container only: the RHDH operator does not mount the service
# account into its pod (automountServiceAccountToken: false), and without
# the API's CA RHDH cannot verify kubernetes.default.svc.
- name: saw-ca-sa
  projected:
    sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 3600
      - configMap:
          name: kube-root-ca.crt
          items: [{key: ca.crt, path: ca.crt}]
      - configMap:
          name: openshift-service-ca.crt
          items: [{key: service-ca.crt, path: service-ca.crt}]
          optional: true
{{- end -}}

{{- define "openshell-rhdh.caNamespaces" -}}
{{- list .Values.rhdh.namespace .Values.portal.namespace | uniq | toJson -}}
{{- end -}}

{{- define "openshell-rhdh.argoNamespace" -}}
{{- .Values.applicationSet.namespace | default .Values.global.vpArgoNamespace | default "vp-gitops" -}}
{{- end -}}

{{/*
Token the ApplicationSet controller sends to the plugin generator. It only
guards a read-only list of workspace names and profiles, so a value derived
from the release is enough and keeps renders stable.
*/}}
{{- define "openshell-rhdh.generatorToken" -}}
{{- printf "%s/%s/%s" .Release.Namespace .Release.Name .Values.portal.namespace | sha256sum -}}
{{- end -}}

{{/* saw-users values every portal workspace starts from. */}}
{{- define "openshell-rhdh.sawUsersValues" -}}
{{- $v := deepCopy (.Values.sawUsers | default dict) -}}
{{- /* The Pattern supplies overrides/saw-users.yaml to both charts. Share
      its operator defaults (including the proxy image pin), while explicit
      portal sawUsers.defaults overrides retain precedence. */ -}}
{{- if or .Values.defaults (hasKey $v "defaults") -}}
{{- $shared := deepCopy (.Values.defaults | default dict) -}}
{{- $_ := set $v "defaults" (mergeOverwrite $shared (deepCopy (index $v "defaults" | default dict))) -}}
{{- end -}}
{{- $g := dict "repoURL" .Values.global.repoURL "targetRevision" .Values.global.targetRevision
      "clusterDomain" .Values.global.clusterDomain "pattern" (.Values.global.pattern | default "secure-agent-workspace")
      "vpArgoNamespace" (.Values.global.vpArgoNamespace | default "vp-gitops") -}}
{{- if .Values.global.sshPublicKey -}}{{- $_ := set $g "sshPublicKey" .Values.global.sshPublicKey -}}{{- end -}}
{{- /* The governance engine decides each gateway's bindings (docs/apf.md). */ -}}
{{- if .Values.global.governance -}}{{- $_ := set $g "governance" (deepCopy .Values.global.governance) -}}{{- end -}}
{{- $_ := set $v "global" $g -}}
{{- $labels := deepCopy (index $v "namespaceLabels" | default dict) -}}
{{- $_ := set $labels "saw.redhat.com/portal" "true" -}}
{{- $_ := set $v "namespaceLabels" $labels -}}
{{- toJson $v -}}
{{- end -}}

{{/* The Backstage CR's apiVersion: rhdh.apiVersion, or the newest served. */}}
{{- define "openshell-rhdh.backstageApiVersion" -}}
{{- if .Values.rhdh.apiVersion -}}
{{- .Values.rhdh.apiVersion -}}
{{- else -}}
{{- $found := "" -}}
{{- range list "v1alpha5" "v1alpha4" "v1alpha3" -}}
{{- if and (not $found) ($.Capabilities.APIVersions.Has (printf "rhdh.redhat.com/%s/Backstage" .)) -}}
{{- $found = printf "rhdh.redhat.com/%s" . -}}
{{- end -}}
{{- end -}}
{{- $found | default "rhdh.redhat.com/v1alpha5" -}}
{{- end -}}
{{- end -}}
