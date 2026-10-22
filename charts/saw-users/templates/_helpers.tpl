{{/*
Fail the render on a bad user list, or when the Argo CD namespace and git
source cannot be resolved. Applications must land in the namespace Argo CD
watches, not in whatever namespace this chart happens to be released into.
*/}}
{{- define "saw-users.validate" -}}
{{- $argoNS := .Values.global.vpArgoNamespace | default .Values.argo.namespace -}}
{{- if not $argoNS -}}
{{- fail "set global.vpArgoNamespace or argo.namespace so Applications are created in the Argo CD namespace" -}}
{{- end -}}
{{- if not .Values.global.repoURL -}}
{{- fail "global.repoURL is required" -}}
{{- end -}}
{{- if not .Values.global.targetRevision -}}
{{- fail "global.targetRevision is required" -}}
{{- end -}}
{{- $seen := dict -}}
{{- range .Values.users | default list -}}
{{- $name := .name | default "" | toString -}}
{{- if $.Values.ownerResolution.enabled -}}
{{- $entryValues := .values | default dict -}}
{{- $entryAccess := index $entryValues "accessControl" | default dict -}}
{{- if or (hasKey . "ownerSubject") (hasKey $entryAccess "ownerSubject") (hasKey $entryAccess "owner") -}}
{{- fail (printf "user %q: ownerResolution uses name as the only owner; remove ownerSubject and accessControl owner overrides" $name) -}}
{{- end -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name) -}}
{{- fail (printf "user name %q must be a lowercase DNS label (letters, digits, and hyphens; must start and end with a letter or digit)" $name) -}}
{{- end -}}
{{- if gt (len $name) 19 -}}
{{- fail (printf "user name %q is too long: it names the VM (%d characters) and OpenShell allows 19" $name (len $name)) -}}
{{- end -}}
{{- $route := printf "%s-dashboard-saw-%s" $name $name -}}
{{- if gt (len $route) 63 -}}
{{- fail (printf "user name %q makes dashboard route label %q %d characters; DNS labels allow 63" $name $route (len $route)) -}}
{{- end -}}
{{- if or (hasSuffix "-bom" $name) (hasSuffix "-secrets" $name) -}}
{{- fail (printf "user name %q ends in -bom or -secrets: its Argo CD applications would take another user's names" $name) -}}
{{- end -}}
{{- if hasKey $seen $name -}}
{{- fail (printf "duplicate user name %q" $name) -}}
{{- end -}}
{{- $_ := set $seen $name "1" -}}
{{- end -}}
{{- end -}}

{{- define "saw-users.argoNamespace" -}}
{{- .Values.global.vpArgoNamespace | default .Values.argo.namespace -}}
{{- end -}}

{{/*
global.* values: openshell-saw only gets the keys in machineGlobals, when
non-empty (an empty helm parameter makes Argo CD flap OutOfSync; framework
internals such as deletePattern are not copied).
*/}}

{{/*
Whether removing this user also deletes the VM and namespace: the user's
own pruneOnRemove, else the chart-wide default. "true" or "".
*/}}
{{- define "saw-users.prune" -}}
{{- $user := .user -}}
{{- $prune := .root.Values.pruneOnRemove -}}
{{- if hasKey $user "pruneOnRemove" -}}
{{- $prune = $user.pruneOnRemove -}}
{{- end -}}
{{- if $prune -}}true{{- end -}}
{{- end -}}

{{/*
Web search: the user's webSearch.enabled, else global.webSearch.enabled,
else on. Pattern extraParameters may supply the string "false". "true" or "".
*/}}
{{- define "saw-users.webSearch" -}}
{{- $enabled := true -}}
{{- $global := .root.Values.global.webSearch | default dict -}}
{{- $user := .user.webSearch | default dict -}}
{{- if hasKey $global "enabled" -}}
{{- $enabled = $global.enabled -}}
{{- end -}}
{{- if hasKey $user "enabled" -}}
{{- $enabled = $user.enabled -}}
{{- end -}}
{{- if ne (toString $enabled) "false" -}}true{{- end -}}
{{- end -}}

{{/*
openshell-saw values: chart defaults, then this user's owner, then the
user's `values` on top. Nested maps merge; the user's keys win.
*/}}
{{- define "saw-users.openshellValues" -}}
{{- $user := .user -}}
{{- $root := .root -}}
{{- $base := deepCopy ($root.Values.defaults.openshellSaw | default dict) -}}
{{- $ac := deepCopy (index $base "accessControl" | default dict) -}}
{{- $_ := set $ac "owner" $user.name -}}
{{- $_ := set $ac "ownerSubject" ($user.ownerSubject | default "" | toString) -}}
{{- $_ := set $base "accessControl" $ac -}}
{{- $globals := dict -}}
{{- range $k := $root.Values.machineGlobals | default list -}}
{{- $v := index $root.Values.global $k -}}
{{- if $v -}}
{{- $_ := set $globals $k $v -}}
{{- end -}}
{{- end -}}
{{- $_ := set $base "global" $globals -}}
{{- /* Argo CD runs the chart's pre-delete hook when the app is deleted: only
     users with pruneOnRemove get it, the others keep their VM. */ -}}
{{- $_ := set $base "cleanupOnDelete" (eq (include "saw-users.prune" (dict "root" $root "user" $user)) "true") -}}
{{- $_ := set $base "sandboxUi" (include "saw-users.sandboxUi" . | fromJsonArray) -}}
{{- /* The provider Secrets the VM mounts and waits for: the ones the user's
     profiles read, which is also what pattern-secrets syncs. */ -}}
{{- $secretNames := include "saw-users.secretNames" . | fromJsonArray -}}
{{- $inf := deepCopy (index $base "inference" | default dict) -}}
{{- $_ := set $inf "secretName" (ternary "inference" "" (has "inference" $secretNames)) -}}
{{- $_ := set $base "inference" $inf -}}
{{- $extra := list -}}
{{- range $secretNames -}}{{- if ne . "inference" -}}{{- $extra = append $extra . -}}{{- end -}}{{- end -}}
{{- $_ := set $base "additionalProviderSecrets" $extra -}}
{{- /* The cluster's ingress CA, synced by pattern-secrets; openshell-saw only
     uses it for the in-cluster Keycloak without an explicit caBundle. */ -}}
{{- $oidc := deepCopy (index $base "oidc" | default dict) -}}
{{- if not (hasKey $oidc "clusterCaSecret") -}}
{{- $_ := set $oidc "clusterCaSecret" ($root.Values.defaults.clusterCaSecret | default "") -}}
{{- end -}}
{{- $_ := set $base "oidc" $oidc -}}
{{- /* harnessEnabled puts a harnessRef on a sandbox, which OpenShell 0.1.x
     refuses to mount without allow_driver_config; derive it here so the two
     flags can't drift apart. The user's own `values.allowDriverConfig`
     still wins if set. */ -}}
{{- if $user.harnessEnabled -}}
{{- $_ := set $base "allowDriverConfig" true -}}
{{- end -}}
{{- $overlay := deepCopy ($user.values | default dict) -}}
{{- if $root.Values.ownerResolution.enabled -}}
{{- $_ := set $ac "ownerSubjectSource" "resolved" -}}
{{- end -}}
{{- mergeOverwrite $base $overlay | toYaml -}}
{{- end -}}

{{/*
The user's profile names: their own `profiles`, else the default.
*/}}
{{- define "saw-users.profileNames" -}}
{{- $user := .user -}}
{{- $profiles := .root.Values.defaults.profiles -}}
{{- if hasKey $user "profiles" -}}
{{- $profiles = $user.profiles -}}
{{- end -}}
{{- toJson ($profiles | default list) -}}
{{- end -}}

{{/*
The catalog entries (files/profile-catalog.json, generated from
charts/saw-bom/profiles by scripts/saw-profile-catalog.py; CI checks it is
current) of the user's profiles. A profile the catalog does not know (one
added to a fork without regenerating it) contributes nothing here.
*/}}
{{- define "saw-users.userCatalog" -}}
{{- $catalog := (.root.Files.Get "files/profile-catalog.json" | fromJson).profiles | default dict -}}
{{- $out := list -}}
{{- range $name := (include "saw-users.profileNames" . | fromJsonArray) -}}
{{- if hasKey $catalog $name -}}
{{- $out = append $out (index $catalog $name) -}}
{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/*
Sandboxes of the user's profiles that ask for a UI route (enabled sandbox
in an enabled workspace, ui.route: true), sorted by <workspace>/<sandbox>,
each with the VM ports its oauth2-proxy and its forward listen on. A user's
`sandboxUi` list, when set, replaces it.
*/}}
{{- define "saw-users.sandboxUi" -}}
{{- $user := .user -}}
{{- $root := .root -}}
{{- $cfg := $root.Values.sandboxUi -}}
{{- $keys := dict -}}
{{- if hasKey $user "sandboxUi" -}}
{{- range $user.sandboxUi | default list -}}
{{- $_ := set $keys (printf "%s/%s" .workspace .sandbox) true -}}
{{- end -}}
{{- else -}}
{{- range $profile := (include "saw-users.userCatalog" . | fromJsonArray) -}}
{{- range $ws := $profile.workspaces | default list -}}
{{- if $ws.enabled -}}
{{- range $sb := $ws.sandboxes | default list -}}
{{- if and $sb.enabled $sb.uiRoute -}}
{{- $_ := set $keys (printf "%s/%s" $ws.name $sb.name) true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $sorted := keys $keys | sortAlpha -}}
{{- if gt (len $sorted) (int $cfg.max) -}}
{{- fail (printf "user %q has %d sandboxes with a UI route; at most %d (sandboxUi.max)" $user.name (len $sorted) (int $cfg.max)) -}}
{{- end -}}
{{- $out := list -}}
{{- range $i, $key := $sorted -}}
{{- $parts := splitList "/" $key -}}
{{- $out = append $out (dict "workspace" (index $parts 0) "sandbox" (index $parts 1)
      "proxyPort" (add (int $cfg.proxyBasePort) $i) "forwardPort" (add (int $cfg.forwardBasePort) $i)) -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/*
The Secrets the user's profiles read (credentialSecret of every provider in
an enabled workspace). pattern-secrets syncs only these.
*/}}
{{- define "saw-users.secretNames" -}}
{{- $names := dict -}}
{{- $known := include "saw-users.userCatalog" . | fromJsonArray -}}
{{- range $profile := $known -}}
{{- range $name, $_ := $profile.secrets | default dict -}}
{{- $_ := set $names $name true -}}
{{- end -}}
{{- end -}}
{{- if not $known -}}
{{- /* No profile in the catalog: keep the Secrets every SAW used to get. */ -}}
{{- range .root.Values.defaults.secrets -}}{{- $_ := set $names . true -}}{{- end -}}
{{- end -}}
{{- if not (include "saw-users.webSearch" .) -}}
{{- $_ := unset $names "web-search" -}}
{{- end -}}
{{- toJson (keys $names | sortAlpha) -}}
{{- end -}}

{{- define "saw-users.profiles" -}}
{{- $user := .user -}}
{{- $root := .root -}}
{{- $profiles := $root.Values.defaults.profiles -}}
{{- if hasKey $user "profiles" -}}
{{- $profiles = $user.profiles -}}
{{- end -}}
{{- $bomValues := dict "profiles" $profiles -}}
{{- if $user.harnessEnabled -}}
{{- $_ := set $bomValues "harnessEnabled" true -}}
{{- end -}}
{{- if not (include "saw-users.webSearch" .) -}}
{{- $_ := set $bomValues "webSearch" (dict "enabled" false) -}}
{{- end -}}
{{- toYaml $bomValues -}}
{{- end -}}

{{/*
pattern-secrets values: the user's Vault prefix for their provider keys,
the shared prefix for the SSH key, and only the Secrets their profiles read.
*/}}
{{- define "saw-users.vaultPrefix" -}}
{{- $user := .user -}}
{{- $root := .root -}}
{{- toYaml (dict "vaultPrefix" ($user.vaultPrefix | default $root.Values.defaults.vaultPrefix)
      "sshVaultPrefix" $root.Values.defaults.sshVaultPrefix
      "secrets" (include "saw-users.secretNames" . | fromJsonArray)
      "clusterCaSecret" ($root.Values.defaults.clusterCaSecret | default "")) -}}
{{- end -}}

{{- define "saw-users.application" -}}
{{- $root := .root -}}
{{- $user := .user -}}
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: {{ .appName }}
  namespace: {{ include "saw-users.argoNamespace" $root }}
  labels:
    validatedpatterns.io/pattern: {{ $root.Values.global.pattern | default "secure-agent-workspace" | quote }}
    openshell.pattern/owner: {{ $user.name | quote }}
  annotations:
    argocd.argoproj.io/sync-wave: {{ .wave | quote }}
    # With ServerSideApply (syncOptions below) there is no last-applied
    # annotation to diff against, so fields the cluster defaults (KubeVirt
    # adds the VM's firmware serial/uuid and machine type) would show the
    # VM OutOfSync forever. Let the API server compute the diff instead.
    # IncludeMutationWebhook=true: without it Argo strips webhook changes
    # with its built-in schemas, which do not know OpenShift's Route, and
    # every comparison fails ("unable to resolve parseableType for
    # route.openshift.io/v1, Kind=Route"): a user with a dashboard or UI
    # route never gets a later commit. With it, the dry run's webhook
    # defaults (KubeVirt's included) are on both sides of the diff.
    argocd.argoproj.io/compare-options: ServerSideDiff=true,IncludeMutationWebhook=true
  {{- if include "saw-users.prune" (dict "root" $root "user" $user) }}
  finalizers:
    - {{ $root.Values.argo.finalizer }}
  {{- end }}
spec:
  project: {{ $root.Values.argo.project }}
  {{- if eq .path "charts/openshell-saw" }}
  # KubeMacPool changes this timestamp even on admission dry-runs. With
  # ServerSideDiff it otherwise makes every healthy VM permanently OutOfSync.
  ignoreDifferences:
    - group: kubevirt.io
      kind: VirtualMachine
      jsonPointers:
        - /metadata/annotations/kubemacpool.io~1transaction-timestamp
  {{- end }}
  destination:
    name: {{ $root.Values.argo.destinationName }}
    namespace: {{ printf "saw-%s" $user.name }}
  source:
    repoURL: {{ $root.Values.global.repoURL | quote }}
    targetRevision: {{ $root.Values.global.targetRevision | quote }}
    path: {{ .path }}
    helm:
      releaseName: {{ .release }}
      values: |
{{ .values | indent 8 }}
  syncPolicy:
    # selfHeal like the pattern's other apps: objects deleted or changed by
    # hand (e.g. while cleaning up an older install) are restored.
    automated:
      selfHeal: true
    retry:
      limit: {{ $root.Values.argo.retryLimit }}
    # Server-side apply: client-side apply copies every object into its
    # kubectl.kubernetes.io/last-applied-configuration annotation, and
    # annotations may hold at most 256 KiB. The VM's installer ConfigMap
    # (apply_bom.py and friends) is past that; ConfigMaps themselves may
    # hold 1 MiB.
    syncOptions:
      - ServerSideApply=true
{{- end -}}
