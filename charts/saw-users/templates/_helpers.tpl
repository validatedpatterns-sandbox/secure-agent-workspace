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
{{- $revisions := .Values.workspaceRevisions -}}
{{- if not (kindIs "map" $revisions) -}}{{- fail "workspaceRevisions requires owner names and full Git commit SHAs" -}}{{- end -}}
{{- range $name, $revision := $revisions -}}
{{- if or (not (regexMatch "^[a-z0-9]([-a-z0-9]{0,17}[a-z0-9])?$" $name)) (not (kindIs "string" $revision)) (not (regexMatch "^[a-f0-9]{40}$" (toString $revision))) -}}
{{- fail "workspaceRevisions requires owner names and full Git commit SHAs" -}}
{{- end -}}{{- end -}}
{{- $seen := dict -}}
{{- range .Values.users | default list -}}
{{- $name := .name | default "" | toString -}}
{{- if not (include "saw-users.awaitingOwner" (dict "root" $ "user" .)) -}}
{{- include "saw-users.validateDeploymentMode" (dict "root" $ "user" .) -}}
{{- end -}}
{{- if and $.Values.ownerResolution.enabled (not (has (dig "deployment" "mode" "vm" (.values | default dict)) (list "container" "kata"))) -}}
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

{{- define "saw-users.credentialProxyEnabled" -}}
{{- $base := .root.Values.defaults.openshellSaw | default dict -}}
{{- $defaults := $base.credentialProxy | default dict -}}
{{- $values := .user.values | default dict -}}
{{- $user := $values.credentialProxy | default dict -}}
{{- $enabled := true -}}
{{- if hasKey $defaults "enabled" -}}{{- $enabled = $defaults.enabled -}}{{- end -}}
{{- if hasKey $user "enabled" -}}{{- $enabled = $user.enabled -}}{{- end -}}
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
{{- $proxy := deepCopy (index $base "credentialProxy" | default dict) -}}
{{- $bindings := include "saw-users.credentialBindings" . | fromJsonArray -}}
{{- if $bindings -}}
{{- $_ := set $proxy "secrets" $bindings -}}
{{- end -}}
{{- $_ := set $base "credentialProxy" $proxy -}}
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
{{- if eq (include "saw-users.harnessEnabled" .) "true" -}}
{{- $_ := set $base "allowDriverConfig" true -}}
{{- end -}}
{{- $overlay := deepCopy ($user.values | default dict) -}}
{{- if $root.Values.ownerResolution.enabled -}}
{{- $_ := set $ac "ownerSubjectSource" "resolved" -}}
{{- end -}}
{{- $base = mergeOverwrite $base $overlay -}}
{{- $proxy := index $base "credentialProxy" | default dict -}}
{{- $_ := set $proxy "enabled" (eq (include "saw-users.credentialProxyEnabled" .) "true") -}}
{{- $_ := set $base "credentialProxy" $proxy -}}
{{- toYaml $base -}}
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

{{/* Only fields marked kind=secret become proxy bindings. */}}
{{- define "saw-users.harnessEnabled" -}}
{{- $required := false -}}
{{- range (include "saw-users.userCatalog" . | fromJsonArray) -}}
{{- if .harnessRequired -}}{{- $required = true -}}{{- end -}}
{{- end -}}
{{- or (.user.harnessEnabled | default false) $required -}}
{{- end -}}

{{- define "saw-users.credentialBindings" -}}
{{- $bindings := dict -}}
{{- $secretNames := include "saw-users.secretNames" . | fromJsonArray -}}
{{- $known := include "saw-users.userCatalog" . | fromJsonArray -}}
{{- range $profile := $known -}}
  {{- range $secret, $entry := $profile.secrets | default dict -}}
    {{- $fields := $entry.fields | default list -}}
    {{- if $entry.refresh -}}
      {{- $fields = append $fields (dict "key" $entry.refresh.credentialKey "kind" "secret" "proxyRefresh" true) -}}
    {{- end -}}
    {{- range $field := $fields -}}
      {{- if and (has $secret $secretNames) (eq $field.kind "secret") (not $field.refreshMaterial) -}}
        {{- $id := printf "%s/%s" $secret $field.key -}}
        {{- $previous := index $bindings $id | default (dict "name" $secret "key" $field.key "providers" (list)) -}}
        {{- $providers := $previous.providers -}}
        {{- range $entry.providers | default list -}}
          {{- if not (has . $providers) -}}{{- $providers = append $providers . -}}{{- end -}}
          {{- if and (eq . "nvidia") (not (has "build" $providers)) -}}{{- $providers = append $providers "build" -}}{{- end -}}
        {{- end -}}
        {{- if $field.proxyRefresh -}}{{- $_ := set $previous "refresh" true -}}{{- end -}}
        {{- $_ := set $previous "providers" $providers -}}
        {{- $_ := set $bindings $id $previous -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- $out := list -}}
{{- range keys $bindings | sortAlpha -}}{{- $out = append $out (index $bindings .) -}}{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{- define "saw-users.profiles" -}}
{{- $user := .user -}}
{{- $root := .root -}}
{{- $profiles := $root.Values.defaults.profiles -}}
{{- if hasKey $user "profiles" -}}
{{- $profiles = $user.profiles -}}
{{- end -}}
{{- $bomValues := dict "profiles" $profiles -}}
{{- $imageOverrides := deepCopy ($root.Values.defaults.imageOverrides | default dict) -}}
{{- range $name, $image := ($user.imageOverrides | default dict) -}}
{{- $_ := set $imageOverrides $name $image -}}
{{- end -}}
{{- $_ := set $bomValues "imageOverrides" $imageOverrides -}}
{{- if eq (include "saw-users.harnessEnabled" .) "true" -}}
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
{{- $saw := deepCopy ($root.Values.defaults.openshellSaw | default dict) -}}
{{- $saw = mergeOverwrite $saw (deepCopy ($user.values | default dict)) -}}
{{- $registry := index $saw "registry" | default dict -}}
{{- $metaKeys := dict -}}
{{- $credentialKeys := dict -}}
{{- range (include "saw-users.credentialBindings" . | fromJsonArray) -}}
{{- $_ := set $credentialKeys (printf "%s/%s" .name .key) true -}}
{{- end -}}
{{- range (include "saw-users.userCatalog" . | fromJsonArray) -}}
{{- range $secret, $entry := .secrets | default dict -}}
{{- $keys := index $metaKeys $secret | default (list "provider") -}}
{{- range $entry.fields | default list -}}
{{- if and (ne .kind "secret") (not (hasKey $credentialKeys (printf "%s/%s" $secret .key))) -}}
{{- $keys = append $keys .key -}}
{{- end -}}
{{- end -}}
{{- $_ := set $metaKeys $secret ($keys | uniq | sortAlpha) -}}
{{- end -}}
{{- end -}}
{{- $values := dict "vaultPrefix" ($user.vaultPrefix | default $root.Values.defaults.vaultPrefix)
      "sshVaultPrefix" $root.Values.defaults.sshVaultPrefix
      "secrets" (include "saw-users.secretNames" . | fromJsonArray)
      "metadataSecrets" (eq (include "saw-users.credentialProxyEnabled" .) "true")
      "clusterCaSecret" ($root.Values.defaults.clusterCaSecret | default "") -}}
{{- if include "saw-users.credentialProxyEnabled" . -}}
{{- $_ := set $values "metaKeys" $metaKeys -}}
{{- end -}}
{{- if $registry.authSecret -}}
{{- $_ := set $values "registryPullSecret" $registry.authSecret -}}
{{- end -}}
{{- toYaml $values -}}
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
  {{- if .ignoreVMDefaults }}
  ignoreDifferences:
    - group: kubevirt.io
      kind: VirtualMachine
      jsonPointers:
        - /metadata/annotations/kubemacpool.io~1transaction-timestamp
        - /metadata/annotations/kubevirt.io~1latest-observed-api-version
        - /metadata/annotations/kubevirt.io~1storage-observed-api-version
        - /spec/template/metadata/annotations/kubevirt.io~1pci-topology-version
        - /spec/template/spec/architecture
        - /spec/template/spec/domain/devices/interfaces/0/macAddress
        - /spec/template/spec/domain/firmware/serial
        - /spec/template/spec/domain/firmware/uuid
        - /spec/template/spec/domain/machine
  {{- end }}
  destination:
    name: {{ $root.Values.argo.destinationName }}
    namespace: {{ printf "saw-%s" $user.name }}
  source:
    repoURL: {{ $root.Values.global.repoURL | quote }}
    targetRevision: {{ index $root.Values.workspaceRevisions $user.name | default $root.Values.global.targetRevision | quote }}
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
      {{- if and (eq .path "charts/saw-portal-container") (eq (int ($user.lifecycleVersion | default 0)) 1) }}
      # Retire superseded publication Jobs. Audit archives opt out of prune and delete.
      prune: true
      {{- end }}
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

{{/* Check effective backend before emitting any per-user Argo applications.
Validate both layers' shape, then apply the same defaults/user precedence as
openshellValues. Keep omission as vm without changing existing rendered values. */}}
{{- define "saw-users.validateDeploymentMode" -}}
{{- $mode := "vm" -}}
{{- range $values := list (.root.Values.defaults.openshellSaw | default dict) (.user.values | default dict) -}}
{{- if hasKey $values "deployment" -}}
{{- $deployment := get $values "deployment" -}}
{{- if not (kindIs "map" $deployment) -}}
{{- fail "deployment must be an object with a mode" -}}
{{- end -}}
{{- range $key, $_ := $deployment -}}
{{- if ne $key "mode" -}}{{- fail (printf "unknown deployment field %q" $key) -}}{{- end -}}
{{- end -}}
{{- if hasKey $deployment "mode" -}}
{{- $mode = get $deployment "mode" -}}
{{- if not (kindIs "string" $mode) -}}{{- fail "deployment.mode must be a string" -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not (has $mode (list "vm" "container" "kata")) -}}
{{- fail "deployment.mode must be one of vm, container, kata" -}}
{{- end -}}
{{- if and (has $mode (list "container" "kata")) (or (hasKey (.root.Values.containerSites | default dict) .user.name) .root.Values.containerDefaults) -}}
{{- $u := include "saw-users.containerUser" (dict "root" .root "user" .user) | fromJson -}}
{{- $site := include "saw-users.containerSite" (dict "root" .root "user" $u) | fromJson -}}
{{- if not (has (dig "deployment" "mode" "vm" ($u.values | default dict)) (list "container" "kata")) -}}{{- fail "deployment.mode=container must be explicit on each user" -}}{{- end -}}
{{- $foundation := or (eq (dig "automaticEnrollment" "enabled" true $site | toString) "false") (eq (dig "automaticEnrollment" "autoApprove" false $site | toString) "true") -}}
{{- $catalog := (.root.Files.Get "files/profile-catalog.json" | fromJson).profiles -}}
{{- $profile := first ($u.profiles | default list) | default "" -}}
{{- $approved := or $foundation (hasKey (dig "automaticEnrollment" "approvedProfiles" dict $site) $profile) -}}
{{- if or (not $u.ownerSubject) (ne $u.ownerSubject $site.subject) (not (regexMatch "^[0-9a-f]{16}$" (default "" $u.registration))) (ne (len ($u.profiles | default list)) 1) (not (hasKey $catalog $profile)) (not $approved) (not $u.pruneOnRemove) -}}
{{- fail "container requires verified owner subject, scoped registration, approved BOM profile and foreground cleanup" -}}
{{- end -}}
{{- else if has $mode (list "container" "kata") -}}
{{- fail (printf "user %q: deployment.mode=container requires containerDefaults or a containerSites entry" .user.name) -}}
{{- end -}}
{{- end -}}

{{/* installationID for a container user. An explicit value wins; otherwise
it is uuid5(NAMESPACE_URL, "urn:saw:portal:<name>:<registration>"), the same
ID the portal and inspect-boundary.py derive. Empty without a valid registration. */}}
{{- define "saw-users.installationID" -}}
{{- if .installationID -}}
{{- .installationID -}}
{{- else if regexMatch "^[0-9a-f]{16}$" (toString (.registration | default "")) -}}
{{- $h := printf "%s%s" ("a6e4EZ2tEdGAtADAT9QwyA==" | b64dec) (printf "urn:saw:portal:%s:%s" .name .registration) | sha1sum -}}
{{- $variant := index (dict "0" "8" "1" "9" "2" "a" "3" "b" "4" "8" "5" "9" "6" "a" "7" "b" "8" "8" "9" "9" "a" "a" "b" "b" "c" "8" "d" "9" "e" "a" "f" "b") (substr 16 17 $h) -}}
{{- printf "%s-%s-5%s-%s%s-%s" (substr 0 8 $h) (substr 8 12 $h) (substr 13 16 $h) $variant (substr 17 20 $h) (substr 20 32 $h) -}}
{{- end -}}
{{- end -}}

{{/* A container user with defaults filled in, so an entry needs only name,
ownerSubject, profiles, vaultPrefix and values.deployment.mode:
- registration: sha256("<name>:<generation>")[:16]; bump generation (default 1)
  for a fresh workspace instead of reusing an old one's storage.
- vaultPrefix: a base path (default defaults.vaultPrefix) gets
  /saw-<name>/<registration> appended; a full owner-scoped path is kept.
- pruneOnRemove: true, intentGeneration: 1, installationID: derived.
Explicit values always win. Returns JSON. */}}
{{- define "saw-users.containerUser" -}}
{{- $u := deepCopy .user -}}
{{- if not $u.registration -}}
{{- $_ := set $u "registration" (printf "%s:%v" $u.name ($u.generation | default 1) | sha256sum | trunc 16) -}}
{{- end -}}
{{- $base := $u.vaultPrefix | default .root.Values.defaults.vaultPrefix | default "secret/data/hub" | trimSuffix "/" -}}
{{- if not (regexMatch (printf "/saw-%s/%s$" $u.name $u.registration) $base) -}}
{{- $base = printf "%s/saw-%s/%s" $base $u.name $u.registration -}}
{{- end -}}
{{- $_ := set $u "vaultPrefix" $base -}}
{{- if not (hasKey $u "pruneOnRemove") }}{{ $_ := set $u "pruneOnRemove" true }}{{ end -}}
{{- if not (hasKey $u "intentGeneration") }}{{ $_ := set $u "intentGeneration" 1 }}{{ end -}}
{{- with include "saw-users.installationID" $u }}{{ $_ := set $u "installationID" . }}{{ end -}}
{{- toJson $u -}}
{{- end -}}

{{/* A container user's site: containerSites.<name> layered over the shared
containerDefaults (site values win). subject defaults to the user's
ownerSubject; every chart revision defaults to global.targetRevision, so the
workspace follows the pattern's branch like VM users. Note: mergeOverwrite
skips empty values, so a per-user false/"" cannot unset a default. Returns JSON. */}}
{{- define "saw-users.containerSite" -}}
{{- $root := .root -}}{{- $u := .user -}}
{{- $site := mergeOverwrite (deepCopy ($root.Values.containerDefaults | default dict)) (deepCopy (index ($root.Values.containerSites | default dict) $u.name | default dict)) -}}
{{- if and $site (not $site.subject) }}{{ $_ := set $site "subject" $u.ownerSubject }}{{ end -}}
{{- $rev := $root.Values.global.targetRevision -}}
{{- range $key, $item := ($site.stack | default dict) -}}
{{- if and (kindIs "map" $item) (not $item.revision) }}{{ $_ := set $item "revision" $rev }}{{ end -}}
{{- end -}}
{{- with $site.automaticEnrollment -}}
{{- if not .revision }}{{ $_ := set . "revision" $rev }}{{ end -}}
{{- if and .relay (not .relay.revision) }}{{ $_ := set .relay "revision" $rev }}{{ end -}}
{{- end -}}
{{- toJson $site -}}
{{- end -}}

{{/* "true" for a container or Kata user whose ownerSubject is not known yet
(typically before the Keycloak account exists) on an installation configured
for containers (containerDefaults or the user's containerSites entry). Such a
user is left out of every rendered resource and listed in the
saw-users-awaiting-owner ConfigMap, so VM users and the rest of the install
still sync. Without any container configuration the entry still fails. */}}
{{- define "saw-users.awaitingOwner" -}}
{{- $u := .user -}}
{{- $configured := or .root.Values.containerDefaults (hasKey (.root.Values.containerSites | default dict) ($u.name | default "")) -}}
{{- if and $configured (has (dig "deployment" "mode" "vm" ($u.values | default dict)) (list "container" "kata")) (not $u.ownerSubject) -}}true{{- end -}}
{{- end -}}
