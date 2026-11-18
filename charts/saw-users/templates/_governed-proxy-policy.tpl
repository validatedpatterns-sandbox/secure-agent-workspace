{{/* Shared broker config for VM and container. The catalog generator mirrors this template into saw-users. */}}
{{- define "saw.governedProxyPolicy" -}}
{{- $profiles := dict -}}
{{- $refresh := dict -}}
{{- range $profile := .catalog -}}
  {{- range $credential := $profile.credentials | default list -}}
    {{- $spec := $credential.refresh | default dict -}}
    {{- if eq ($spec.strategy | default "") "oauth2_refresh_token" -}}
      {{- $keys := list -}}
      {{- range $spec.material -}}{{- $keys = append $keys .name -}}{{- end -}}
      {{- range list "client_id" "client_secret" "refresh_token" -}}
        {{- if not (has . $keys) -}}{{- fail "OAuth refresh requires client_id, client_secret and refresh_token material" -}}{{- end -}}
      {{- end -}}
      {{- $_ := set $refresh $profile.id (dict "credential" $credential.name "spec" (dict "strategy" $spec.strategy "tokenURL" $spec.token_url "refreshBeforeSeconds" $spec.refresh_before_seconds "maxLifetimeSeconds" $spec.max_lifetime_seconds "material" (dict "clientID" "client_id" "clientSecret" "client_secret" "refreshToken" "refresh_token"))) -}}
    {{- end -}}
  {{- end -}}
  {{- if $profile.credentials -}}
    {{- $hosts := list -}}
    {{- range $profile.endpoints -}}
      {{- if and .host (not (has .host $hosts)) -}}{{- $hosts = append $hosts .host -}}{{- end -}}
    {{- end -}}
    {{- $_ := set $profiles $profile.id $hosts -}}
  {{- end -}}
{{- end -}}
{{- if hasKey $profiles "nvidia" -}}{{- $_ := set $profiles "build" (index $profiles "nvidia") -}}{{- end -}}
{{- $bindings := list -}}
{{- $attached := .attached -}}
{{- range .bindings -}}
  {{- if has .name $attached -}}
  {{- if and .name (not (regexMatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" .name)) -}}{{ fail (printf "invalid secret name %q" .name) }}{{- end -}}
  {{- if not (regexMatch "^[A-Za-z0-9_.-]+$" (.key | default "")) -}}
    {{- fail (printf "credentialProxy.secrets[%s].key is invalid" .name) -}}
  {{- end -}}
  {{- if not .providers -}}{{- fail (printf "credentialProxy.secrets[%s].providers is required" .name) -}}{{- end -}}
  {{- if and (hasKey . "refresh") (not (kindIs "bool" .refresh)) -}}
    {{- fail "credentialProxy.secrets[].refresh must be a boolean" -}}
  {{- end -}}
  {{- $binding := dict "secret" .name "key" .key "providers" .providers -}}
  {{- if .refresh -}}
    {{- if ne (len .providers) 1 -}}{{- fail "refresh binding requires exactly one provider type" -}}{{- end -}}
    {{- $type := first .providers -}}
    {{- if not (hasKey $refresh $type) -}}{{- fail (printf "provider %s has no OAuth refresh spec" $type) -}}{{- end -}}
    {{- $entry := index $refresh $type -}}
    {{- if ne .key $entry.credential -}}{{- fail "refresh binding key must match the profile credential" -}}{{- end -}}
    {{- $_ := set $binding "refresh" $entry.spec -}}
  {{- end -}}
  {{- $bindings = append $bindings $binding -}}
  {{- end -}}
{{- end -}}
{{- $policy := dict "markerPrefix" "saw-cred" "allowHosts" .allowHosts "profiles" $profiles "bindings" $bindings -}}
{{ $policy | toJson }}
{{- end -}}
