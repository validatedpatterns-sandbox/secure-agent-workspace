#!/usr/bin/env bash
# Ensure the SAW realm and a confidential OIDC client exist in Keycloak.
set -euo pipefail

NS="${KEYCLOAK_NS:-keycloak}"
REALM="${KEYCLOAK_REALM:-saw}"
RESOURCE="${KEYCLOAK_NAME:-openshell-keycloak}"
CLIENT_ID="${SAW_OIDC_CLIENT_ID:-saw}"
CLIENT_SECRET_NAME="${SAW_OIDC_CLIENT_SECRET_NAME:-saw-oidc-client}"

for command in oc curl jq; do
  command -v "$command" >/dev/null 2>&1 || { echo "Error: $command is required." >&2; exit 2; }
done

if ! oc get keycloak "$RESOURCE" -n "$NS" >/dev/null 2>&1; then
  detected="$(oc get keycloak -A -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers 2>/dev/null \
    | awk -v ns="$NS" '$2 == ns {print $1; exit}')"
  if [[ -n "$detected" ]]; then
    RESOURCE="$detected"
  else
    echo "Error: no Keycloak resource found in namespace $NS. Set KEYCLOAK_NS/KEYCLOAK_NAME or run make keycloak first." >&2
    exit 1
  fi
fi

# RHBK versions expose the public endpoint under different status fields.
base="${KEYCLOAK_URL:-}"
if [[ -z "$base" ]]; then
  base="$(oc get keycloak "$RESOURCE" -n "$NS" -o jsonpath='{.status.externalURL}' 2>/dev/null || true)"
fi
if [[ -z "$base" ]]; then
  base="$(oc get keycloak "$RESOURCE" -n "$NS" -o jsonpath='{.status.externalUrl}' 2>/dev/null || true)"
fi
if [[ -z "$base" ]]; then
  base="$(oc get keycloak "$RESOURCE" -n "$NS" -o jsonpath='{.status.url}' 2>/dev/null || true)"
fi
if [[ -z "$base" ]]; then
  host="$(oc get route -n "$NS" -l app=keycloak -o jsonpath='{.items[0].spec.host}' 2>/dev/null || true)"
  if [[ -z "$host" ]]; then
    # Administrator-managed instances often use a generated route name and
    # do not carry the chart's app=keycloak label.
    host="$(oc get route -n "$NS" -o jsonpath='{range .items[*]}{.spec.host}{"\n"}{end}' 2>/dev/null | head -n 1)"
  fi
  [[ -n "$host" ]] && base="https://$host"
fi
base="${base%/}"
[[ -n "$base" ]] || {
  echo "Error: cannot discover Keycloak URL in namespace $NS." >&2
  echo "Set KEYCLOAK_URL=https://<keycloak-host> and rerun if the instance has no Route/status URL." >&2
  exit 1
}
case "$base" in
  http://*|https://*) ;;
  *) base="https://$base" ;;
esac

admin_user="${KEYCLOAK_ADMIN_USER:-}"
admin_password="${KEYCLOAK_ADMIN_PASSWORD:-}"
if [[ -z "$admin_password" ]]; then
  candidates="${KEYCLOAK_ADMIN_SECRET:-${RESOURCE}-initial-admin ${RESOURCE}-admin keycloak-initial-admin keycloak-admin}"
  for secret in $candidates; do
    admin_password="$(oc get secret "$secret" -n "$NS" -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    [[ -n "$admin_password" ]] || continue
    admin_user="$(oc get secret "$secret" -n "$NS" -o jsonpath='{.data.username}' 2>/dev/null | base64 -d 2>/dev/null || echo admin)"
    break
  done
fi
[[ -n "$admin_password" ]] || { echo "Error: Keycloak admin password unavailable. Set KEYCLOAK_ADMIN_PASSWORD or KEYCLOAK_ADMIN_SECRET." >&2; exit 1; }
admin_user="${admin_user:-admin}"

token="$(curl -skf -X POST "$base/realms/master/protocol/openid-connect/token" \
  --data-urlencode client_id=admin-cli --data-urlencode grant_type=password \
  --data-urlencode "username=$admin_user" --data-urlencode "password=$admin_password" \
  | jq -r '.access_token // empty')"
[[ -n "$token" ]] || { echo "Error: Keycloak admin authentication failed." >&2; exit 1; }
auth=(-H "Authorization: Bearer $token" -H 'Content-Type: application/json')

realm_status="$(curl -sk -o /dev/null -w '%{http_code}' "${auth[@]}" "$base/admin/realms/$REALM")"
if [[ "$realm_status" == "404" ]]; then
  curl -skf -X POST "${auth[@]}" "$base/admin/realms" -d "$(jq -n --arg realm "$REALM" '{realm:$realm,enabled:true,registrationAllowed:true,roles:{realm:[{name:"openshell-user"},{name:"openshell-admin"}]}}')" >/dev/null
  echo "Created Keycloak realm '$REALM'."
elif [[ "$realm_status" != "200" ]]; then
  echo "Error: cannot inspect Keycloak realm '$REALM' (HTTP $realm_status)." >&2
  exit 1
else
  echo "Keycloak realm '$REALM' already exists."
fi

client_json="$(curl -skf "${auth[@]}" "$base/admin/realms/$REALM/clients?clientId=$(printf '%s' "$CLIENT_ID" | jq -sRr @uri)")"
client_uuid="$(jq -r '.[0].id // empty' <<<"$client_json")"
if [[ -z "$client_uuid" ]]; then
  curl -skf -X POST "${auth[@]}" "$base/admin/realms/$REALM/clients" -d "$(jq -n --arg client "$CLIENT_ID" '{clientId:$client,enabled:true,publicClient:false,standardFlowEnabled:true,directAccessGrantsEnabled:true,protocol:"openid-connect",redirectUris:["http://localhost:*","http://127.0.0.1:*"] ,webOrigins:["http://localhost","http://127.0.0.1"]}')" >/dev/null
  client_json="$(curl -skf "${auth[@]}" "$base/admin/realms/$REALM/clients?clientId=$(printf '%s' "$CLIENT_ID" | jq -sRr @uri)")"
  client_uuid="$(jq -r '.[0].id // empty' <<<"$client_json")"
  echo "Created OIDC client '$CLIENT_ID'."
else
  echo "OIDC client '$CLIENT_ID' already exists."
fi
[[ -n "$client_uuid" ]] || { echo "Error: could not resolve OIDC client '$CLIENT_ID'." >&2; exit 1; }
client_secret="$(curl -skf "${auth[@]}" "$base/admin/realms/$REALM/clients/$client_uuid/client-secret" | jq -r '.value // empty')"
[[ -n "$client_secret" ]] || { echo "Error: Keycloak returned no client secret." >&2; exit 1; }

issuer="$base/realms/$REALM"
oc create secret generic "$CLIENT_SECRET_NAME" -n "$NS" \
  --from-literal=issuer="$issuer" --from-literal=client-id="$CLIENT_ID" \
  --from-literal=client-secret="$client_secret" --dry-run=client -o yaml | oc apply -f - >/dev/null
echo "Stored the OIDC client secret in Secret/$CLIENT_SECRET_NAME in namespace $NS."
echo "Issuer: $issuer"
