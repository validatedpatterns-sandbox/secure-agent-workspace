#!/usr/bin/env bash
# Phase: register this VM's redirect URIs on the shared Keycloak client: the
# dashboard's (the *-webui route) and one per sandbox web UI route
# (UI_ROUTE_HOSTS). Cluster-side only; the proxies run in the VM.
# Expects: VM_NAME, NS, OIDC_KEYCLOAK_NAME, OIDC_REALM, KEYCLOAK_NS,
#          DASHBOARD_CLIENT_ID, OIDC_ISSUER_URL, DASHBOARD_ENABLED, UI_ROUTE_HOSTS

HOSTS=()
if [[ "${DASHBOARD_ENABLED:-false}" == "true" ]]; then
  WEBUI_ROUTE_HOST="$(kubectl get route "${VM_NAME}-webui" -n "${NS}" -o jsonpath='{.spec.host}' 2>/dev/null || true)"
  if [[ -n "${WEBUI_ROUTE_HOST}" ]]; then
    HOSTS+=("${WEBUI_ROUTE_HOST}")
  else
    echo "WARNING: ${VM_NAME}-webui route not found — skipping the dashboard redirect URI"
  fi
fi
for host in ${UI_ROUTE_HOSTS:-}; do
  HOSTS+=("${host}")
done
if [[ ${#HOSTS[@]} -eq 0 ]]; then
  echo "No redirect URIs to register."
  return 0 2>/dev/null || exit 0
fi

KC_ADMIN_SECRET="${OIDC_KEYCLOAK_NAME}-initial-admin"
KC_ADMIN_USER="$(kubectl get secret "${KC_ADMIN_SECRET}" -n "${KEYCLOAK_NS}" -o jsonpath='{.data.username}' 2>/dev/null | base64 -d || true)"
KC_ADMIN_PASS="$(kubectl get secret "${KC_ADMIN_SECRET}" -n "${KEYCLOAK_NS}" -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)"
KC_BASE="$(echo "${OIDC_ISSUER_URL}" | sed 's#/realms/.*##')"
if [[ -z "${KC_ADMIN_USER}" || -z "${KC_BASE}" ]]; then
  echo "WARNING: Keycloak admin credentials not found — OIDC login through ${HOSTS[*]} will fail"
  return 0 2>/dev/null || exit 0
fi

echo "Registering redirect URIs on Keycloak client '${DASHBOARD_CLIENT_ID}': ${HOSTS[*]}"
KC_TOKEN_RESPONSE="$(curl -sk -X POST "${KC_BASE}/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=${KC_ADMIN_USER}" -d "password=${KC_ADMIN_PASS}")"
KC_ADMIN_TOKEN="$(echo "${KC_TOKEN_RESPONSE}" | jq -r '.access_token // empty')"
if [[ -z "${KC_ADMIN_TOKEN}" ]]; then
  echo "WARNING: Keycloak admin token fetch failed: $(echo "${KC_TOKEN_RESPONSE}" | jq -r '.error_description // .error // "no response / unparseable response"')"
  return 0 2>/dev/null || exit 0
fi
CLIENT_UUID="$(curl -sk -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
  "${KC_BASE}/admin/realms/${OIDC_REALM}/clients?clientId=${DASHBOARD_CLIENT_ID}" \
  | jq -r '.[0].id // empty')"
if [[ -z "${CLIENT_UUID}" ]]; then
  echo "WARNING: Keycloak client '${DASHBOARD_CLIENT_ID}' not found — OIDC login will fail"
  return 0 2>/dev/null || exit 0
fi

REDIRECTS="$(printf 'https://%s/oauth2/callback\n' "${HOSTS[@]}" | jq -R . | jq -s .)"
ORIGINS="$(printf 'https://%s\n' "${HOSTS[@]}" | jq -R . | jq -s .)"
CLIENT_JSON="$(curl -sk -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
  "${KC_BASE}/admin/realms/${OIDC_REALM}/clients/${CLIENT_UUID}")"
# Added, never removed: other VMs register on the same client.
UPDATED_JSON="$(echo "${CLIENT_JSON}" | jq \
  --argjson redirects "${REDIRECTS}" --argjson origins "${ORIGINS}" \
  '.redirectUris = ((.redirectUris // []) + $redirects | unique) |
   .webOrigins = ((.webOrigins // []) + $origins | unique)')"
HTTP_CODE="$(curl -sk -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -d "${UPDATED_JSON}" \
  "${KC_BASE}/admin/realms/${OIDC_REALM}/clients/${CLIENT_UUID}")"
if [[ "${HTTP_CODE}" == "204" ]]; then
  echo "Redirect URIs registered: $(echo "${REDIRECTS}" | jq -r 'join(" ")')"
else
  echo "WARNING: failed to register redirect URIs (HTTP ${HTTP_CODE}) — OIDC login will fail"
fi
