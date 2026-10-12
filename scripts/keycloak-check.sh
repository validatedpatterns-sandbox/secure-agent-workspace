#!/usr/bin/env bash
# Check that a running Keycloak is configured for OpenShell's OIDC login,
# without admin credentials. Prints one line per check and exits 1 if any
# required check fails.
#
# Usage: keycloak-check.sh   (env: KEYCLOAK_NS, KEYCLOAK_REALM, OIDC_CLIENT_ID)
#
# Checks:
#   - a Keycloak is found in KEYCLOAK_NS (scripts/keycloak-host.sh)
#   - the realm's discovery document: issuer, PKCE S256, device endpoint
#   - the CLI client exists, is public and allows the device flow: a device
#     authorization request (Keycloak returns a short-lived code nobody uses)
#   - realm roles openshell-admin / openshell-user, when a KeycloakRealmImport
#     for the realm is visible (otherwise reported as not verifiable)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NS="${KEYCLOAK_NS:-saw-keycloak}"
REALM="${KEYCLOAK_REALM:-openshell}"
CLIENT="${OIDC_CLIENT_ID:-openshell-cli}"
failed=0

ok()   { echo "  OK    $*"; }
fail() { echo "  FAIL  $*"; failed=1; }
warn() { echo "  WARN  $*"; }

echo "Keycloak in namespace ${NS}, realm ${REALM}, client ${CLIENT}:"

if host="$("${SCRIPT_DIR}/keycloak-host.sh" "${NS}")"; then
  :
else
  rc=$?
  fail "no Keycloak found in ${NS} (run 'make keycloak-deploy', or set KEYCLOAK_NS)"
  exit "${rc}"
fi
issuer="https://${host}/realms/${REALM}"
ok "Keycloak at https://${host}"

if disc="$(curl -skS --max-time 15 "${issuer}/.well-known/openid-configuration")"; then
  :
else
  echo "Error: could not query Keycloak discovery at ${issuer}." >&2
  exit 2
fi
if ! jq -e .issuer >/dev/null 2>&1 <<<"${disc}"; then
  fail "realm '${REALM}' not found at ${issuer} (set KEYCLOAK_REALM)"
  exit 1
fi
if [[ "$(jq -r .issuer <<<"${disc}")" == "${issuer}" ]]; then
  ok "realm ${REALM}: issuer ${issuer}"
else
  fail "realm ${REALM}: discovery reports issuer $(jq -r .issuer <<<"${disc}"), expected ${issuer}"
fi
if jq -e '.code_challenge_methods_supported | index("S256")' >/dev/null <<<"${disc}"; then
  ok "PKCE (S256) supported"
else
  fail "PKCE S256 not supported by the realm"
fi
device_ep="$(jq -r '.device_authorization_endpoint // empty' <<<"${disc}")"

if [[ -z "${device_ep}" ]]; then
  fail "realm has no device authorization endpoint"
else
  # With PKCE enforced on the client, Keycloak requires a code challenge on
  # the device authorization request too.
  verifier="$(openssl rand -hex 32)"
  challenge="$(printf '%s' "${verifier}" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  if resp="$(curl -skS --max-time 15 -X POST "${device_ep}" -d "client_id=${CLIENT}" \
      -d "code_challenge=${challenge}" -d "code_challenge_method=S256")"; then
    :
  else
    echo "Error: could not query the Keycloak device endpoint." >&2
    exit 2
  fi
  if jq -e .device_code >/dev/null 2>&1 <<<"${resp}"; then
    ok "client ${CLIENT} exists, is public and allows the device flow"
  else
    if ! jq -e . <<<"${resp}" >/dev/null; then
      echo "Error: Keycloak device endpoint returned invalid JSON." >&2
      exit 2
    fi
    err="$(jq -r '[.error, .error_description] | map(select(. != null)) | join(": ") | if . == "" then "no response" else . end' <<<"${resp}")"
    case "${err%%:*}" in
      invalid_client) fail "client ${CLIENT} is missing or not public (${err})" ;;
      unauthorized_client) fail "client ${CLIENT} does not allow the device flow (${err})" ;;
      *) fail "client ${CLIENT}: device authorization failed (${err})" ;;
    esac
  fi
fi

realm_imports="$(oc get keycloakrealmimport -n "${NS}" -o json)"
roles="$(jq -r --arg r "${REALM}" \
  '.items[] | select(.spec.realm.realm == $r) | .spec.realm.roles.realm // [] | .[].name' \
  <<<"${realm_imports}")"
if [[ -z "${roles}" ]]; then
  warn "realm roles not verifiable without admin access; the gateway needs openshell-admin / openshell-user in realm_access.roles"
else
  for role in openshell-admin openshell-user; do
    if grep -qx "${role}" <<<"${roles}"; then ok "realm role ${role}"; else fail "realm role ${role} missing"; fi
  done
fi

if (( failed )); then
  echo "Keycloak is not configured for OpenShell; see the FAIL lines above."
  exit 1
fi
echo "Keycloak is configured for OpenShell. OIDC issuer: ${issuer}"
