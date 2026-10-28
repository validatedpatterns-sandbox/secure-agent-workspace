#!/usr/bin/env bash
# Deploy Keycloak instance + realm via RHBK operator.
# Checks that the operator is installed in the correct namespace.

set -euo pipefail

NS="${KEYCLOAK_NS:-saw-keycloak}"
CHART="${KEYCLOAK_CHART:-charts/openshell-keycloak}"
REALM="${KEYCLOAK_REALM:-openshell}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/issuer-tls.sh"
# yes/no: use a Keycloak already running in NS (asked interactively if unset).
USE_EXISTING="${USE_EXISTING_KEYCLOAK:-}"
DEMO_ENABLED="${DEMO_ENABLED:-false}"
[[ "${DEMO_ENABLED}" == true || "${DEMO_ENABLED}" == false ]] || {
  echo "Error: DEMO_ENABLED must be true or false." >&2
  exit 2
}

# Check RHBK operator access and location before any writes.
csv_json="$(oc get csv -n "${NS}" -o json)"
if ! jq -e '.items | any(.metadata.name | contains("rhbk"))' \
    <<<"${csv_json}" >/dev/null; then
  all_csv="$(oc get csv --all-namespaces -o json)"
  RHBK_NS="$(jq -r 'first(.items[] | select(.metadata.name | contains("rhbk")) |
    .metadata.namespace) // empty' <<<"${all_csv}")"
  if [[ -n "${RHBK_NS}" ]]; then
    echo "Error: RHBK is in ${RHBK_NS}, but KEYCLOAK_NS is ${NS}." >&2
  else
    echo "Error: RHBK operator is not installed. Install it from OperatorHub first." >&2
  fi
  exit 1
fi

# --- An existing Keycloak in NS? Use it if it is configured for OpenShell;
# otherwise ask before importing the OpenShell realm into it. ---
keycloaks="$(oc get keycloak -n "${NS}" -o json)"
existing="$(jq -r 'first(.items[] | select(.metadata.name != "openshell-keycloak") |
  .metadata.name) // empty' <<<"${keycloaks}")"
ours="$(jq -r 'first(.items[] | select(.metadata.name == "openshell-keycloak") |
  .metadata.name) // empty' <<<"${keycloaks}")"

if [[ -n "${existing}" && -z "${ours}" ]]; then
  echo "Found an existing Keycloak '${existing}' in ${NS}. Checking it for OpenShell..."
  if KEYCLOAK_NS="${NS}" KEYCLOAK_REALM="${REALM}" "${SCRIPT_DIR}/keycloak-check.sh"; then
    echo "Using the existing Keycloak; nothing to deploy."
    exit 0
  else
    check_rc=$?
    if [[ "${check_rc}" != 1 ]]; then exit "${check_rc}"; fi
  fi
  if [[ -z "${USE_EXISTING}" ]]; then
    if [[ -t 0 ]]; then
      read -r -p "Import the OpenShell realm '${REALM}' into the existing Keycloak '${existing}'? Other realms are not touched. [y/N] " answer
      [[ "${answer}" =~ ^[Yy] ]] && USE_EXISTING=yes || USE_EXISTING=no
    else
      echo "Set USE_EXISTING_KEYCLOAK=yes to import the OpenShell realm into '${existing}', or =no." >&2
      exit 1
    fi
  fi
  if [[ "${USE_EXISTING}" != "yes" ]]; then
    echo "Not using '${existing}'. To deploy a separate Keycloak, pick a namespace with its own RHBK"
    echo "operator (make keycloak-deploy KEYCLOAK_NS=<ns>), or set OIDC_ISSUER to another provider."
    exit 1
  fi
  host="$("${SCRIPT_DIR}/keycloak-host.sh" "${NS}")"
  saw_tls_init "https://${host}" || exit 1
  discovery_status="$(curl -sS "${CURL_TLS_OPTS[@]}" --max-time 15 -o /dev/null -w '%{http_code}' \
    "https://${host}/realms/${REALM}/.well-known/openid-configuration")"
  if [[ "${discovery_status}" == 200 ]]; then
    echo "Error: realm '${REALM}' already exists on '${existing}' but is not configured for OpenShell" >&2
    echo "  (see the check above). Fix that realm in Keycloak, or import a new one with KEYCLOAK_REALM=<name>." >&2
    exit 1
  elif [[ "${discovery_status}" != 404 ]]; then
    echo "Error: Keycloak discovery returned HTTP ${discovery_status}; realm state is unknown." >&2
    exit 1
  fi
  KEYCLOAK_NS="${NS}" KEYCLOAK_CHART="${CHART}" DEMO_ENABLED="${DEMO_ENABLED}" "${SCRIPT_DIR}/keycloak-users.sh" ensure
  echo "Importing realm '${REALM}' into Keycloak '${existing}' in ${NS}..."
  helm upgrade --install openshell-keycloak "${CHART}" --namespace "${NS}" \
    --set keycloak.existing="${existing}" --set keycloak.realm="${REALM}" \
    --set demo.enabled="${DEMO_ENABLED}" --timeout 10m
  deadline=$((SECONDS + 300))
  until [[ "$(oc get keycloakrealmimport -n "${NS}" -o json | jq -r \
      'first(.items[] | select(.metadata.name == "openshell-keycloak-realm") |
       .status.conditions[]? | select(.type == "Done") | .status) // empty')" == "True" ]]; do
    if (( SECONDS > deadline )); then echo "Timed out waiting for the realm import." >&2; exit 1; fi
    echo "  waiting for the realm import..."; sleep 10
  done
  KEYCLOAK_NS="${NS}" KEYCLOAK_REALM="${REALM}" "${SCRIPT_DIR}/keycloak-check.sh"
  exit 0
fi

echo "Deploying Keycloak via RHBK operator in ${NS}..."
# Generate passwords only for selected imported users.
KEYCLOAK_NS="${NS}" KEYCLOAK_CHART="${CHART}" DEMO_ENABLED="${DEMO_ENABLED}" "${SCRIPT_DIR}/keycloak-users.sh" ensure
helm upgrade --install openshell-keycloak "${CHART}" \
  --namespace "${NS}" --create-namespace --set keycloak.realm="${REALM}" \
  --set demo.enabled="${DEMO_ENABLED}" --timeout 10m

echo "Waiting for Keycloak to be ready..."
deadline=$((SECONDS + 300))
while true; do
  keycloaks="$(oc get keycloak -n "${NS}" -o json)"
  ready="$(jq -r 'first(.items[] | select(.metadata.name == "openshell-keycloak") |
    .status.conditions[]? | select(.type == "Ready") | .status) // empty' \
    <<<"${keycloaks}")"
  if [[ "${ready}" == "True" ]]; then
    echo "Keycloak is ready."
    KC_URL="$(jq -r 'first(.items[] | select(.metadata.name == "openshell-keycloak") |
      .status.externalURL) // empty' <<<"${keycloaks}")"
    if [[ -n "${KC_URL}" ]]; then
      echo "  OIDC issuer: ${KC_URL}/realms/${REALM}"
    fi
    if [[ "${DEMO_ENABLED}" == true ]]; then
      echo "  Demo user credentials remain in the Keycloak user Secret."
    fi
    exit 0
  fi
  if (( SECONDS > deadline )); then
    echo "Timed out waiting for Keycloak."
    exit 1
  fi
  echo "  waiting for Keycloak (ready=${ready:-pending})..."
  sleep 10
done
