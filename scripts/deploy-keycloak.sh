#!/usr/bin/env bash
# Deploy Keycloak instance + realm via RHBK operator.
# Checks that the operator is installed in the correct namespace.

set -euo pipefail

NS="${KEYCLOAK_NS:-saw-keycloak}"
CHART="${KEYCLOAK_CHART:-charts/openshell-keycloak}"
REALM="${KEYCLOAK_REALM:-openshell}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# yes/no: use a Keycloak already running in NS (asked interactively if unset).
USE_EXISTING="${USE_EXISTING_KEYCLOAK:-}"

# Check RHBK operator is installed in the target namespace
RHBK_CSV="$(oc get csv -n "${NS}" -o name 2>/dev/null | grep rhbk || true)"
if [[ -z "${RHBK_CSV}" ]]; then
  RHBK_NS=$(oc get csv --all-namespaces 2>/dev/null | grep rhbk | awk '{print $1}' | head -1)
  if [[ -n "${RHBK_NS}" && "${RHBK_NS}" != "${NS}" ]]; then
    echo "Error: RHBK operator is installed in '${RHBK_NS}' but Keycloak needs it in '${NS}'."
    echo ""
    echo "  Either:"
    echo "    1. Run: make keycloak KEYCLOAK_NS=${RHBK_NS}"
    echo "    2. Or install the RHBK operator in '${NS}' from OperatorHub"
    echo "    3. Or use ./pattern.sh make install (installs operator in ${NS} automatically)"
  elif [[ -n "${RHBK_NS}" ]]; then
    echo "RHBK operator found in '${NS}' (CSV may still be installing)..."
  else
    echo "Error: RHBK operator not installed."
    echo ""
    echo "  Install it from OperatorHub or use ./pattern.sh make install."
    exit 1
  fi
fi

# --- An existing Keycloak in NS? Use it if it is configured for OpenShell;
# otherwise ask before importing the OpenShell realm into it. ---
existing="$(oc get keycloak -n "${NS}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null |
  grep -vx openshell-keycloak | head -1 || true)"
ours="$(oc get keycloak openshell-keycloak -n "${NS}" -o name 2>/dev/null || true)"

if [[ -n "${existing}" && -z "${ours}" ]]; then
  echo "Found an existing Keycloak '${existing}' in ${NS}. Checking it for OpenShell..."
  if KEYCLOAK_NS="${NS}" KEYCLOAK_REALM="${REALM}" "${SCRIPT_DIR}/keycloak-check.sh"; then
    echo "Using the existing Keycloak; nothing to deploy."
    exit 0
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
    echo "operator (make keycloak KEYCLOAK_NS=<ns>), or set OIDC_ISSUER to another provider."
    exit 1
  fi
  host="$("${SCRIPT_DIR}/keycloak-host.sh" "${NS}")"
  if curl -skf --max-time 15 "https://${host}/realms/${REALM}/.well-known/openid-configuration" >/dev/null; then
    echo "Error: realm '${REALM}' already exists on '${existing}' but is not configured for OpenShell" >&2
    echo "  (see the check above). Fix that realm in Keycloak, or import a new one with KEYCLOAK_REALM=<name>." >&2
    exit 1
  fi
  KEYCLOAK_NS="${NS}" KEYCLOAK_CHART="${CHART}" "${SCRIPT_DIR}/keycloak-users.sh" ensure
  echo "Importing realm '${REALM}' into Keycloak '${existing}' in ${NS}..."
  helm upgrade --install openshell-keycloak "${CHART}" --namespace "${NS}" \
    --set keycloak.existing="${existing}" --set keycloak.realm="${REALM}" --timeout 10m
  deadline=$((SECONDS + 300))
  until [[ "$(oc get keycloakrealmimport openshell-keycloak-realm -n "${NS}" \
      -o jsonpath='{.status.conditions[?(@.type=="Done")].status}' 2>/dev/null)" == "True" ]]; do
    if (( SECONDS > deadline )); then echo "Timed out waiting for the realm import." >&2; exit 1; fi
    echo "  waiting for the realm import..."; sleep 10
  done
  KEYCLOAK_NS="${NS}" KEYCLOAK_REALM="${REALM}" "${SCRIPT_DIR}/keycloak-check.sh"
  exit $?
fi

echo "Deploying Keycloak via RHBK operator in ${NS}..."
# The test users' passwords: generated once, kept in a Secret the realm
# import reads. No guessable defaults.
KEYCLOAK_NS="${NS}" KEYCLOAK_CHART="${CHART}" "${SCRIPT_DIR}/keycloak-users.sh" ensure
helm upgrade --install openshell-keycloak "${CHART}" \
  --namespace "${NS}" --create-namespace --set keycloak.realm="${REALM}" --timeout 10m

echo "Waiting for Keycloak to be ready..."
deadline=$((SECONDS + 300))
while true; do
  ready=$(oc get keycloak openshell-keycloak -n "${NS}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  if [[ "${ready}" == "True" ]]; then
    echo "Keycloak is ready."
    KC_URL=$(oc get keycloak openshell-keycloak -n "${NS}" -o jsonpath='{.status.externalURL}' 2>/dev/null || true)
    if [[ -n "${KC_URL}" ]]; then
      echo "  OIDC issuer: ${KC_URL}/realms/${REALM}"
    fi
    echo "  Test users' passwords: make -f Makefile-quickstart keycloak-passwords"
    exit 0
  fi
  if (( SECONDS > deadline )); then
    echo "Timed out waiting for Keycloak."
    exit 1
  fi
  echo "  waiting for Keycloak (ready=${ready:-pending})..."
  sleep 10
done
