#!/usr/bin/env bash
# Deploy Keycloak instance + realm via RHBK operator.
# Checks that the operator is installed in the correct namespace.

set -euo pipefail

NS="${KEYCLOAK_NS:-keycloak}"
CHART="${KEYCLOAK_CHART:-charts/openshell-keycloak}"
REALM="${KEYCLOAK_REALM:-saw}"
KC_RESOURCE_NAME="${KEYCLOAK_NAME:-openshell-keycloak}"

yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

reuse_detected_namespace() {
  local detected="$1" detected_name="${2:-$KC_RESOURCE_NAME}"
  yellow "Detected Keycloak '${detected_name}' in namespace '${detected}', while the requested namespace is '${NS}'."
  if [[ "${KEYCLOAK_AUTO_NS:-0}" == "1" ]]; then
    NS="${detected}"
    KC_RESOURCE_NAME="${detected_name}"
    echo "Reusing '${KC_RESOURCE_NAME}' in namespace '${NS}' because KEYCLOAK_AUTO_NS=1."
  elif [[ -t 0 ]]; then
    read -r -p "Reuse Keycloak '${detected_name}' in '${detected}'? [Y/n] " answer
    if [[ -z "${answer}" || "${answer}" =~ ^[Yy]([Ee][Ss])?$ ]]; then
      NS="${detected}"
      KC_RESOURCE_NAME="${detected_name}"
      echo "Reusing '${KC_RESOURCE_NAME}' in namespace '${NS}'."
    else
      echo "Keeping requested namespace '${NS}'; a new instance will be considered."
    fi
  else
    echo "Keycloak was not changed because this command is non-interactive." >&2
    echo "Run: make keycloak KEYCLOAK_NS=${detected} or set KEYCLOAK_AUTO_NS=1 to reuse it." >&2
    exit 2
  fi
}

# Detect an administrator-created or otherwise externally managed instance
# before looking for a Helm release. Keycloak resources are namespace-scoped.
EXISTING_KC_ROWS="$(oc get keycloak -A -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers 2>/dev/null || true)"
TARGET_KC_ROW="$(printf '%s\n' "${EXISTING_KC_ROWS}" | awk -v ns="${NS}" '$2 == ns {print; exit}')"
TARGET_KC_COUNT="$(printf '%s\n' "${EXISTING_KC_ROWS}" | awk -v ns="${NS}" '$2 == ns {count++} END {print count+0}')"
if [[ -n "${KEYCLOAK_NAME:-}" ]]; then
  TARGET_KC_ROW="$(printf '%s\n' "${EXISTING_KC_ROWS}" | awk -v ns="${NS}" -v name="${KEYCLOAK_NAME}" '$1 == name && $2 == ns {print; exit}')"
fi
if [[ "${TARGET_KC_COUNT}" -gt 1 && -z "${KEYCLOAK_NAME:-}" ]]; then
  red "Multiple Keycloak instances already exist in namespace '${NS}':"
  printf '%s\n' "${EXISTING_KC_ROWS}" | awk -v ns="${NS}" '$2 == ns {print}' | sed 's/^/  /'
  echo "Set KEYCLOAK_NAME to select one." >&2
  exit 2
fi
if [[ -n "${TARGET_KC_ROW}" ]]; then
  KC_RESOURCE_NAME="$(printf '%s\n' "${TARGET_KC_ROW}" | awk '{print $1}')"
else
  EXISTING_KC_COUNT="$(printf '%s\n' "${EXISTING_KC_ROWS}" | awk 'NF {count++} END {print count+0}')"
  if [[ "${EXISTING_KC_COUNT}" == "1" ]]; then
    EXISTING_KC_NAME="$(printf '%s\n' "${EXISTING_KC_ROWS}" | awk '{print $1}')"
    EXISTING_KC_NS="$(printf '%s\n' "${EXISTING_KC_ROWS}" | awk '{print $2}')"
    reuse_detected_namespace "${EXISTING_KC_NS}" "${EXISTING_KC_NAME}"
  elif [[ "${EXISTING_KC_COUNT}" -gt 1 && -z "${KEYCLOAK_NAME:-}" ]]; then
    red "Multiple Keycloak instances already exist:"
    printf '%s\n' "${EXISTING_KC_ROWS}" | sed 's/^/  /'
    echo "Set KEYCLOAK_NS and KEYCLOAK_NAME to select one, or remove the ambiguity." >&2
    exit 2
  fi
fi

# Check RHBK operator is installed in the target namespace
RHBK_CSV="$(oc get csv -n "${NS}" -o name 2>/dev/null | grep rhbk || true)"
if [[ -z "${RHBK_CSV}" ]]; then
  RHBK_NS=$(oc get csv --all-namespaces 2>/dev/null | grep rhbk | awk '{print $1}' | head -1)
  if [[ -n "${RHBK_NS}" && "${RHBK_NS}" != "${NS}" ]]; then
    reuse_detected_namespace "${RHBK_NS}"
    if [[ "${NS}" != "${RHBK_NS}" ]]; then
      echo "RHBK operator is not installed in requested namespace '${NS}'." >&2
      echo "Run: make keycloak KEYCLOAK_NS=${RHBK_NS} or install RHBK there." >&2
      exit 2
    fi
  elif [[ -n "${RHBK_NS}" ]]; then
    echo "RHBK operator found in '${NS}' (CSV may still be installing)..."
  else
    echo "Error: RHBK operator not installed."
    echo ""
    echo "  Install it from OperatorHub or use ./pattern.sh make install."
    exit 1
  fi
fi

if helm status openshell-keycloak -n "${NS}" >/dev/null 2>&1; then
  yellow "Warning: Keycloak is already installed in namespace ${NS}."
  echo "  Existing Helm release: openshell-keycloak"
  echo "  Checking the existing Keycloak resource instead of reinstalling it."
elif oc get keycloak "${KC_RESOURCE_NAME}" -n "${NS}" >/dev/null 2>&1; then
  yellow "Warning: Keycloak '${KC_RESOURCE_NAME}' is administrator-managed in namespace ${NS}; no Helm release was found."
  echo "  Leaving ownership unchanged and checking the existing Keycloak resource."
else
  echo "Deploying Keycloak via RHBK operator in ${NS}..."
  helm upgrade --install openshell-keycloak "${CHART}" \
    --namespace "${NS}" --create-namespace --timeout 10m \
    --set-string "keycloak.realm=${REALM}"
fi

echo "Waiting for Keycloak to be ready..."
deadline=$((SECONDS + 300))
while true; do
  ready=$(oc get keycloak "${KC_RESOURCE_NAME}" -n "${NS}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  if [[ "${ready}" == "True" ]]; then
    green "Keycloak is ready in namespace ${NS}."
    KC_URL=$(oc get keycloak "${KC_RESOURCE_NAME}" -n "${NS}" -o jsonpath='{.status.externalURL}' 2>/dev/null || true)
    if [[ -n "${KC_URL}" ]]; then
      echo "  OIDC issuer: ${KC_URL}/realms/${REALM}"
    fi
    exit 0
  fi
  if (( SECONDS > deadline )); then
    echo "Timed out waiting for Keycloak in namespace ${NS}." >&2
    echo "  Resource status:" >&2
    oc get keycloak "${KC_RESOURCE_NAME}" -n "${NS}" -o wide 2>/dev/null || true
    echo "  Recent pods:" >&2
    oc get pods -n "${NS}" -l app.kubernetes.io/managed-by=keycloak-operator 2>/dev/null || true
    echo "  Inspect events with: oc get events -n ${NS} --sort-by=.lastTimestamp | tail -20" >&2
    exit 1
  fi
  echo "  waiting for Keycloak (ready=${ready:-pending})..."
  sleep 10
done
