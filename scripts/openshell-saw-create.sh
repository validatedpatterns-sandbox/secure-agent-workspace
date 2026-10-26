#!/usr/bin/env bash
# Provision a sandbox — detects owner from OIDC token, deploys via helm.
#
# Required env vars: OPENSHELL_SAW_NAME, SAW_CHART
# New inference Secrets need PROVIDER and MODEL; API_KEY may be empty.
# Optional: OWNER, OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_TOKEN_DIR, NS, SAW_NS,
#           KEYCLOAK_NS, ENDPOINT_URL, WEB_SEARCH, SCRIPTS_DIR,
#           PROFILES (comma-separated SAW-BOM profiles, default: the chart's),
#           SAW_VALUES_FILE or SAW_VALUES (Helm settings; topology is discovered),
#           SAW_BOM_VALUES (additional SAW-BOM settings), DYNAMIC_PROVIDERS
#
# Custom OpenAI-compatible endpoint (vLLM, Ollama, ...):
#   PROVIDER=custom-inference MODEL=<served model> ENDPOINT_URL=https://<host>/v1 \
#   API_KEY=<key> PROFILES=custom-inference
#
# Each SAW gets its own namespace (SAW_NS, default saw-<name>). The shared
# namespace NS keeps the golden image and the governance interceptor.

set -euo pipefail

cleanup_tmp() {
  if [[ -n "${inference_key_file:-}" ]]; then rm -f "${inference_key_file}"; fi
  if [[ -n "${web_search_key_file:-}" ]]; then rm -f "${web_search_key_file}"; fi
  if [[ -n "${BOM_VALUES:-}" ]]; then rm -f "${BOM_VALUES}"; fi
  if [[ -n "${NETWORK_TOPOLOGY_VALUES:-}" ]]; then rm -f "${NETWORK_TOPOLOGY_VALUES}"; fi
}
trap cleanup_tmp EXIT

NS="${NS:-openshell-agents}"
OPENSHELL_SAW_NAME="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
SAW_NS="${SAW_NS:-saw-${OPENSHELL_SAW_NAME}}"
KEYCLOAK_NS="${KEYCLOAK_NS:-saw-keycloak}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-openshell}"
SAW_BOM_CHART="${SAW_BOM_CHART:-charts/saw-bom}"
WEB_SEARCH_API_KEY="${WEB_SEARCH_API_KEY:-}"
"$(dirname "$0")/check-saw-name.sh"
SAW_CHART="${SAW_CHART:?SAW_CHART is required}"
SAW_VALUES_FILE="${SAW_VALUES_FILE:-}"
if [[ -n "${SAW_VALUES_FILE}" && ! -f "${SAW_VALUES_FILE}" ]]; then
  echo "Error: SAW_VALUES_FILE does not exist: ${SAW_VALUES_FILE}" >&2
  exit 1
fi
DYNAMIC_MODE="${DYNAMIC_PROVIDERS:-false}"
if [[ "${DYNAMIC_MODE}" != true && "${DYNAMIC_MODE}" != false ]]; then
  echo "Error: DYNAMIC_PROVIDERS must be true or false." >&2
  exit 1
fi
SAW_VALUES_ARGS=()
SAW_VALUE_FILES=()
if [[ -n "${SAW_VALUES_FILE}" ]]; then
  SAW_VALUE_FILES+=("${SAW_VALUES_FILE}")
fi
if [[ -n "${SAW_VALUES:-}" ]]; then
  IFS=',' read -r -a extra_saw_values <<< "${SAW_VALUES}"
  SAW_VALUE_FILES+=("${extra_saw_values[@]}")
fi
for values_file in "${SAW_VALUE_FILES[@]}"; do
  [[ -f "${values_file}" ]] || { echo "SAW values file not found: ${values_file}" >&2; exit 1; }
  SAW_VALUES_ARGS+=(-f "${values_file}")
done
BOM_VALUES_ARGS=()
SAW_BOM_VALUES="${SAW_BOM_VALUES:-}"
if [[ -n "${SAW_BOM_VALUES}" ]]; then
  [[ -f "${SAW_BOM_VALUES}" ]] || { echo "SAW-BOM values file not found: ${SAW_BOM_VALUES}" >&2; exit 1; }
  BOM_VALUES_ARGS=(-f "${SAW_BOM_VALUES}")
fi
if [[ "${DYNAMIC_MODE}" == true && ( ${#SAW_VALUES_ARGS[@]} -eq 0 || -z "${SAW_BOM_VALUES}" ) ]]; then
  echo 'Dynamic providers require SAW_VALUES and SAW_BOM_VALUES files.' >&2
  exit 1
fi
PROVIDER="${PROVIDER:-}"
MODEL="${MODEL:-}"
API_KEY="${API_KEY:-}"
ENDPOINT_URL="${ENDPOINT_URL:-}"
PROFILES="${PROFILES:-}"
WEB_SEARCH="${WEB_SEARCH:-}"
GCP_SA_JSON="${GCP_SA_JSON:-}"
OIDC_ISSUER="${OIDC_ISSUER:-}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-openshell-cli}"
OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR:-$HOME/.config/openshell/oidc}"
OWNER="${OWNER:-}"
OWNER_SUBJECT="${OWNER_SUBJECT:-}"
SCRIPTS_DIR="${SCRIPTS_DIR:-scripts}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
GOVERNANCE_ENABLED="${GOVERNANCE_ENABLED:-true}"
GOVERNANCE_ENGINE="${GOVERNANCE_ENGINE:-interceptor}"
DASHBOARD="${DASHBOARD:-false}"

# Validate all provider settings before changing the cluster.
if [[ -n "${GCP_SA_JSON}" || -n "${SANDBOX_IMAGE:-}" ]]; then
  echo "Error: GCP_SA_JSON and SANDBOX_IMAGE are not supported by this chart." >&2
  exit 1
fi
if [[ -n "${WEB_SEARCH}" ]]; then
  echo "Error: WEB_SEARCH is unsupported. Use WEB_SEARCH_API_KEY and a SAW-BOM profile." >&2
  exit 1
fi
if ! command -v uv >/dev/null 2>&1; then
  echo "Error: uv is required. Install uv before running make saw-create." >&2
  exit 1
fi
if ! python3 -c 'import yaml' >/dev/null 2>&1; then
  echo "Error: python3 with PyYAML is required for network topology discovery." >&2
  exit 1
fi
if [[ "${DASHBOARD}" != true && "${DASHBOARD}" != false ]]; then
  echo "Error: DASHBOARD must be true or false." >&2
  exit 1
fi

oc whoami >/dev/null || { echo "Error: Not logged in to OpenShift. Run 'oc login' first." >&2; exit 1; }

inference_exists=false
if [[ -n "$(oc get namespace "${SAW_NS}" -o name --ignore-not-found)" ]]; then
  if [[ -n "$(oc get secret inference -n "${SAW_NS}" -o name --ignore-not-found)" ]]; then
    inference_exists=true
  fi
fi
if [[ "${DYNAMIC_MODE}" != true && "${inference_exists}" == false && ( -z "${PROVIDER}" || -z "${MODEL}" ) ]]; then
  echo "Error: PROVIDER and MODEL are required when the inference Secret is absent." >&2
  exit 1
fi
if [[ -z "${OWNER}" && ! -f "${OIDC_TOKEN_DIR}/token.json" ]]; then
  echo "Error: no OIDC token found. Run 'make login' first." >&2
  exit 1
fi

token_claim() {
  local claim="$1" token payload
  token="$(jq -er '.access_token' "${OIDC_TOKEN_DIR}/token.json")"
  payload="$(cut -d. -f2 <<<"${token}" | tr '_-' '/+')"
  case $(( ${#payload} % 4 )) in
    2) payload+='==' ;;
    3) payload+='=' ;;
    1) echo "Error: invalid OIDC token format." >&2; return 1 ;;
  esac
  printf '%s' "${payload}" | openssl base64 -d -A | jq -er --arg claim "${claim}" '.[$claim]'
}

# --- Detect owner from OIDC token ---
if [[ -z "${OWNER}" ]]; then
  KC_USER="$(token_claim preferred_username)"

  if [[ -z "${KC_USER}" ]]; then
    echo "Error: Not authenticated. Run 'make login' to sign in before creating a sandbox."
    exit 1
  fi

  # The token's subject is the identity OpenShell uses for workspace
  # membership; the installer makes it admin of the SAW's workspaces.
  OWNER_SUBJECT="$(token_claim sub)"
  printf "Logged in as '\033[1m%s\033[0m'\n" "${KC_USER}"
  printf "Press Enter to set owner to '%s', or type a different owner: " "${KC_USER}"
  read -r INPUT_OWNER
  if [[ -n "${INPUT_OWNER}" ]]; then
    OWNER="${INPUT_OWNER}"
    if [[ "${OWNER}" != "${KC_USER}" ]]; then
      OWNER_SUBJECT=""
    fi
  else
    OWNER="${KC_USER}"
  fi
fi
if [[ -f "${OIDC_TOKEN_DIR}/token.json" && -n "${OWNER}" ]]; then
  token_user="$(token_claim preferred_username)"
  token_subject="$(token_claim sub)"
  if [[ "${OWNER}" == "${token_user}" ]]; then
    if [[ -n "${OWNER_SUBJECT}" && "${OWNER_SUBJECT}" != "${token_subject}" ]]; then
      echo "Error: OWNER_SUBJECT does not match the logged-in owner." >&2
      exit 1
    fi
    OWNER_SUBJECT="${token_subject}"
  fi
fi
# --- Detect OIDC issuer (OIDC_ISSUER=none deploys without OIDC) ---
local_keycloak=false
oidc_disabled=false
oidc_enabled=true
if [[ "${OIDC_ISSUER}" == "none" ]]; then
  OIDC_ISSUER=""
  oidc_disabled=true
  oidc_enabled=false
elif [[ -z "${OIDC_ISSUER}" && "${DYNAMIC_MODE}" != true ]]; then
  KC_HOST="$("${SCRIPTS_DIR}/keycloak-host.sh" "${KEYCLOAK_NS}")"
  OIDC_ISSUER="https://${KC_HOST}/realms/${KEYCLOAK_REALM}"
  local_keycloak=true
elif [[ -n "${OIDC_ISSUER}" ]] && KC_HOST="$("${SCRIPTS_DIR}/keycloak-host.sh" "${KEYCLOAK_NS}")"; then
  if [[ "${OIDC_ISSUER%/}" == "https://${KC_HOST}/realms/${KEYCLOAK_REALM}" ]]; then
    local_keycloak=true
  fi
fi
if [[ -n "${OIDC_ISSUER}" && -z "${OWNER_SUBJECT}" ]]; then
  if [[ "${local_keycloak}" == true ]]; then
    OWNER_SUBJECT="$(KEYCLOAK_NS="${KEYCLOAK_NS}" KEYCLOAK_REALM="${KEYCLOAK_REALM}" \
      "${SCRIPTS_DIR}/keycloak-users.sh" resolve-subject "${OWNER}")"
  else
    echo "Error: external issuer needs a verified OWNER_SUBJECT." >&2
    exit 1
  fi
elif [[ -n "${OIDC_ISSUER}" && "${local_keycloak}" == true ]]; then
  resolved_subject="$(KEYCLOAK_NS="${KEYCLOAK_NS}" KEYCLOAK_REALM="${KEYCLOAK_REALM}" \
    "${SCRIPTS_DIR}/keycloak-users.sh" resolve-subject "${OWNER}")"
  if [[ "${OWNER_SUBJECT}" != "${resolved_subject}" ]]; then
    echo "Error: OWNER_SUBJECT does not match the enabled Keycloak account." >&2
    exit 1
  fi
fi
dashboard_enabled=false
if [[ -n "${OIDC_ISSUER}" && ( "${local_keycloak}" == true || "${DASHBOARD}" == true ) ]]; then
  dashboard_enabled=true
elif [[ "${DASHBOARD}" == true ]]; then
  echo "Error: DASHBOARD=true requires an OIDC issuer." >&2
  exit 1
fi

# Discover the target cluster's networks and exact API backend before any
# namespace, Secret, or Helm release is changed. The generated values overlay
# follows SAW_VALUES_FILE so manually supplied stale topology cannot win.
NETWORK_TOPOLOGY_VALUES="$(mktemp)"
topology_opts=(--output "${NETWORK_TOPOLOGY_VALUES}")
for values_file in "${SAW_VALUE_FILES[@]}"; do
  topology_opts+=(--values-file "${values_file}")
done
python3 "$(dirname "$0")/network-topology.py" discover "${topology_opts[@]}"

# --- Build OIDC helm options ---
OIDC_OPTS=()
if [[ -n "${OIDC_ISSUER}" ]]; then
  # The gateway only needs the issuer. Your own token stays on your machine;
  # the VM's installer uses its local mTLS identity instead.
  OIDC_OPTS=(--set-string "oidc.issuerUrl=${OIDC_ISSUER}"
             --set-string "oidc.clientId=${OIDC_CLIENT_ID}"
             --set-string "oidc.realm=${KEYCLOAK_REALM}")
  # The chart uses the Keycloak CR name to derive the issuer when needed.
  # Use the Keycloak running in KEYCLOAK_NS.
  if [[ "${local_keycloak}" == true ]]; then
    keycloak_list="$(oc get keycloak -n "${KEYCLOAK_NS}" -o json)"
    KC_NAME="$(jq -r '[.items[]?.metadata.name] |
      if index("openshell-keycloak") then "openshell-keycloak" else .[0] // empty end' \
      <<<"${keycloak_list}")"
    if [[ -z "${KC_NAME}" ]]; then
      echo "Error: no Keycloak resource was found in ${KEYCLOAK_NS}." >&2
      exit 1
    fi
    OIDC_OPTS+=(--set-string "oidc.keycloakName=${KC_NAME}")
  fi
fi

# --- Namespace: one per SAW ---
DEPLOY_NS="${SAW_NS}"
oc create namespace "${DEPLOY_NS}" --dry-run=client -o yaml | oc apply -f - >/dev/null
# The label lets the shared governance interceptor accept this SAW's VM.
owner_label="$(printf '%s' "${OWNER}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g' | cut -c1-63)"
oc label namespace "${DEPLOY_NS}" openshell.pattern/saw=true \
  "openshell.pattern/owner=${owner_label}" --overwrite >/dev/null

# --- Compute route hostname ---
ROUTE_HOST=""
APPS_DOMAIN=$(oc get ingress.config.openshift.io cluster \
  -o jsonpath='{.spec.domain}')
if [[ -n "${APPS_DOMAIN}" ]]; then
  ROUTE_HOST="${OPENSHELL_SAW_NAME}-gateway-${DEPLOY_NS}.${APPS_DOMAIN}"
fi

# --- Provider credential Secret ---
# The VM's installer reads provider keys only from mounted Secrets, so the
# key goes into the "inference" Secret instead of the Helm release values.
if [[ "${DYNAMIC_MODE}" != true && ( -n "${API_KEY}" || "${inference_exists}" == false ) ]]; then
  umask 077
  inference_key_file="$(mktemp)"
  # OpenShell requires a nonempty credential even for a keyless endpoint.
  # A keyless server ignores this local placeholder.
  printf '%s' "${API_KEY:-unused-key-for-keyless-provider}" > "${inference_key_file}"
  inference_fields=("--from-file=api_key=${inference_key_file}")
  [[ -z "${PROVIDER}" ]] || inference_fields+=("--from-literal=provider=${PROVIDER}")
  [[ -z "${MODEL}" ]] || inference_fields+=("--from-literal=model=${MODEL}")
  [[ -z "${ENDPOINT_URL}" ]] || inference_fields+=("--from-literal=url=${ENDPOINT_URL}")
  oc create secret generic inference -n "${DEPLOY_NS}" \
    "${inference_fields[@]}" \
    --dry-run=client -o yaml | oc apply -f - >/dev/null
  rm -f "${inference_key_file}"
  inference_key_file=""
  echo "Secret 'inference' updated in ${DEPLOY_NS}."
fi

if [[ -n "${WEB_SEARCH_API_KEY}" ]]; then
  umask 077
  web_search_key_file="$(mktemp)"
  printf '%s' "${WEB_SEARCH_API_KEY}" > "${web_search_key_file}"
  oc create secret generic web-search -n "${DEPLOY_NS}" \
    "--from-file=api_key=${web_search_key_file}" \
    --dry-run=client -o yaml | oc apply -f - >/dev/null
  rm -f "${web_search_key_file}"
  web_search_key_file=""
  echo "Secret 'web-search' updated in ${DEPLOY_NS}."
fi

# Only mount available Secrets; disable web-search providers in the BOM too
# when the optional web-search Secret is absent.
SECRET_SET=()
web_search_enabled=true
secret_names="$(oc get secrets -n "${DEPLOY_NS}" -o name)"
if ! grep -qx 'secret/inference' <<<"${secret_names}"; then
  SECRET_SET+=(--set "inference.secretName=")
fi
if ! grep -qx 'secret/web-search' <<<"${secret_names}"; then
  SECRET_SET+=(--set "additionalProviderSecrets=null")
  web_search_enabled=false
fi

# --- SAW-BOM profiles ---
# The VM can only attach ConfigMaps from its own namespace, so each SAW gets
# its own saw-bom-profiles ConfigMap.
BOM_OPTS=()
if [[ -n "${PROFILES}" ]]; then
  BOM_VALUES="$(mktemp)"
  { echo "profiles:"; tr ',' '\n' <<<"${PROFILES}" | sed -e 's/^ *//' -e 's/ *$//' -e '/^$/d' -e 's/^/  - /'; } > "${BOM_VALUES}"
  BOM_OPTS=(-f "${BOM_VALUES}")
fi
if [[ "${web_search_enabled}" == false ]]; then
  BOM_OPTS+=(--set webSearch.enabled=false)
fi
# ${arr[@]+...}: an empty array is "unbound" under set -u in bash < 4.4 (macOS).
helm upgrade --install saw-bom "${SAW_BOM_CHART}" --namespace "${DEPLOY_NS}" \
  ${BOM_OPTS[@]+"${BOM_OPTS[@]}"} ${BOM_VALUES_ARGS[@]+"${BOM_VALUES_ARGS[@]}"} >/dev/null
echo "SAW-BOM profiles installed in ${DEPLOY_NS}${PROFILES:+ (${PROFILES})}."

# --- Deploy ---
echo "Provisioning sandbox '${OPENSHELL_SAW_NAME}' for owner '${OWNER}' in namespace '${DEPLOY_NS}'..."

helm_opts=(
  --set-string "sandboxName=${OPENSHELL_SAW_NAME}"
  --set-string "accessControl.owner=${OWNER}"
  --set-string "oidc.keycloakNamespace=${KEYCLOAK_NS}"
  --set-string "governance.namespace=${NS}"
  --set-string "source.dataSourceNamespace=${NS}"
  --set-string "containerRuntime=${CONTAINER_RUNTIME}"
)
if [[ "${DYNAMIC_MODE}" != true ]]; then
  helm_opts+=(
    --set "oidc.enabled=${oidc_enabled}"
    --set "governance.enabled=${GOVERNANCE_ENABLED}"
    --set-string "governance.engine=${GOVERNANCE_ENGINE}"
    --set route.enabled=true --set route.dashboard=true
  )
fi
if [[ "${#SAW_VALUES_ARGS[@]}" -gt 0 ]]; then
  helm_opts=("${SAW_VALUES_ARGS[@]}" -f "${NETWORK_TOPOLOGY_VALUES}" "${helm_opts[@]}")
else
  helm_opts=(-f "${NETWORK_TOPOLOGY_VALUES}" "${helm_opts[@]}")
fi
if [[ "${dashboard_enabled}" != true && "${DYNAMIC_MODE}" != true ]]; then
  # External OIDC providers cannot be updated through the Keycloak Admin API.
  helm_opts+=(--set dashboard.enabled=false --set route.dashboard=false
    --set route.webui=false)
fi
if [[ "${oidc_disabled}" == true && "${DYNAMIC_MODE}" != true ]]; then
  helm_opts+=(--set-string oidc.issuerUrl= --set-json 'sandboxUi=[]')
fi
[[ -z "${OWNER_SUBJECT}" ]] || helm_opts+=(--set-string "accessControl.ownerSubject=${OWNER_SUBJECT}")
if [[ "${DYNAMIC_MODE}" != true && -n "${ROUTE_HOST}" ]]; then
  helm_opts+=(--set-string "route.host=${ROUTE_HOST}")
fi
if [[ -n "${APPS_DOMAIN}" ]]; then
  if [[ "${DYNAMIC_MODE}" != true ]]; then
    helm_opts+=(--set-string "route.webuiHost=${OPENSHELL_SAW_NAME}-webui-${DEPLOY_NS}.${APPS_DOMAIN}")
    if [[ "${APPS_DOMAIN}" == apps.* ]]; then
      helm_opts+=(--set-string "global.clusterDomain=${APPS_DOMAIN#apps.}")
    fi
    if [[ "${dashboard_enabled}" == true ]]; then
      helm_opts+=(--set-string "route.dashboardHost=${OPENSHELL_SAW_NAME}-dashboard-${DEPLOY_NS}.${APPS_DOMAIN}")
    fi
  fi
fi
ui_routes='[]'
if [[ "${dashboard_enabled}" == true && "${DYNAMIC_MODE}" != true ]]; then
  ui_routes="$(uv run --locked python "${SCRIPTS_DIR}/sandbox-ui-values.py" "${PROFILES:-data-science}")"
  if [[ "${ui_routes}" != '[]' && "${APPS_DOMAIN}" != apps.* ]]; then
    echo "Error: sandbox UI routes need an apps.<cluster-domain> ingress domain." >&2
    exit 1
  fi
  helm_opts+=(--set-json "sandboxUi=${ui_routes}")
fi
helm_opts+=(${OIDC_OPTS[@]+"${OIDC_OPTS[@]}"})
helm_opts+=(${SECRET_SET[@]+"${SECRET_SET[@]}"})
helm upgrade --install "${OPENSHELL_SAW_NAME}" "${SAW_CHART}" \
  --namespace "${DEPLOY_NS}" --create-namespace \
  "${helm_opts[@]}"

echo ""
echo "Sandbox '${OPENSHELL_SAW_NAME}' resources created. Wait for the VM installer before connecting."
echo "  Owner:     ${OWNER}"
echo "  Namespace: ${DEPLOY_NS}"

GW_URL=$(oc get route "${OPENSHELL_SAW_NAME}-gateway" -n "${DEPLOY_NS}" -o jsonpath='https://{.spec.host}' || true)
if [[ -n "${GW_URL}" ]]; then
  echo "  Gateway:   ${GW_URL}"
fi

echo ""
echo "Next steps:"
printf -v quoted_name '%q' "${OPENSHELL_SAW_NAME}"
printf -v quoted_ns '%q' "${DEPLOY_NS}"
printf -v quoted_issuer '%q' "${OIDC_ISSUER:-none}"
printf -v quoted_client '%q' "${OIDC_CLIENT_ID}"
printf -v quoted_kc_ns '%q' "${KEYCLOAK_NS}"
echo "  1. make saw-status OPENSHELL_SAW_NAME=${quoted_name} SAW_NS=${quoted_ns}"
echo "     Wait until both install and apply report Done."
echo "  2. OIDC_ISSUER=${quoted_issuer} OIDC_CLIENT_ID=${quoted_client} KEYCLOAK_NS=${quoted_kc_ns} make saw-configure OPENSHELL_SAW_NAME=${quoted_name} SAW_NS=${quoted_ns}"
echo "  3. openshell sandbox list"
if [[ "${ui_routes}" != '[]' ]]; then
  echo "  Sandbox UIs: make sandbox-ui SAW_NS=${quoted_ns}"
fi
echo "  OpenClaw UI, when enabled: make openclaw-gui OPENSHELL_SAW_NAME=${quoted_name} SAW_NS=${quoted_ns} SANDBOX_NAME=notebook"
echo "Shell on the VM (adds your SSH key on demand): make saw-vm-ssh OPENSHELL_SAW_NAME=${OPENSHELL_SAW_NAME} SAW_NS=${DEPLOY_NS}"
