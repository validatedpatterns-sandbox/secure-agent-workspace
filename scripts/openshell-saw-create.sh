#!/usr/bin/env bash
# Provision a sandbox — detects owner from OIDC token, deploys via helm.
#
# Required env vars: OPENSHELL_SAW_NAME, SAW_CHART
# Required env vars (provider): PROVIDER + MODEL + API_KEY, or GCP_SA_JSON
# Optional: OWNER, OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_TOKEN_DIR, NS, SAW_NS,
#           KEYCLOAK_NS, AGENT, ENDPOINT_URL, WEB_SEARCH, SCRIPTS_DIR,
#           PROFILES (comma-separated SAW-BOM profiles, default: the chart's)
#
# Custom OpenAI-compatible endpoint (vLLM, Ollama, ...):
#   PROVIDER=openai MODEL=<served model> ENDPOINT_URL=https://<host>/v1 \
#   API_KEY=<key> PROFILES=custom-inference
#
# Each SAW gets its own namespace (SAW_NS, default saw-<name>). The shared
# namespace NS keeps the golden image and the governance interceptor.

set -euo pipefail

NS="${NS:-openshell-agents}"
OPENSHELL_SAW_NAME="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
SAW_NS="${SAW_NS:-saw-${OPENSHELL_SAW_NAME}}"
KEYCLOAK_NS="${KEYCLOAK_NS:-saw-keycloak}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-openshell}"
SAW_BOM_CHART="${SAW_BOM_CHART:-charts/saw-bom}"
WEB_SEARCH_API_KEY="${WEB_SEARCH_API_KEY:-}"
if (( ${#OPENSHELL_SAW_NAME} > 19 )); then
  echo "ERROR: OPENSHELL_SAW_NAME '${OPENSHELL_SAW_NAME}' is ${#OPENSHELL_SAW_NAME} characters — OpenShell enforces a 19-character maximum." >&2
  exit 1
fi
SAW_CHART="${SAW_CHART:?SAW_CHART is required}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-}"
AGENT="${AGENT:-openclaw}"
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

# Validate provider
if [[ -z "${PROVIDER}" && -z "${GCP_SA_JSON}" ]]; then
  echo "Error: PROVIDER or GCP_SA_JSON is required."
  echo ""
  echo "Usage:"
  echo "  make openshell-saw-create OPENSHELL_SAW_NAME=my-sandbox PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<key>"
  echo ""
  echo "Providers: gemini, anthropic, openai, build (NVIDIA), openrouter, ollama, custom"
  exit 1
fi

if [[ -n "${GCP_SA_JSON}" && ! -f "${GCP_SA_JSON}" ]]; then
  echo "Error: file not found: ${GCP_SA_JSON}"
  exit 1
fi

oc whoami >/dev/null 2>&1 || { echo "Error: Not logged in to OpenShift. Run 'oc login' first."; exit 1; }

# --- Detect owner from OIDC token ---
if [[ -z "${OWNER}" ]]; then
  KC_USER=$(jq -r '.access_token // empty' "${OIDC_TOKEN_DIR}/token.json" 2>/dev/null \
    | python3 -c "import sys,base64,json; t=sys.stdin.read().strip().split('.')[1]; t+='='*(4-len(t)%4); print(json.loads(base64.urlsafe_b64decode(t)).get('preferred_username',''))" 2>/dev/null || true)

  if [[ -z "${KC_USER}" ]]; then
    echo "Error: Not authenticated. Run 'make login' to sign in before creating a sandbox."
    exit 1
  fi

  # The token's subject is the identity OpenShell uses for workspace
  # membership; the installer makes it admin of the SAW's workspaces.
  OWNER_SUBJECT=$(jq -r '.access_token // empty' "${OIDC_TOKEN_DIR}/token.json" 2>/dev/null \
    | python3 -c "import sys,base64,json; t=sys.stdin.read().strip().split('.')[1]; t+='='*(4-len(t)%4); print(json.loads(base64.urlsafe_b64decode(t)).get('sub',''))" 2>/dev/null || true)
  printf "Logged in as '\033[1m%s\033[0m'\n" "${KC_USER}"
  printf "Press Enter to set owner to '%s', or type a different owner: " "${KC_USER}"
  read -r INPUT_OWNER
  if [[ -n "${INPUT_OWNER}" ]]; then
    OWNER="${INPUT_OWNER}"
  else
    OWNER="${KC_USER}"
  fi
fi

# --- Detect OIDC issuer (OIDC_ISSUER=none deploys without OIDC) ---
if [[ "${OIDC_ISSUER}" == "none" ]]; then
  OIDC_ISSUER=""
elif [[ -z "${OIDC_ISSUER}" ]]; then
  KC_HOST=$("${SCRIPTS_DIR}/keycloak-host.sh" "${KEYCLOAK_NS}" 2>/dev/null || true)
  if [[ -n "${KC_HOST}" ]]; then
    OIDC_ISSUER="https://${KC_HOST}/realms/${KEYCLOAK_REALM}"
  fi
fi

# --- Build OIDC helm options ---
OIDC_OPTS=""
if [[ -n "${OIDC_ISSUER}" ]]; then
  # The gateway only needs the issuer. Your own token stays on your machine;
  # the VM's installer uses its local mTLS identity instead.
  OIDC_OPTS="--set oidc.issuerUrl=${OIDC_ISSUER} --set oidc.clientId=${OIDC_CLIENT_ID}"
  OIDC_OPTS="${OIDC_OPTS} --set oidc.realm=${KEYCLOAK_REALM}"
  # The prepare Job reads <Keycloak CR name>-initial-admin to register the
  # dashboard redirect URI; use the Keycloak actually running in KEYCLOAK_NS
  # (the repo's openshell-keycloak if present, else e.g. an existing `keycloak`).
  if oc get keycloak openshell-keycloak -n "${KEYCLOAK_NS}" >/dev/null 2>&1; then
    KC_NAME=openshell-keycloak
  else
    KC_NAME=$(oc get keycloak -n "${KEYCLOAK_NS}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  fi
  if [[ -n "${KC_NAME}" ]]; then
    OIDC_OPTS="${OIDC_OPTS} --set oidc.keycloakName=${KC_NAME}"
  fi
fi

# --- Namespace: one per SAW ---
DEPLOY_NS="${SAW_NS}"
oc create namespace "${DEPLOY_NS}" --dry-run=client -o yaml | oc apply -f - >/dev/null
# The label lets the shared governance interceptor accept this SAW's VM.
oc label namespace "${DEPLOY_NS}" openshell.pattern/saw=true \
  ${OWNER:+openshell.pattern/owner="$(echo "${OWNER}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g' | cut -c1-63)"} \
  --overwrite >/dev/null

# --- Compute route hostname ---
ROUTE_HOST=""
APPS_DOMAIN=$(oc get ingress.config.openshift.io cluster \
  -o jsonpath='{.spec.domain}' 2>/dev/null || true)
if [[ -n "${APPS_DOMAIN}" ]]; then
  ROUTE_HOST="${OPENSHELL_SAW_NAME}-gateway-${DEPLOY_NS}.${APPS_DOMAIN}"
fi

# --- Provider credential Secret ---
# The VM's installer reads provider keys only from mounted Secrets, so the
# key goes into the "inference" Secret instead of the Helm release values.
if [[ -n "${API_KEY}" ]]; then
  oc create secret generic inference -n "${DEPLOY_NS}" \
    --from-literal=api_key="${API_KEY}" \
    ${PROVIDER:+--from-literal=provider="${PROVIDER}"} \
    ${MODEL:+--from-literal=model="${MODEL}"} \
    ${ENDPOINT_URL:+--from-literal=url="${ENDPOINT_URL}"} \
    --dry-run=client -o yaml | oc apply -f - >/dev/null
  echo "Secret 'inference' updated in ${DEPLOY_NS}."
fi

if [[ -n "${WEB_SEARCH_API_KEY}" ]]; then
  oc create secret generic web-search -n "${DEPLOY_NS}" \
    --from-literal=api_key="${WEB_SEARCH_API_KEY}" \
    --dry-run=client -o yaml | oc apply -f - >/dev/null
  echo "Secret 'web-search' updated in ${DEPLOY_NS}."
fi

# --- SAW-BOM profiles ---
# The VM can only attach ConfigMaps from its own namespace, so each SAW gets
# its own saw-bom-profiles ConfigMap.
BOM_OPTS=()
if [[ -n "${PROFILES}" ]]; then
  BOM_VALUES="$(mktemp)"
  trap 'rm -f "${BOM_VALUES}"' EXIT
  { echo "profiles:"; tr ',' '\n' <<<"${PROFILES}" | sed -e 's/^ *//' -e 's/ *$//' -e '/^$/d' -e 's/^/  - /'; } > "${BOM_VALUES}"
  BOM_OPTS=(-f "${BOM_VALUES}")
fi
# ${arr[@]+...}: an empty array is "unbound" under set -u in bash < 4.4 (macOS).
helm upgrade --install saw-bom "${SAW_BOM_CHART}" --namespace "${DEPLOY_NS}" ${BOM_OPTS[@]+"${BOM_OPTS[@]}"} >/dev/null
echo "SAW-BOM profiles installed in ${DEPLOY_NS}${PROFILES:+ (${PROFILES})}."

# --- Deploy ---
echo "Provisioning sandbox '${OPENSHELL_SAW_NAME}' for owner '${OWNER}' in namespace '${DEPLOY_NS}'..."

# shellcheck disable=SC2086
helm upgrade --install "${OPENSHELL_SAW_NAME}" "${SAW_CHART}" \
  --namespace "${DEPLOY_NS}" --create-namespace \
  --set sandboxName="${OPENSHELL_SAW_NAME}" \
  ${SANDBOX_IMAGE:+--set sandboxImage="${SANDBOX_IMAGE}"} \
  --set agent="${AGENT}" \
  --set inference.provider="${PROVIDER}" \
  --set inference.model="${MODEL}" \
  --set inference.endpointUrl="${ENDPOINT_URL}" \
  --set inference.webSearch="${WEB_SEARCH}" \
  ${GCP_SA_JSON:+--set-file vertexSaJson="${GCP_SA_JSON}"} \
  ${OIDC_OPTS} \
  --set accessControl.owner="${OWNER}" \
  ${OWNER_SUBJECT:+--set-string accessControl.ownerSubject="${OWNER_SUBJECT}"} \
  --set oidc.keycloakNamespace="${KEYCLOAK_NS}" \
  --set governance.namespace="${NS}" \
  --set source.dataSourceNamespace="${NS}" \
  --set containerRuntime="${CONTAINER_RUNTIME}" \
  --set governance.enabled="${GOVERNANCE_ENABLED}" \
  --set governance.engine="${GOVERNANCE_ENGINE}" \
  --set route.enabled=true --set route.dashboard=true \
  ${ROUTE_HOST:+--set route.host="${ROUTE_HOST}"} \
  ${APPS_DOMAIN:+--set route.webuiHost="${OPENSHELL_SAW_NAME}-webui-${DEPLOY_NS}.${APPS_DOMAIN}"} \
  ${APPS_DOMAIN:+--set route.dashboardHost="${OPENSHELL_SAW_NAME}-dashboard-${DEPLOY_NS}.${APPS_DOMAIN}"}

echo ""
echo "Sandbox '${OPENSHELL_SAW_NAME}' deployed."
echo "  Owner:     ${OWNER}"
echo "  Namespace: ${DEPLOY_NS}"

GW_URL=$(oc get route "${OPENSHELL_SAW_NAME}-gateway" -n "${DEPLOY_NS}" -o jsonpath='https://{.spec.host}' 2>/dev/null || true)
if [[ -n "${GW_URL}" ]]; then
  echo "  Gateway:   ${GW_URL}"
fi

DASH_URL=$(oc get route "${OPENSHELL_SAW_NAME}-dashboard" -n "${DEPLOY_NS}" -o jsonpath='https://{.spec.host}' 2>/dev/null || true)
if [[ -n "${DASH_URL}" ]]; then
  echo "  Dashboard: ${DASH_URL}"
fi

echo ""
echo "Next steps:"
echo "  1. make openshell-saw-configure-gateway OPENSHELL_SAW_NAME=${OPENSHELL_SAW_NAME} SAW_NS=${DEPLOY_NS}"
echo "  2. openshell gateway login"
echo "  3. openshell sandbox list"
echo "Shell on the VM (adds your SSH key on demand): make openshell-saw-vm-ssh OPENSHELL_SAW_NAME=${OPENSHELL_SAW_NAME} SAW_NS=${DEPLOY_NS}"
