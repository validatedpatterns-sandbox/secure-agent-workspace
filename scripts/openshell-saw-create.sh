#!/usr/bin/env bash
# Provision a sandbox — detects owner from OIDC token, deploys via helm.
#
# Required env vars: OPENSHELL_SAW_NAME, SSH_PUBKEY, SAW_CHART
# Required env vars (provider): PROVIDER + MODEL + API_KEY, or GCP_SA_JSON
# Optional: OWNER, OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_TOKEN_DIR, NS,
#           AGENT, ENDPOINT_URL, WEB_SEARCH, NAMESPACE_MODE, SCRIPTS_DIR

set -euo pipefail

NS="${NS:-openshell-agents}"
OPENSHELL_SAW_NAME="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
if (( ${#OPENSHELL_SAW_NAME} > 19 )); then
  echo "ERROR: OPENSHELL_SAW_NAME '${OPENSHELL_SAW_NAME}' is ${#OPENSHELL_SAW_NAME} characters — OpenShell enforces a 19-character maximum." >&2
  exit 1
fi
SAW_CHART="${SAW_CHART:?SAW_CHART is required}"
SSH_PUBKEY="${SSH_PUBKEY:?SSH_PUBKEY is required}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-}"
AGENT="${AGENT:-openclaw}"
PROVIDER="${PROVIDER:-}"
MODEL="${MODEL:-}"
API_KEY="${API_KEY:-}"
ENDPOINT_URL="${ENDPOINT_URL:-}"
WEB_SEARCH="${WEB_SEARCH:-}"
GCP_SA_JSON="${GCP_SA_JSON:-}"
OIDC_ISSUER="${OIDC_ISSUER:-}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-openshell-cli}"
OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR:-$HOME/.config/openshell/oidc}"
OWNER="${OWNER:-}"
NAMESPACE_MODE="${NAMESPACE_MODE:-shared}"
SCRIPTS_DIR="${SCRIPTS_DIR:-scripts}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
GOVERNANCE_ENABLED="${GOVERNANCE_ENABLED:-true}"
# GPU passthrough — off by default. Requires bare-metal/IOMMU-capable nodes with a GPU bound
# to vfio-pci and a matching HyperConverged permittedHostDevices entry — see
# docs/gpu-passthrough.md. Setting this on hardware that doesn't support it is a documented
# no-op/warning, not a hard failure.
GPU_ENABLED="${GPU_ENABLED:-false}"
GPU_COUNT="${GPU_COUNT:-1}"

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

  printf "Logged in as '\033[1m%s\033[0m'\n" "${KC_USER}"
  printf "Press Enter to set owner to '%s', or type a different owner: " "${KC_USER}"
  read -r INPUT_OWNER
  if [[ -n "${INPUT_OWNER}" ]]; then
    OWNER="${INPUT_OWNER}"
  else
    OWNER="${KC_USER}"
  fi
fi

# --- Detect OIDC issuer ---
if [[ -z "${OIDC_ISSUER}" ]]; then
  KC_HOST=$(oc get keycloak --all-namespaces -o jsonpath='{.items[0].status.externalURL}' 2>/dev/null \
    | sed 's|^https://||;s|/$||' || true)
  if [[ -z "${KC_HOST}" ]]; then
    KC_HOST=$(oc get route --all-namespaces -l app=keycloak -o jsonpath='{.items[0].spec.host}' 2>/dev/null || true)
  fi
  if [[ -n "${KC_HOST}" ]]; then
    OIDC_ISSUER="https://${KC_HOST}/realms/openshell"
  fi
fi

# --- Build OIDC helm options ---
OIDC_OPTS=""
if [[ -n "${OIDC_ISSUER}" ]]; then
  OIDC_OPTS="--set oidc.issuerUrl=${OIDC_ISSUER} --set oidc.clientId=${OIDC_CLIENT_ID}"
  OIDC_TOKEN=$(OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR}" OIDC_CLIENT_ID="${OIDC_CLIENT_ID}" \
    OIDC_ISSUER="${OIDC_ISSUER}" NS="${NS}" "${SCRIPTS_DIR}/oidc-login.sh" token 2>/dev/null || true)
  if [[ -n "${OIDC_TOKEN}" ]]; then
    OIDC_OPTS="${OIDC_OPTS} --set-string oidc.token=${OIDC_TOKEN}"
  fi
fi

# --- Namespace ---
DEPLOY_NS="${NS}"
if [[ "${NAMESPACE_MODE}" == "perUser" ]]; then
  DEPLOY_NS="saw-$(echo "${OWNER}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | cut -c1-58)"
  oc create namespace "${DEPLOY_NS}" --dry-run=client -o yaml | oc apply -f - 2>/dev/null
fi

# --- Deploy ---
echo "Provisioning sandbox '${OPENSHELL_SAW_NAME}' for owner '${OWNER}' in namespace '${DEPLOY_NS}'..."

# shellcheck disable=SC2086
helm upgrade --install "${OPENSHELL_SAW_NAME}" "${SAW_CHART}" \
  --namespace "${DEPLOY_NS}" --create-namespace \
  --set sandboxName="${OPENSHELL_SAW_NAME}" \
  --set sshPublicKey="${SSH_PUBKEY}" \
  ${SANDBOX_IMAGE:+--set sandboxImage="${SANDBOX_IMAGE}"} \
  --set agent="${AGENT}" \
  --set inference.provider="${PROVIDER}" \
  --set inference.model="${MODEL}" \
  --set inference.apiKey="${API_KEY}" \
  --set inference.endpointUrl="${ENDPOINT_URL}" \
  --set inference.webSearch="${WEB_SEARCH}" \
  ${GCP_SA_JSON:+--set-file vertexSaJson="${GCP_SA_JSON}"} \
  ${OIDC_OPTS} \
  --set accessControl.owner="${OWNER}" \
  --set namespaceMode="${NAMESPACE_MODE}" \
  --set containerRuntime="${CONTAINER_RUNTIME}" \
  --set governance.enabled="${GOVERNANCE_ENABLED}" \
  --set vm.gpu.enabled="${GPU_ENABLED}" --set vm.gpu.count="${GPU_COUNT}" \
  --set route.enabled=true --set route.dashboard=true

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
echo "  1. make openshell-saw-configure-gateway OPENSHELL_SAW_NAME=${OPENSHELL_SAW_NAME} NS=${DEPLOY_NS}"
echo "  2. openshell gateway login"
echo "  3. openshell --gateway-insecure sandbox list"
