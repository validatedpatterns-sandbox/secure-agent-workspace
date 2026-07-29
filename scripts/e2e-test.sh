#!/usr/bin/env bash
# Headless E2E test — exercises the full quickstart flow without interactive prompts.
#
# Auto-detects the first configured provider from ~/values-secret.yaml,
# generates SSH keys, deploys Keycloak, fetches an OIDC token via Keycloak's
# ROPC grant, creates a sandbox, verifies VM health, and cleans up.
#
# Prerequisites:
#   - oc logged in to the cluster
#   - OpenShift Virtualization + RHBK operators installed
#   - Bootc gateway image built (make build-gateway-image)
#   - ~/values-secret.yaml with at least one provider API key
#
# Usage:
#   make test
#   # or directly:
#   ./scripts/e2e-test.sh [--skip-cleanup]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

NS="${NS:-openshell-agents}"
TEST_SANDBOX="${TEST_SANDBOX:-e2e-test-sb}"
TEST_OWNER="${TEST_OWNER:-alice}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-openshell-cli}"
OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR:-$HOME/.config/openshell/oidc}"
VALUES_SECRET="${VALUES_SECRET:-$HOME/values-secret.yaml}"
SSH_KEY_PATH="${SSH_KEY_PATH:-${REPO_ROOT}/.generated-ssh-keys/sandbox-ssh}"
SKIP_CLEANUP="${1:-}"

CHARTS_DIR="${REPO_ROOT}/charts"
HELM_DIR="${REPO_ROOT}/image-builder-charts/helm"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FAIL=0

step() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

check() {
  local desc="$1"; shift
  echo -n "  ${desc} ... "
  if "$@" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}FAIL${NC}"
    FAIL=1
  fi
}

wait_for() {
  local desc="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while true; do
    if "$@" 2>/dev/null; then return 0; fi
    if (( SECONDS > deadline )); then
      echo -e "  ${YELLOW}timeout after ${timeout}s waiting for: ${desc}${NC}"
      return 1
    fi
    sleep 10
  done
}

guest_ssh() {
  virtctl -n "${NS}" ssh "cloud-user@vm/${TEST_SANDBOX}" \
    --identity-file="${SSH_KEY_PATH}" \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
    --command="$1" 2>/dev/null
}

cleanup() {
  if [[ "${SKIP_CLEANUP}" == "--skip-cleanup" ]]; then
    echo -e "\n${YELLOW}Skipping cleanup (--skip-cleanup). To clean up:${NC}"
    echo "  helm uninstall ${TEST_SANDBOX} -n ${NS}"
    echo "  oc delete secret ${PROV:-provider} -n ${NS}"
    return
  fi
  step "Cleanup"
  helm uninstall "${TEST_SANDBOX}" -n "${NS}" 2>/dev/null || true
  oc delete secret "${PROV:-provider}" -n "${NS}" 2>/dev/null || true
  for _ in $(seq 1 30); do
    kubectl get vm "${TEST_SANDBOX}" -n "${NS}" 2>/dev/null || break
    sleep 5
  done
  echo "Done."
}

trap cleanup EXIT

# =============================================================================
# Detect provider
# =============================================================================

default_model_for() {
  case "$1" in
    gemini)     echo "gemini-2.5-flash" ;;
    anthropic)  echo "claude-sonnet-4-6" ;;
    openai)     echo "gpt-4o" ;;
    nvidia)     echo "meta/llama-3.3-70b-instruct" ;;
    openrouter) echo "anthropic/claude-sonnet-4-6" ;;
    *)          echo "" ;;
  esac
}

if [[ ! -f "${VALUES_SECRET}" ]]; then
  echo -e "${RED}Error: ${VALUES_SECRET} not found.${NC}"
  echo "  cp values-secret.yaml.template ~/values-secret.yaml && edit it"
  exit 1
fi

DETECTED=$(python3 -c "
import yaml, sys
PROVIDERS = ['gemini', 'anthropic', 'openai', 'nvidia', 'openrouter']
with open('${VALUES_SECRET}') as f:
    data = yaml.safe_load(f)
for s in data.get('secrets', []):
    if s['name'] in PROVIDERS:
        for field in s.get('fields', []):
            if field['name'] == 'api_key' and field.get('value') and str(field['value']) != 'null':
                print(f\"{s['name']}={field['value']}\")
                sys.exit(0)
sys.exit(1)
" 2>/dev/null) || true

if [[ -z "${DETECTED}" ]]; then
  echo -e "${RED}Error: No provider API key found in ${VALUES_SECRET}.${NC}"
  echo "  Set at least one provider key (gemini, anthropic, openai, nvidia, openrouter)"
  exit 1
fi

PROV="${DETECTED%%=*}"
PKEY="${DETECTED#*=}"
PMOD=$(default_model_for "${PROV}")

echo "============================================="
echo " Headless E2E Test"
echo "============================================="
echo "  Namespace:    ${NS}"
echo "  Sandbox:      ${TEST_SANDBOX}"
echo "  Provider:     ${PROV}"
echo "  Model:        ${PMOD}"
echo "  Owner:        ${TEST_OWNER}"
echo "  SSH key:      ${SSH_KEY_PATH}"

# =============================================================================
# Pre-flight
# =============================================================================
step "Pre-flight checks"

check "oc is logged in" oc whoami
check "OpenShift Virtualization operator" bash -c "oc get csv --all-namespaces 2>/dev/null | grep -q kubevirt"
check "RHBK operator" bash -c "oc get csv --all-namespaces 2>/dev/null | grep -q rhbk"

# =============================================================================
# SSH keys
# =============================================================================
step "SSH keys"

if [[ ! -f "${SSH_KEY_PATH}" ]]; then
  echo "  Generating SSH keypair..."
  mkdir -p "$(dirname "${SSH_KEY_PATH}")"
  ssh-keygen -t ed25519 -f "${SSH_KEY_PATH}" -N "" -C "openshell-sandbox"
fi
check "SSH keypair exists" test -f "${SSH_KEY_PATH}.pub"

# =============================================================================
# Keycloak
# =============================================================================
step "Deploy Keycloak"

KC_INSTALLED=$(helm list -n "${NS}" -o json 2>/dev/null | python3 -c "
import json, sys
releases = json.load(sys.stdin)
print('yes' if any(r['name'] == 'openshell-keycloak' for r in releases) else 'no')
" 2>/dev/null || echo "no")

if [[ "${KC_INSTALLED}" == "yes" ]]; then
  echo "  Already deployed, skipping."
else
  helm upgrade --install openshell-keycloak "${CHARTS_DIR}/openshell-keycloak" \
    --namespace "${NS}" --create-namespace --timeout 10m
fi

echo "  Waiting for Keycloak Ready..."
check "Keycloak is Ready (up to 5 min)" \
  wait_for "Keycloak Ready" 300 \
    bash -c "[[ \$(oc get keycloak openshell-keycloak -n '${NS}' -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null) == 'True' ]]"

# =============================================================================
# OIDC token (headless via ROPC grant)
# =============================================================================
step "Fetch OIDC token"

KC_URL=$(oc get keycloak openshell-keycloak -n "${NS}" -o jsonpath='{.status.externalURL}' 2>/dev/null || true)
if [[ -z "${KC_URL}" ]]; then
  KC_HOST=$(oc get route -n "${NS}" -l app=keycloak -o jsonpath='{.items[0].spec.host}' 2>/dev/null || true)
  KC_URL="https://${KC_HOST}"
fi
OIDC_ISSUER="${KC_URL}/realms/openshell"
echo "  Keycloak: ${KC_URL}"

OIDC_TOKEN=$(curl -sk -X POST "${KC_URL}/realms/openshell/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=${OIDC_CLIENT_ID}" \
  -d "username=${TEST_OWNER}" \
  -d "password=${TEST_OWNER}" \
  -d "scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)

if [[ -z "${OIDC_TOKEN}" ]]; then
  echo -e "  ${YELLOW}WARN: Could not fetch OIDC token${NC}"
else
  echo "  Token obtained for ${TEST_OWNER}"
  mkdir -p "${OIDC_TOKEN_DIR}"
  printf '{"access_token":"%s"}' "${OIDC_TOKEN}" > "${OIDC_TOKEN_DIR}/token.json"
fi

# =============================================================================
# Provider secret
# =============================================================================
step "Create provider secret"

oc delete secret "${PROV}" -n "${NS}" 2>/dev/null || true
check "Create k8s Secret '${PROV}'" \
  oc create secret generic "${PROV}" --namespace "${NS}" --from-literal=api_key="${PKEY}"

# SSH secret
oc delete secret openshell-aap-ssh -n "${NS}" 2>/dev/null || true
oc create secret generic openshell-aap-ssh --namespace "${NS}" --from-file=key="${SSH_KEY_PATH}" 2>/dev/null || true

# =============================================================================
# Deploy sandbox
# =============================================================================
step "Deploy sandbox"

SSH_PUBKEY="$(cat "${SSH_KEY_PATH}.pub")"
OIDC_OPTS=""
if [[ -n "${OIDC_ISSUER}" ]]; then
  OIDC_OPTS="--set oidc.issuerUrl=${OIDC_ISSUER} --set oidc.clientId=${OIDC_CLIENT_ID}"
fi
if [[ -n "${OIDC_TOKEN:-}" ]]; then
  OIDC_OPTS="${OIDC_OPTS} --set-string oidc.token=${OIDC_TOKEN}"
fi

helm upgrade --install "${TEST_SANDBOX}" "${CHARTS_DIR}/openshell-sandbox" \
  --namespace "${NS}" \
  --set sandboxName="${TEST_SANDBOX}" \
  --set sshPublicKey="${SSH_PUBKEY}" \
  --set inference.provider="${PROV}" \
  --set inference.model="${PMOD}" \
  --set inference.secretName="${PROV}" \
  --set accessControl.owner="${TEST_OWNER}" \
  --set route.enabled=true \
  --set route.dashboard=true \
  ${OIDC_OPTS}

# =============================================================================
# Wait for VM
# =============================================================================
step "Wait for VM"

echo "  Waiting for DataVolume..."
wait_for "DataVolume Succeeded" 600 \
  bash -c "[[ \$(oc get dv '${TEST_SANDBOX}-root' -n '${NS}' -o jsonpath='{.status.phase}' 2>/dev/null) == 'Succeeded' ]]" \
  || { echo "FAIL: DataVolume not ready"; exit 1; }

echo "  Waiting for VMI Running + Ready..."
deadline=$((SECONDS + 600))
while true; do
  phase=$(oc get vmi "${TEST_SANDBOX}" -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  ready=$(oc get vmi "${TEST_SANDBOX}" -n "${NS}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
  echo "  vmi phase=${phase:-pending} ready=${ready:-false}"
  if [[ "${phase}" == "Running" && "${ready}" == "True" ]]; then break; fi
  if (( SECONDS > deadline )); then echo "FAIL: VM not ready in time"; exit 1; fi
  sleep 10
done

# =============================================================================
# Wait for SSH
# =============================================================================
step "Wait for SSH"

check "SSH reachable (up to 3 min)" \
  wait_for "SSH" 180 \
    virtctl -n "${NS}" ssh "cloud-user@vm/${TEST_SANDBOX}" \
      --identity-file="${SSH_KEY_PATH}" \
      --local-ssh-opts=-oStrictHostKeyChecking=no \
      --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
      --command="echo ssh-ok"

# =============================================================================
# VM health checks
# =============================================================================
step "Verify VM health"

check "openshell CLI installed"        guest_ssh "openshell --version"
check "podman installed"               guest_ssh "podman --version"
check "nodejs installed"               guest_ssh "node --version"
check "/etc/openshell exists"          guest_ssh "test -d /etc/openshell"
check "gateway setup service exists"   guest_ssh "systemctl cat openshell-gateway-setup.service >/dev/null 2>&1"
check "cloud-user has sudo"            guest_ssh "sudo whoami | grep -q root"

# =============================================================================
# Routes
# =============================================================================
step "Verify routes"

GW_TLS=$(oc get route "${TEST_SANDBOX}-gateway" -n "${NS}" -o jsonpath='{.spec.tls.termination}' 2>/dev/null || true)
check "Gateway route exists"           test -n "${GW_TLS}"
check "Gateway uses TLS passthrough"   test "${GW_TLS}" = "passthrough"
check "Dashboard route exists"         oc get route "${TEST_SANDBOX}-dashboard" -n "${NS}" -o name

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================="
if [[ "${FAIL}" -eq 0 ]]; then
  echo -e " ${GREEN}ALL CHECKS PASSED${NC}"
else
  echo -e " ${RED}SOME CHECKS FAILED${NC}"
fi
echo "============================================="

exit "${FAIL}"
