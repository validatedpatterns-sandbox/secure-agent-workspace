#!/usr/bin/env bash
# End-to-end test: Keycloak + bootc gateway image + golden image + sandbox VM.
#
# Auto-detects the first configured inference provider from ~/values-secret.yaml
# and creates k8s Secrets directly (no Vault/ESO required for testing).
#
# Validates the full pipeline:
#   1. Prerequisites (operators, CLI tools)
#   2. Keycloak deployed via RHBK operator
#   3. Bootc image build completed (ImageStream tag exists)
#   4. Golden image DataVolume imported successfully
#   5. Provider k8s Secret created
#   6. Sandbox VM boots from golden image
#   7. Cloud-init completes inside the VM
#   8. OpenShell packages installed
#   9. Routes created with correct TLS termination
#  10. Cleanup
#
# Prerequisites:
#   - oc logged in to the cluster
#   - Bootc image already built (make build-gateway-image)
#   - RHBK operator installed
#   - OpenShift Virtualization operator installed
#   - SSH keypair at ~/.ssh/id_ed25519
#   - ~/values-secret.yaml with at least one provider API key set
#
# Usage:
#   ./tests/test-bootc-e2e.sh [--skip-cleanup]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHARTS_DIR="${REPO_ROOT}/charts"

NS="${NS:-openshell-agents}"
SANDBOX_NAME="${SANDBOX_NAME:-bootc-test-sb}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-openshell-cli}"
VALUES_SECRET="${VALUES_SECRET:-$HOME/values-secret.yaml}"
SKIP_CLEANUP="${1:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass_count=0
fail_count=0
total_count=0

check() {
  local desc="$1"
  shift
  total_count=$((total_count + 1))
  echo -e "${CYAN}[${total_count}] ${desc}${NC}"
  if "$@"; then
    echo -e "  ${GREEN}PASS${NC}"
    pass_count=$((pass_count + 1))
  else
    echo -e "  ${RED}FAIL${NC}"
    fail_count=$((fail_count + 1))
  fi
}

wait_for() {
  local desc="$1"
  local timeout="$2"
  shift 2
  local deadline=$((SECONDS + timeout))
  while true; do
    if "$@" 2>/dev/null; then
      return 0
    fi
    if (( SECONDS > deadline )); then
      echo -e "  ${YELLOW}timeout after ${timeout}s waiting for: ${desc}${NC}"
      return 1
    fi
    sleep 10
  done
}

cleanup() {
  if [[ "${SKIP_CLEANUP}" == "--skip-cleanup" ]]; then
    echo -e "\n${YELLOW}Skipping cleanup (--skip-cleanup). To clean up manually:${NC}"
    echo "  helm uninstall ${SANDBOX_NAME} -n ${NS}"
    echo "  helm uninstall openshell-keycloak -n ${NS}"
    echo "  oc delete secret ${PROVIDER_NAME:-provider} -n ${NS}"
    return
  fi
  echo -e "\n${CYAN}Cleaning up...${NC}"
  helm uninstall "${SANDBOX_NAME}" -n "${NS}" 2>/dev/null || true
  helm uninstall openshell-keycloak -n "${NS}" 2>/dev/null || true
  oc delete secret "${PROVIDER_NAME:-provider}" -n "${NS}" 2>/dev/null || true
  for _ in $(seq 1 30); do
    if ! kubectl get vm "${SANDBOX_NAME}" -n "${NS}" 2>/dev/null; then
      break
    fi
    sleep 5
  done
  echo "Cleanup complete."
}

trap cleanup EXIT

# =============================================================================
# Auto-detect provider from ~/values-secret.yaml
# =============================================================================

# Provider name -> default model mapping
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

PROVIDER_NAME=""
PROVIDER_KEY=""
PROVIDER_MODEL=""

if [[ ! -f "${VALUES_SECRET}" ]]; then
  echo -e "${RED}Error: ${VALUES_SECRET} not found.${NC}"
  echo ""
  echo "Create it from the template:"
  echo "  cp values-secret.yaml.template ~/values-secret.yaml"
  echo "  # Edit ~/values-secret.yaml and set at least one provider API key"
  exit 1
fi

# Parse values-secret.yaml to find the first provider with a non-null key
DETECTED=$(python3 -c "
import yaml, sys
PROVIDERS = ['gemini', 'anthropic', 'openai', 'nvidia', 'openrouter']
with open('${VALUES_SECRET}') as f:
    data = yaml.safe_load(f)
for s in data.get('secrets', []):
    if s['name'] in PROVIDERS:
        for field in s.get('fields', []):
            if field['name'] == 'api_key' and field.get('value') and field['value'] != 'null':
                print(f\"{s['name']}={field['value']}\")
                sys.exit(0)
sys.exit(1)
" 2>/dev/null) || true

if [[ -z "${DETECTED}" ]]; then
  echo -e "${RED}Error: No inference provider API key found in ${VALUES_SECRET}.${NC}"
  echo ""
  echo "Set at least one provider API key (gemini, anthropic, openai, nvidia, or openrouter):"
  echo "  vi ~/values-secret.yaml"
  echo ""
  echo "Example:"
  echo "  - name: gemini"
  echo "    fields:"
  echo "    - name: api_key"
  echo "      value: AIza..."
  exit 1
fi

PROVIDER_NAME="${DETECTED%%=*}"
PROVIDER_KEY="${DETECTED#*=}"
PROVIDER_MODEL=$(default_model_for "${PROVIDER_NAME}")

echo "============================================="
echo " Bootc E2E Test"
echo "============================================="
echo "  Namespace:    ${NS}"
echo "  Sandbox:      ${SANDBOX_NAME}"
echo "  Provider:     ${PROVIDER_NAME}"
echo "  Model:        ${PROVIDER_MODEL}"
echo "  Secrets from: ${VALUES_SECRET}"
echo ""

# =============================================================================
# Phase 1: Pre-flight checks
# =============================================================================
echo -e "${CYAN}=== Phase 1: Pre-flight checks ===${NC}"

check "oc is logged in" oc whoami

check "SSH public key exists" test -f "${SSH_KEY_PATH}.pub"

SSH_PUBKEY="$(cat "${SSH_KEY_PATH}.pub")"

check "OpenShift Virtualization operator installed" \
  bash -c "oc get csv --all-namespaces 2>/dev/null | grep -q kubevirt"

check "RHBK (Keycloak) operator installed" \
  bash -c "oc get csv --all-namespaces 2>/dev/null | grep -q rhbk"

# =============================================================================
# Phase 2: Deploy Keycloak
# =============================================================================
echo ""
echo -e "${CYAN}=== Phase 2: Keycloak ===${NC}"

KC_INSTALLED=$(helm list -n "${NS}" -o json 2>/dev/null | python3 -c "
import json, sys
releases = json.load(sys.stdin)
print('yes' if any(r['name'] == 'openshell-keycloak' for r in releases) else 'no')
" 2>/dev/null || echo "no")

if [[ "${KC_INSTALLED}" == "yes" ]]; then
  echo "  Keycloak already deployed, skipping install."
  check "Keycloak helm release exists" true
else
  check "Deploy Keycloak via RHBK operator" \
    helm upgrade --install openshell-keycloak "${CHARTS_DIR}/openshell-keycloak" \
      --namespace "${NS}" --create-namespace --timeout 10m
fi

check "Keycloak is Ready (up to 5 min)" \
  wait_for "Keycloak Ready" 300 \
    bash -c "[[ \$(oc get keycloak openshell-keycloak -n '${NS}' -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null) == 'True' ]]"

# Detect OIDC issuer
OIDC_ISSUER=""
KC_URL=$(oc get keycloak openshell-keycloak -n "${NS}" -o jsonpath='{.status.externalURL}' 2>/dev/null || true)
if [[ -n "${KC_URL}" ]]; then
  OIDC_ISSUER="${KC_URL}/realms/openshell"
else
  KC_HOST=$(oc get route -n "${NS}" -l app=keycloak -o jsonpath='{.items[0].spec.host}' 2>/dev/null || true)
  if [[ -n "${KC_HOST}" ]]; then
    OIDC_ISSUER="https://${KC_HOST}/realms/openshell"
  fi
fi
echo "  OIDC issuer: ${OIDC_ISSUER:-not detected}"

# =============================================================================
# Phase 3: Verify bootc image + golden image
# =============================================================================
echo ""
echo -e "${CYAN}=== Phase 3: Bootc image + golden image ===${NC}"

check "ImageStream openshell-gateway exists" \
  oc get is openshell-gateway -n "${NS}" -o name

check "ImageStream tag :latest has a docker image reference" \
  bash -c "oc get is openshell-gateway -n '${NS}' -o jsonpath='{.status.tags[?(@.tag==\"latest\")].items[0].dockerImageReference}' | grep -q 'sha256:'"

check "DataVolume openshell-gateway-golden exists" \
  oc get dv openshell-gateway-golden -n "${NS}" -o name

DV_PHASE=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
if [[ "${DV_PHASE}" != "Succeeded" ]]; then
  echo -e "  ${YELLOW}DataVolume phase is '${DV_PHASE}', waiting up to 10 min...${NC}"
  check "DataVolume reaches Succeeded" \
    wait_for "DataVolume Succeeded" 600 \
      bash -c "[[ \$(oc get dv openshell-gateway-golden -n '${NS}' -o jsonpath='{.status.phase}') == 'Succeeded' ]]"
else
  check "DataVolume is Succeeded" true
fi

check "DataSource openshell-gateway exists" \
  oc get datasource openshell-gateway -n "${NS}" -o name

# =============================================================================
# Phase 4: Create provider secret + deploy sandbox
# =============================================================================
echo ""
echo -e "${CYAN}=== Phase 4: Deploy sandbox ===${NC}"

echo "  Creating k8s Secret '${PROVIDER_NAME}' with API key..."
oc delete secret "${PROVIDER_NAME}" -n "${NS}" 2>/dev/null || true
check "Create provider secret" \
  oc create secret generic "${PROVIDER_NAME}" \
    --namespace "${NS}" \
    --from-literal=api_key="${PROVIDER_KEY}"

oc delete secret openshell-aap-ssh -n "${NS}" 2>/dev/null || true
oc create secret generic openshell-aap-ssh \
  --namespace "${NS}" \
  --from-file=key="${SSH_KEY_PATH}" 2>/dev/null || true

OIDC_OPTS=""
if [[ -n "${OIDC_ISSUER}" ]]; then
  OIDC_OPTS="--set oidc.issuerUrl=${OIDC_ISSUER} --set oidc.clientId=${OIDC_CLIENT_ID}"
fi

echo "  Installing sandbox helm release: ${SANDBOX_NAME}"
check "Helm install sandbox" \
  helm upgrade --install "${SANDBOX_NAME}" "${CHARTS_DIR}/openshell-sandbox" \
    --namespace "${NS}" \
    --set sandboxName="${SANDBOX_NAME}" \
    --set sshPublicKey="${SSH_PUBKEY}" \
    --set inference.provider="${PROVIDER_NAME}" \
    --set inference.model="${PROVIDER_MODEL}" \
    --set inference.secretName="${PROVIDER_NAME}" \
    --set route.enabled=true \
    --set route.dashboard=true \
    ${OIDC_OPTS}

# =============================================================================
# Phase 5: Wait for VM provisioning
# =============================================================================
echo ""
echo -e "${CYAN}=== Phase 5: VM provisioning ===${NC}"

check "Sandbox DataVolume reaches Succeeded (up to 10 min)" \
  wait_for "sandbox DataVolume" 600 \
    bash -c "[[ \$(oc get dv '${SANDBOX_NAME}-root' -n '${NS}' -o jsonpath='{.status.phase}' 2>/dev/null) == 'Succeeded' ]]"

check "VM is Running (up to 5 min)" \
  wait_for "VM Running" 300 \
    bash -c "[[ \$(oc get vmi '${SANDBOX_NAME}' -n '${NS}' -o jsonpath='{.status.phase}' 2>/dev/null) == 'Running' ]]"

check "VM is Ready" \
  wait_for "VM Ready" 120 \
    bash -c "[[ \$(oc get vmi '${SANDBOX_NAME}' -n '${NS}' -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null) == 'True' ]]"

# =============================================================================
# Phase 6: VM health checks
# =============================================================================
echo ""
echo -e "${CYAN}=== Phase 6: VM health ===${NC}"

echo "  Waiting for SSH access..."
check "SSH is reachable (up to 3 min)" \
  wait_for "SSH" 180 \
    virtctl -n "${NS}" ssh "cloud-user@vm/${SANDBOX_NAME}" \
      --identity-file="${SSH_KEY_PATH}" \
      --local-ssh-opts=-oStrictHostKeyChecking=no \
      --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
      --command="echo ssh-ok"

guest_ssh() {
  virtctl -n "${NS}" ssh "cloud-user@vm/${SANDBOX_NAME}" \
    --identity-file="${SSH_KEY_PATH}" \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
    --command="$1" 2>/dev/null
}

check "cloud-init finished" \
  wait_for "cloud-init" 300 \
    bash -c "virtctl -n '${NS}' ssh 'cloud-user@vm/${SANDBOX_NAME}' --identity-file='${SSH_KEY_PATH}' --local-ssh-opts=-oStrictHostKeyChecking=no --local-ssh-opts=-oUserKnownHostsFile=/dev/null --command='cloud-init status 2>/dev/null | grep -q done' 2>/dev/null"

check "cloud-user exists with sudo" \
  guest_ssh "sudo whoami | grep -q root"

check "podman is installed" \
  guest_ssh "podman --version"

check "openshell CLI is installed" \
  guest_ssh "openshell --version"

check "openshell-gateway binary is installed" \
  guest_ssh "which openshell-gateway"

check "nodejs is installed" \
  guest_ssh "node --version"

check "/etc/openshell directory exists" \
  guest_ssh "test -d /etc/openshell"

check "openshell-gateway-setup.service exists" \
  guest_ssh "systemctl cat openshell-gateway-setup.service >/dev/null 2>&1"

# =============================================================================
# Phase 7: Routes
# =============================================================================
echo ""
echo -e "${CYAN}=== Phase 7: Routes ===${NC}"

GW_ROUTE=$(oc get route "${SANDBOX_NAME}-gateway" -n "${NS}" -o jsonpath='{.spec.host}' 2>/dev/null || true)
if [[ -n "${GW_ROUTE}" ]]; then
  check "Gateway route exists" true
  echo "  Gateway URL: https://${GW_ROUTE}"

  ROUTE_TLS=$(oc get route "${SANDBOX_NAME}-gateway" -n "${NS}" -o jsonpath='{.spec.tls.termination}' 2>/dev/null || true)
  check "Gateway route uses TLS passthrough" \
    bash -c "[[ '${ROUTE_TLS}' == 'passthrough' ]]"
else
  check "Gateway route exists" false
fi

DASH_ROUTE=$(oc get route "${SANDBOX_NAME}-dashboard" -n "${NS}" -o jsonpath='{.spec.host}' 2>/dev/null || true)
if [[ -n "${DASH_ROUTE}" ]]; then
  check "Dashboard route exists" true
  echo "  Dashboard URL: https://${DASH_ROUTE}"
else
  check "Dashboard route exists" false
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================="
echo -e " Results: ${GREEN}${pass_count} passed${NC}, ${RED}${fail_count} failed${NC} out of ${total_count} checks"
echo "============================================="

if [[ "${fail_count}" -gt 0 ]]; then
  exit 1
fi
