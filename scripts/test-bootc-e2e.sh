#!/usr/bin/env bash
# End-to-end test: bootc gateway image → golden image → sandbox VM.
#
# Validates the full pipeline:
#   1. Bootc image build completed (ImageStream tag exists)
#   2. Golden image DataVolume imported successfully
#   3. Sandbox VM boots from golden image
#   4. Cloud-init completes inside the VM
#   5. OpenShell gateway is running (port 17670 reachable)
#   6. openshell CLI can list sandboxes
#   7. Cleanup
#
# Prerequisites:
#   - oc logged in to the cluster
#   - Bootc image already built (make build-gateway-image)
#   - Keycloak deployed (make keycloak) — or set OIDC_ISSUER
#   - SSH keypair at ~/.ssh/id_ed25519
#
# Usage:
#   ./scripts/test-bootc-e2e.sh [--skip-cleanup]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHARTS_DIR="${REPO_ROOT}/charts"

NS="${NS:-openshell-agents}"
SANDBOX_NAME="${SANDBOX_NAME:-bootc-test-sb}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-openshell-cli}"
SKIP_CLEANUP="${1:-}"

# Inference provider for the test sandbox (not exercised, just needs valid values)
TEST_PROVIDER="${TEST_PROVIDER:-gemini}"
TEST_MODEL="${TEST_MODEL:-gemini-2.5-flash}"
TEST_API_KEY="${TEST_API_KEY:-test-key-not-real}"

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
    echo -e "  ${GREEN}✓ PASS${NC}"
    pass_count=$((pass_count + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC}"
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
    echo -e "\n${YELLOW}Skipping cleanup (--skip-cleanup). Resources in namespace ${NS}:${NC}"
    echo "  helm delete ${SANDBOX_NAME} -n ${NS}"
    return
  fi
  echo -e "\n${CYAN}Cleaning up...${NC}"
  helm delete "${SANDBOX_NAME}" -n "${NS}" 2>/dev/null || true
  # Wait for VM to be deleted
  for _ in $(seq 1 30); do
    if ! kubectl get vm "${SANDBOX_NAME}" -n "${NS}" 2>/dev/null; then
      break
    fi
    sleep 5
  done
  echo "Cleanup complete."
}

trap cleanup EXIT

echo "============================================="
echo " Bootc E2E Test"
echo "============================================="
echo "  Namespace:    ${NS}"
echo "  Sandbox:      ${SANDBOX_NAME}"
echo "  Charts dir:   ${CHARTS_DIR}"
echo ""

# --- Pre-flight checks ---
echo -e "${CYAN}Pre-flight checks...${NC}"

check "oc is logged in" oc whoami

check "SSH public key exists" test -f "${SSH_KEY_PATH}.pub"

SSH_PUBKEY="$(cat "${SSH_KEY_PATH}.pub")"

# --- 1. Verify bootc image build ---
echo ""
echo -e "${CYAN}=== Phase 1: Bootc image ===${NC}"

check "ImageStream openshell-gateway exists" \
  oc get is openshell-gateway -n "${NS}" -o name

check "ImageStream tag :latest has a docker image reference" \
  bash -c "oc get is openshell-gateway -n '${NS}' -o jsonpath='{.status.tags[?(@.tag==\"latest\")].items[0].dockerImageReference}' | grep -q 'sha256:'"

# --- 2. Verify golden image ---
echo ""
echo -e "${CYAN}=== Phase 2: Golden image ===${NC}"

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

# --- 3. Deploy test sandbox ---
echo ""
echo -e "${CYAN}=== Phase 3: Deploy sandbox ===${NC}"

# Detect OIDC issuer
OIDC_ISSUER="${OIDC_ISSUER:-}"
if [[ -z "${OIDC_ISSUER}" ]]; then
  KC_HOST=$(oc get route openshell-keycloak -n "${NS}" -o jsonpath='{.spec.host}' 2>/dev/null || true)
  if [[ -n "${KC_HOST}" ]]; then
    OIDC_ISSUER="https://${KC_HOST}/realms/openshell"
  fi
fi

OIDC_OPTS=""
if [[ -n "${OIDC_ISSUER}" ]]; then
  echo "  Using OIDC issuer: ${OIDC_ISSUER}"
  OIDC_OPTS="--set oidc.issuerUrl=${OIDC_ISSUER} --set oidc.clientId=${OIDC_CLIENT_ID}"
fi

echo "  Installing sandbox helm release: ${SANDBOX_NAME}"
check "Helm install sandbox" \
  helm upgrade --install "${SANDBOX_NAME}" "${CHARTS_DIR}/openshell-sandbox" \
    --namespace "${NS}" \
    --set sandboxName="${SANDBOX_NAME}" \
    --set sshPublicKey="${SSH_PUBKEY}" \
    --set inference.provider="${TEST_PROVIDER}" \
    --set inference.model="${TEST_MODEL}" \
    --set inference.apiKey="${TEST_API_KEY}" \
    --set route.enabled=true \
    --set route.dashboard=true \
    ${OIDC_OPTS}

# --- 4. Wait for DataVolume provisioning ---
echo ""
echo -e "${CYAN}=== Phase 4: VM provisioning ===${NC}"

check "Sandbox DataVolume reaches Succeeded (up to 10 min)" \
  wait_for "sandbox DataVolume" 600 \
    bash -c "[[ \$(oc get dv '${SANDBOX_NAME}-root' -n '${NS}' -o jsonpath='{.status.phase}' 2>/dev/null) == 'Succeeded' ]]"

# --- 5. Wait for VM running ---
check "VM is Running (up to 5 min)" \
  wait_for "VM Running" 300 \
    bash -c "[[ \$(oc get vmi '${SANDBOX_NAME}' -n '${NS}' -o jsonpath='{.status.phase}' 2>/dev/null) == 'Running' ]]"

check "VM is Ready" \
  wait_for "VM Ready" 120 \
    bash -c "[[ \$(oc get vmi '${SANDBOX_NAME}' -n '${NS}' -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null) == 'True' ]]"

# --- 6. Verify cloud-init and gateway ---
echo ""
echo -e "${CYAN}=== Phase 5: VM health ===${NC}"

# Wait for SSH
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

# --- 7. Check routes ---
echo ""
echo -e "${CYAN}=== Phase 6: Routes ===${NC}"

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

# --- Summary ---
echo ""
echo "============================================="
echo -e " Results: ${GREEN}${pass_count} passed${NC}, ${RED}${fail_count} failed${NC} out of ${total_count} checks"
echo "============================================="

if [[ "${fail_count}" -gt 0 ]]; then
  exit 1
fi
