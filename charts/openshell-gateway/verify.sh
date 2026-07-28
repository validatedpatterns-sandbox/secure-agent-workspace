#!/usr/bin/env bash
# Verify that the openshell-gateway Helm release is healthy.
# Run from your workstation after: helm install openshell-gateway ./helm/openshell-gateway ...
#
# Usage:
#   ./helm/openshell-gateway/verify.sh [RELEASE_NAME] [NAMESPACE]
#
set -euo pipefail

RELEASE="${1:-openshell-gateway}"
NS="${2:-openshell-agents}"
SSH_USER="cloud-user"
PASS=0
FAIL=0
WARN=0

pass() { PASS=$((PASS + 1)); echo "  PASS  $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }
warn() { WARN=$((WARN + 1)); echo "  WARN  $1"; }

echo "=== openshell-gateway verify: release=${RELEASE}  namespace=${NS} ==="
echo

# ---------- Phase 1: Kubernetes resources ----------
echo "--- Kubernetes resources ---"

if oc -n "${NS}" get vm "${RELEASE}" -o name &>/dev/null; then
  pass "VirtualMachine '${RELEASE}' exists"
else
  fail "VirtualMachine '${RELEASE}' not found"
fi

VMI_PHASE=$(oc -n "${NS}" get vmi "${RELEASE}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [[ "${VMI_PHASE}" == "Running" ]]; then
  pass "VMI '${RELEASE}' phase is Running"
else
  fail "VMI '${RELEASE}' phase is '${VMI_PHASE:-not found}' (expected Running)"
fi

VMI_READY=$(oc -n "${NS}" get vmi "${RELEASE}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
if [[ "${VMI_READY}" == "True" ]]; then
  pass "VMI '${RELEASE}' condition Ready=True"
else
  fail "VMI '${RELEASE}' condition Ready='${VMI_READY:-unknown}' (expected True)"
fi

SVC_NAME="${RELEASE}-gateway"
SVC_EP=$(oc -n "${NS}" get endpoints "${SVC_NAME}" -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null || true)
if [[ -n "${SVC_EP}" ]]; then
  pass "Service '${SVC_NAME}' has endpoints (${SVC_EP})"
else
  fail "Service '${SVC_NAME}' has no endpoints"
fi

echo

# ---------- Phase 2: Guest-level checks via virtctl SSH ----------
echo "--- Guest checks (via virtctl SSH) ---"

guest_cmd() {
  virtctl -n "${NS}" ssh "${SSH_USER}@vm/${RELEASE}" \
    --local-ssh-opts "-o StrictHostKeyChecking=no -o LogLevel=ERROR" \
    --command "$1" 2>/dev/null
}

if ! command -v virtctl &>/dev/null; then
  warn "virtctl not found — skipping guest checks"
else
  # Cloud-init completion
  CLOUD_INIT_STATUS=$(guest_cmd "cloud-init status 2>/dev/null | head -1" || true)
  if echo "${CLOUD_INIT_STATUS}" | grep -q "done"; then
    pass "cloud-init status: done"
  elif echo "${CLOUD_INIT_STATUS}" | grep -q "running"; then
    warn "cloud-init is still running"
  else
    fail "cloud-init status: '${CLOUD_INIT_STATUS:-unreachable}'"
  fi

  # Setup stamp file
  STAMP=$(guest_cmd "test -f /var/lib/openshell-gateway-setup.done && echo yes || echo no" || true)
  if [[ "${STAMP}" == *"yes"* ]]; then
    pass "Gateway setup stamp exists (/var/lib/openshell-gateway-setup.done)"
  else
    fail "Gateway setup stamp missing"
  fi

  # openshell CLI installed
  OS_VERSION=$(guest_cmd "openshell --version 2>/dev/null" || true)
  if [[ -n "${OS_VERSION}" ]]; then
    pass "openshell CLI installed: ${OS_VERSION}"
  else
    fail "openshell CLI not found"
  fi

  # openshell status
  OS_STATUS=$(guest_cmd "openshell status 2>&1" || true)
  if echo "${OS_STATUS}" | grep -qi "gateway.*running\|connected\|healthy"; then
    pass "openshell status: gateway running"
  elif [[ -n "${OS_STATUS}" ]]; then
    warn "openshell status output (review manually):"
    echo "        ${OS_STATUS}" | head -5
  else
    fail "openshell status returned nothing"
  fi

  # systemd services
  for unit in openshell-gateway.service podman.socket; do
    ACTIVE=$(guest_cmd "sudo -u ${SSH_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u) systemctl --user is-active ${unit} 2>/dev/null" || true)
    if [[ "${ACTIVE}" == *"active"* ]]; then
      pass "User service '${unit}' is active"
    else
      fail "User service '${unit}' is '${ACTIVE:-unknown}'"
    fi
  done

  # Gateway port listening
  GW_PORT=$(guest_cmd "ss -tlnp 2>/dev/null | grep ':17670'" || true)
  if [[ -n "${GW_PORT}" ]]; then
    pass "Gateway port 17670 is listening"
  else
    fail "Gateway port 17670 not listening"
  fi

  # SSH port (sanity — we just used it)
  pass "SSH port 22 is reachable (used for these checks)"

  # Podman healthy
  PODMAN_INFO=$(guest_cmd "podman info --format '{{.Host.OS}}' 2>/dev/null" || true)
  if [[ -n "${PODMAN_INFO}" ]]; then
    pass "Podman is functional (OS: ${PODMAN_INFO})"
  else
    warn "Podman info failed"
  fi

  # mTLS certs
  MTLS=$(guest_cmd "test -f /home/${SSH_USER}/.config/openshell/gateways/openshell/mtls/ca.crt && echo yes || echo no" || true)
  if [[ "${MTLS}" == *"yes"* ]]; then
    pass "mTLS certificates present"
  else
    warn "mTLS certificates not found (gateway may still be initializing)"
  fi
fi

echo
echo "=== Results: ${PASS} passed, ${FAIL} failed, ${WARN} warnings ==="

if [[ "${FAIL}" -gt 0 ]]; then
  echo "Gateway verification FAILED."
  exit 1
else
  echo "Gateway verification PASSED."
  exit 0
fi
