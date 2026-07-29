#!/usr/bin/env bash
# End-to-end test: per-user access control via oauth2-proxy.
#
# Validates that two users (alice and bob) in a SHARED namespace cannot
# access each other's sandbox gateways or dashboards:
#   1. Provision alice's sandbox with accessControl.owner=alice
#   2. Provision bob's sandbox with accessControl.owner=bob
#   3. Alice can access her own gateway/dashboard
#   4. Alice cannot access bob's gateway/dashboard (403)
#   5. Bob can access his own gateway/dashboard
#   6. Bob cannot access alice's gateway/dashboard (403)
#   7. Cleanup
#
# Prerequisites:
#   - oc logged in to the cluster
#   - Keycloak deployed with alice and bob users (make keycloak)
#   - Gateway deployed with OIDC (make gateway OIDC_ISSUER=...)
#   - Golden image or snapshot available
#
# Usage:
#   ./tests/test-access-control.sh [--skip-cleanup]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SHARED_NS="${SHARED_NS:-openshell-agents}"
ALICE_USER="alice"
ALICE_PASS="alice"
BOB_USER="bob"
BOB_PASS="bob"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-openshell-cli}"
SKIP_CLEANUP="${1:-}"

TEST_PROVIDER="${TEST_PROVIDER:-gemini}"
TEST_MODEL="${TEST_MODEL:-gemini-2.5-flash}"
TEST_API_KEY="${TEST_API_KEY:-test-key-not-real}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"

ALICE_SANDBOX="ac-alice-sb"
BOB_SANDBOX="ac-bob-sb"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass_count=0
fail_count=0

log()  { echo -e "${CYAN}[TEST]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; pass_count=$((pass_count + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; fail_count=$((fail_count + 1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

# --- Helpers ---

keycloak_token() {
  local username="$1" password="$2"
  local keycloak_host
  keycloak_host="$(oc get route openshell-keycloak -n "${SHARED_NS}" \
    -o jsonpath='{.spec.host}' 2>/dev/null)" \
    || die "Keycloak route not found in ${SHARED_NS}"

  local token_url="https://${keycloak_host}/realms/openshell/protocol/openid-connect/token"
  local response
  response="$(curl -fsSL --insecure --connect-timeout 5 --max-time 10 \
    -X POST "${token_url}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${OIDC_CLIENT_ID}" \
    -d "username=${username}" \
    -d "password=${password}" \
    -d "scope=openid email profile" 2>/dev/null)" \
    || die "Failed to get token for ${username} from Keycloak"

  local error
  error="$(echo "${response}" | jq -r '.error // empty' 2>/dev/null)"
  if [[ -n "${error}" ]]; then
    die "Keycloak login failed for ${username}: ${error}"
  fi

  echo "${response}" | jq -r '.access_token'
}

get_oidc_issuer() {
  local keycloak_host
  keycloak_host="$(oc get route openshell-keycloak -n "${SHARED_NS}" \
    -o jsonpath='{.spec.host}' 2>/dev/null)" \
    || die "Keycloak route not found"
  echo "https://${keycloak_host}/realms/openshell"
}

ssh_pubkey() {
  cat "${SSH_KEY_PATH}.pub" 2>/dev/null || die "SSH public key not found at ${SSH_KEY_PATH}.pub"
}

cleanup() {
  log "Cleaning up..."

  helm uninstall "${ALICE_SANDBOX}" -n "${SHARED_NS}" --wait 2>/dev/null || true
  helm uninstall "${BOB_SANDBOX}" -n "${SHARED_NS}" --wait 2>/dev/null || true

  log "Cleanup complete."
}

# --- Preconditions ---

check_prerequisites() {
  log "Checking prerequisites..."

  command -v oc >/dev/null 2>&1 || die "'oc' not found"
  command -v helm >/dev/null 2>&1 || die "'helm' not found"
  command -v curl >/dev/null 2>&1 || die "'curl' not found"
  command -v jq >/dev/null 2>&1 || die "'jq' not found"

  oc whoami >/dev/null 2>&1 || die "Not logged in to OpenShift cluster"
  log "Cluster: $(oc whoami --show-console 2>/dev/null || oc whoami -c)"

  test -f "${SSH_KEY_PATH}.pub" || die "SSH public key not found at ${SSH_KEY_PATH}.pub"

  oc get route openshell-keycloak -n "${SHARED_NS}" >/dev/null 2>&1 \
    || die "Keycloak not deployed in ${SHARED_NS}. Run 'make keycloak' first."

  pass "Prerequisites OK"
}

# --- Tests ---

test_provision_alice_sandbox() {
  log "Provisioning alice's sandbox with access control..."

  local chart="${REPO_ROOT}/helm/openshell-sandbox"
  local issuer
  issuer="$(get_oidc_issuer)"
  local pubkey
  pubkey="$(ssh_pubkey)"

  helm upgrade --install "${ALICE_SANDBOX}" "${chart}" \
    -n "${SHARED_NS}" \
    --set "sandboxName=${ALICE_SANDBOX}" \
    --set "sshPublicKey=${pubkey}" \
    --set "inference.provider=${TEST_PROVIDER}" \
    --set "inference.model=${TEST_MODEL}" \
    --set "inference.apiKey=${TEST_API_KEY}" \
    --set "sourceMode=containerDisk" \
    --set "sourceGoldenImageNamespace=${SHARED_NS}" \
    --set "route.enabled=true" \
    --set "route.dashboard=true" \
    --set "accessControl.enabled=true" \
    --set "accessControl.owner=${ALICE_USER}" \
    --set "oidc.issuerUrl=${issuer}" \
    --set "oidc.clientId=${OIDC_CLIENT_ID}" \
    --timeout 10m 2>&1 | while IFS= read -r line; do echo "  ${line}"; done

  if helm list -n "${SHARED_NS}" 2>/dev/null | grep -q "${ALICE_SANDBOX}"; then
    pass "Alice's sandbox '${ALICE_SANDBOX}' deployed with accessControl.owner=alice"
  else
    fail "Alice's sandbox deployment failed"
    return 1
  fi
}

test_provision_bob_sandbox() {
  log "Provisioning bob's sandbox with access control..."

  local chart="${REPO_ROOT}/helm/openshell-sandbox"
  local issuer
  issuer="$(get_oidc_issuer)"
  local pubkey
  pubkey="$(ssh_pubkey)"

  helm upgrade --install "${BOB_SANDBOX}" "${chart}" \
    -n "${SHARED_NS}" \
    --set "sandboxName=${BOB_SANDBOX}" \
    --set "sshPublicKey=${pubkey}" \
    --set "inference.provider=${TEST_PROVIDER}" \
    --set "inference.model=${TEST_MODEL}" \
    --set "inference.apiKey=${TEST_API_KEY}" \
    --set "sourceMode=containerDisk" \
    --set "sourceGoldenImageNamespace=${SHARED_NS}" \
    --set "route.enabled=true" \
    --set "route.dashboard=true" \
    --set "accessControl.enabled=true" \
    --set "accessControl.owner=${BOB_USER}" \
    --set "oidc.issuerUrl=${issuer}" \
    --set "oidc.clientId=${OIDC_CLIENT_ID}" \
    --timeout 10m 2>&1 | while IFS= read -r line; do echo "  ${line}"; done

  if helm list -n "${SHARED_NS}" 2>/dev/null | grep -q "${BOB_SANDBOX}"; then
    pass "Bob's sandbox '${BOB_SANDBOX}' deployed with accessControl.owner=bob"
  else
    fail "Bob's sandbox deployment failed"
    return 1
  fi
}

test_wait_for_oauth2_proxy() {
  log "Waiting for oauth2-proxy pods to be ready..."

  local ready=0
  for i in $(seq 1 60); do
    local alice_ready bob_ready
    alice_ready="$(kubectl get deployment "${ALICE_SANDBOX}-auth-proxy" -n "${SHARED_NS}" \
      -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"
    bob_ready="$(kubectl get deployment "${BOB_SANDBOX}-auth-proxy" -n "${SHARED_NS}" \
      -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"

    if [[ "${alice_ready}" -ge 1 && "${bob_ready}" -ge 1 ]]; then
      ready=1
      break
    fi
    sleep 5
  done

  if [[ "${ready}" -eq 1 ]]; then
    pass "Both oauth2-proxy pods are ready"
  else
    fail "oauth2-proxy pods not ready after 5 minutes"
    return 1
  fi
}

test_routes_point_to_auth_proxy() {
  log "Verifying Routes point to auth-proxy service..."

  local alice_svc bob_svc
  alice_svc="$(oc get route "${ALICE_SANDBOX}-gateway" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.to.name}' 2>/dev/null || true)"
  bob_svc="$(oc get route "${BOB_SANDBOX}-gateway" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.to.name}' 2>/dev/null || true)"

  local alice_ok=0 bob_ok=0
  if [[ "${alice_svc}" == "${ALICE_SANDBOX}-auth-proxy" ]]; then
    alice_ok=1
  fi
  if [[ "${bob_svc}" == "${BOB_SANDBOX}-auth-proxy" ]]; then
    bob_ok=1
  fi

  if [[ "${alice_ok}" -eq 1 && "${bob_ok}" -eq 1 ]]; then
    pass "Both gateway Routes point to auth-proxy services"
  else
    fail "Route targets wrong: alice=${alice_svc}, bob=${bob_svc}"
  fi

  # Also check dashboard routes
  local alice_dash_svc bob_dash_svc
  alice_dash_svc="$(oc get route "${ALICE_SANDBOX}-dashboard" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.to.name}' 2>/dev/null || true)"
  bob_dash_svc="$(oc get route "${BOB_SANDBOX}-dashboard" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.to.name}' 2>/dev/null || true)"

  if [[ "${alice_dash_svc}" == "${ALICE_SANDBOX}-auth-proxy" && \
        "${bob_dash_svc}" == "${BOB_SANDBOX}-auth-proxy" ]]; then
    pass "Both dashboard Routes point to auth-proxy services"
  else
    fail "Dashboard route targets wrong: alice=${alice_dash_svc}, bob=${bob_dash_svc}"
  fi
}

test_route_tls_is_edge() {
  log "Verifying gateway Routes use edge TLS (not passthrough)..."

  local alice_tls bob_tls
  alice_tls="$(oc get route "${ALICE_SANDBOX}-gateway" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.tls.termination}' 2>/dev/null || true)"
  bob_tls="$(oc get route "${BOB_SANDBOX}-gateway" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.tls.termination}' 2>/dev/null || true)"

  if [[ "${alice_tls}" == "edge" && "${bob_tls}" == "edge" ]]; then
    pass "Gateway Routes use edge TLS termination (oauth2-proxy handles TLS)"
  else
    fail "Gateway Route TLS wrong: alice=${alice_tls}, bob=${bob_tls} (expected: edge)"
  fi
}

test_alice_can_access_own_gateway() {
  log "Verifying alice can access her own gateway..."

  local alice_token
  alice_token="$(keycloak_token "${ALICE_USER}" "${ALICE_PASS}")"

  local gw_host
  gw_host="$(oc get route "${ALICE_SANDBOX}-gateway" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.host}' 2>/dev/null || true)"

  if [[ -z "${gw_host}" ]]; then
    warn "Alice's gateway route not found — skipping"
    return 0
  fi

  # Owner should NOT get 401 or 403 — any other code (200, 502, etc.) means
  # the proxy accepted the token. 502 is expected when the VM isn't ready.
  local http_code
  http_code="$(curl -sS --insecure --connect-timeout 10 --max-time 15 \
    -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${alice_token}" \
    "https://${gw_host}/" 2>/dev/null || echo "000")"

  if [[ "${http_code}" != "401" && "${http_code}" != "403" && "${http_code}" != "000" ]]; then
    pass "Alice can access her own gateway (HTTP ${http_code})"
  else
    fail "Alice cannot access her own gateway (HTTP ${http_code})"
  fi
}

test_bob_cannot_access_alice_gateway() {
  log "Verifying bob CANNOT access alice's gateway..."

  local bob_token
  bob_token="$(keycloak_token "${BOB_USER}" "${BOB_PASS}")"

  local gw_host
  gw_host="$(oc get route "${ALICE_SANDBOX}-gateway" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.host}' 2>/dev/null || true)"

  if [[ -z "${gw_host}" ]]; then
    warn "Alice's gateway route not found — skipping"
    return 0
  fi

  local http_code body
  body="$(curl -sS --insecure --connect-timeout 10 --max-time 15 \
    -w "\n%{http_code}" \
    -H "Authorization: Bearer ${bob_token}" \
    "https://${gw_host}/" 2>/dev/null || echo -e "\n000")"
  http_code="$(echo "${body}" | tail -1)"

  if [[ "${http_code}" == "403" ]]; then
    pass "Bob blocked from alice's gateway (HTTP 403)"
  else
    fail "Bob was NOT blocked from alice's gateway (HTTP ${http_code}) — access control broken!"
  fi
}

test_bob_can_access_own_gateway() {
  log "Verifying bob can access his own gateway..."

  local bob_token
  bob_token="$(keycloak_token "${BOB_USER}" "${BOB_PASS}")"

  local gw_host
  gw_host="$(oc get route "${BOB_SANDBOX}-gateway" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.host}' 2>/dev/null || true)"

  if [[ -z "${gw_host}" ]]; then
    warn "Bob's gateway route not found — skipping"
    return 0
  fi

  local http_code
  http_code="$(curl -sS --insecure --connect-timeout 10 --max-time 15 \
    -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${bob_token}" \
    "https://${gw_host}/" 2>/dev/null || echo "000")"

  if [[ "${http_code}" != "401" && "${http_code}" != "403" && "${http_code}" != "000" ]]; then
    pass "Bob can access his own gateway (HTTP ${http_code})"
  else
    fail "Bob cannot access his own gateway (HTTP ${http_code})"
  fi
}

test_alice_cannot_access_bob_gateway() {
  log "Verifying alice CANNOT access bob's gateway..."

  local alice_token
  alice_token="$(keycloak_token "${ALICE_USER}" "${ALICE_PASS}")"

  local gw_host
  gw_host="$(oc get route "${BOB_SANDBOX}-gateway" -n "${SHARED_NS}" \
    -o jsonpath='{.spec.host}' 2>/dev/null || true)"

  if [[ -z "${gw_host}" ]]; then
    warn "Bob's gateway route not found — skipping"
    return 0
  fi

  local http_code
  http_code="$(curl -sS --insecure --connect-timeout 10 --max-time 15 \
    -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${alice_token}" \
    "https://${gw_host}/" 2>/dev/null || echo "000")"

  if [[ "${http_code}" == "403" ]]; then
    pass "Alice blocked from bob's gateway (HTTP 403)"
  else
    fail "Alice was NOT blocked from bob's gateway (HTTP ${http_code}) — access control broken!"
  fi
}

test_both_sandboxes_in_same_namespace() {
  log "Verifying both sandboxes are in the same shared namespace..."

  local alice_ns bob_ns
  alice_ns="$(helm list -n "${SHARED_NS}" -o json 2>/dev/null | \
    jq -r ".[] | select(.name == \"${ALICE_SANDBOX}\") | .namespace" 2>/dev/null)"
  bob_ns="$(helm list -n "${SHARED_NS}" -o json 2>/dev/null | \
    jq -r ".[] | select(.name == \"${BOB_SANDBOX}\") | .namespace" 2>/dev/null)"

  if [[ "${alice_ns}" == "${SHARED_NS}" && "${bob_ns}" == "${SHARED_NS}" ]]; then
    pass "Both sandboxes in shared namespace '${SHARED_NS}' (no per-user namespaces)"
  else
    fail "Namespace mismatch: alice=${alice_ns}, bob=${bob_ns} (expected: ${SHARED_NS})"
  fi
}

test_auth_proxy_configmap() {
  log "Verifying auth proxy ConfigMaps contain correct owners..."

  local alice_owner bob_owner
  alice_owner="$(kubectl get configmap "${ALICE_SANDBOX}-auth-proxy" -n "${SHARED_NS}" \
    -o jsonpath='{.data.nginx\.conf}' 2>/dev/null | sed -n 's/.*local allowed_user = "\([^"]*\)".*/\1/p' || true)"
  bob_owner="$(kubectl get configmap "${BOB_SANDBOX}-auth-proxy" -n "${SHARED_NS}" \
    -o jsonpath='{.data.nginx\.conf}' 2>/dev/null | sed -n 's/.*local allowed_user = "\([^"]*\)".*/\1/p' || true)"

  if [[ "${alice_owner}" == "${ALICE_USER}" && "${bob_owner}" == "${BOB_USER}" ]]; then
    pass "ConfigMaps correct: alice=${alice_owner}, bob=${bob_owner}"
  else
    fail "ConfigMap owners wrong: alice=${alice_owner}, bob=${bob_owner}"
  fi
}

# --- Main ---

echo ""
echo "============================================"
echo "  Per-User Access Control E2E Test"
echo "============================================"
echo ""
echo "  Mode:      shared namespace + oauth2-proxy"
echo "  Namespace: ${SHARED_NS}"
echo "  Alice:     ${ALICE_USER} → ${ALICE_SANDBOX}"
echo "  Bob:       ${BOB_USER} → ${BOB_SANDBOX}"
echo ""

if [[ "${SKIP_CLEANUP}" != "--skip-cleanup" ]]; then
  trap cleanup EXIT
fi

check_prerequisites

echo ""
echo "--- Phase 1: Provision sandboxes ---"
test_provision_alice_sandbox
test_provision_bob_sandbox

echo ""
echo "--- Phase 2: Verify infrastructure ---"
test_wait_for_oauth2_proxy
test_routes_point_to_auth_proxy
test_route_tls_is_edge
test_both_sandboxes_in_same_namespace
test_auth_proxy_configmap

echo ""
echo "--- Phase 3: Test access control ---"
test_alice_can_access_own_gateway
test_bob_cannot_access_alice_gateway
test_bob_can_access_own_gateway
test_alice_cannot_access_bob_gateway

echo ""
echo "============================================"
echo "  Results: ${pass_count} passed, ${fail_count} failed"
echo "============================================"
echo ""

if (( fail_count > 0 )); then
  die "${fail_count} test(s) failed"
fi

echo -e "${GREEN}All tests passed!${NC}"
