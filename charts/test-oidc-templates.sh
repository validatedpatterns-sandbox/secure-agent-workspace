#!/usr/bin/env bash
# Offline validation: verify all OIDC-related chart templates render correctly.
# Run from the repo root or helm/ directory. Requires: helm.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELM_DIR="${SCRIPT_DIR}"
PASS=0
FAIL=0
ERRORS=""

run_test() {
  local name="$1"; shift
  echo -n "  ${name}... "
  local output
  if output=$("$@" 2>&1); then
    echo "OK"
    PASS=$((PASS + 1))
  else
    echo "FAILED"
    ERRORS="${ERRORS}\n--- ${name} ---\n${output}\n"
    FAIL=$((FAIL + 1))
  fi
}

assert_contains() {
  local output="$1" pattern="$2" desc="$3"
  echo -n "  ${desc}... "
  if echo "${output}" | grep -qE "${pattern}"; then
    echo "OK"
    PASS=$((PASS + 1))
  else
    echo "FAILED (pattern '${pattern}' not found)"
    FAIL=$((FAIL + 1))
  fi
}

assert_not_contains() {
  local output="$1" pattern="$2" desc="$3"
  echo -n "  ${desc}... "
  if echo "${output}" | grep -qE "${pattern}"; then
    echo "FAILED (pattern '${pattern}' found but should not be)"
    FAIL=$((FAIL + 1))
  else
    echo "OK"
    PASS=$((PASS + 1))
  fi
}

SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@test"

# ============================================================
echo "=== Keycloak Chart ==="
# ============================================================

run_test "renders with defaults" \
  helm template openshell-keycloak "${HELM_DIR}/openshell-keycloak" --namespace openshell-agents

KC_OUTPUT="$(helm template openshell-keycloak "${HELM_DIR}/openshell-keycloak" --namespace openshell-agents 2>&1)"
assert_contains "${KC_OUTPUT}" "openshell-realm.json" "realm configmap present"
assert_contains "${KC_OUTPUT}" "openshell-cli" "CLI client configured"
assert_contains "${KC_OUTPUT}" "openshell-user" "user role defined"
assert_contains "${KC_OUTPUT}" "openshell-admin" "admin role defined"
assert_contains "${KC_OUTPUT}" "developer@openshell.local" "test user 'developer' present"
assert_contains "${KC_OUTPUT}" "admin@openshell.local" "test user 'admin' present"
assert_contains "${KC_OUTPUT}" "Route" "Route created"
assert_contains "${KC_OUTPUT}" "pkce.code.challenge.method" "PKCE configured"
assert_contains "${KC_OUTPUT}" "device.authorization.grant.enabled" "device code flow enabled"
assert_contains "${KC_OUTPUT}" "registrationAllowed.*true" "user registration enabled"
assert_contains "${KC_OUTPUT}" "helm.sh/hook: test" "test hook present"

run_test "renders with external IdP" \
  helm template openshell-keycloak "${HELM_DIR}/openshell-keycloak" --namespace openshell-agents \
    --set keycloak.externalIdp.enabled=true \
    --set keycloak.externalIdp.issuerUrl=https://sso.example.com \
    --set keycloak.externalIdp.clientId=ext-client \
    --set keycloak.externalIdp.clientSecret=ext-secret

KC_EXT="$(helm template openshell-keycloak "${HELM_DIR}/openshell-keycloak" --namespace openshell-agents \
  --set keycloak.externalIdp.enabled=true \
  --set keycloak.externalIdp.issuerUrl=https://sso.example.com \
  --set keycloak.externalIdp.clientId=ext-client \
  --set keycloak.externalIdp.clientSecret=ext-secret 2>&1)"
assert_contains "${KC_EXT}" "identityProviders" "external IdP configured"
assert_contains "${KC_EXT}" "sso.example.com" "external IdP issuer URL present"

run_test "renders with route disabled" \
  helm template openshell-keycloak "${HELM_DIR}/openshell-keycloak" --namespace openshell-agents \
    --set keycloak.route.enabled=false

KC_NOROUTE="$(helm template openshell-keycloak "${HELM_DIR}/openshell-keycloak" --namespace openshell-agents \
  --set keycloak.route.enabled=false 2>&1)"
assert_not_contains "${KC_NOROUTE}" "kind: Route" "Route not created when disabled"

# ============================================================
echo ""
echo "=== Gateway Chart (no OIDC) ==="
# ============================================================

GW_DEFAULT="$(helm template openshell-gateway "${HELM_DIR}/openshell-gateway" \
  --set sshPublicKey="${SSH_KEY}" 2>&1)"
run_test "renders without OIDC" \
  helm template openshell-gateway "${HELM_DIR}/openshell-gateway" --set sshPublicKey="${SSH_KEY}"

assert_contains "${GW_DEFAULT}" 'auth_mode.*mtls' "auth_mode is mtls"
assert_not_contains "${GW_DEFAULT}" "gateway.toml" "no gateway.toml written"
assert_not_contains "${GW_DEFAULT}" "OPENSHELL_CONFIG_FILE" "no config file env var"
assert_contains "${GW_DEFAULT}" "cp -f.*ca.crt.*MTLS_DIR" "mTLS certs copied"
assert_not_contains "${GW_DEFAULT}" 'Values\.namespace' "no .Values.namespace references"

# ============================================================
echo ""
echo "=== Gateway Chart (with OIDC) ==="
# ============================================================

GW_OIDC="$(helm template openshell-gateway "${HELM_DIR}/openshell-gateway" \
  --set sshPublicKey="${SSH_KEY}" \
  --set oidc.enabled=true \
  --set oidc.issuerUrl=https://keycloak.apps.cluster/realms/openshell 2>&1)"
run_test "renders with OIDC" \
  helm template openshell-gateway "${HELM_DIR}/openshell-gateway" \
    --set sshPublicKey="${SSH_KEY}" \
    --set oidc.enabled=true \
    --set oidc.issuerUrl=https://keycloak.apps.cluster/realms/openshell

assert_contains "${GW_OIDC}" 'auth_mode.*oidc' "auth_mode is oidc"
assert_contains "${GW_OIDC}" "gateway.toml" "gateway.toml written"
assert_contains "${GW_OIDC}" "OPENSHELL_CONFIG_FILE" "config file env var set"
assert_contains "${GW_OIDC}" 'issuer.*=.*keycloak.apps.cluster/realms/openshell' "OIDC issuer in TOML"
assert_contains "${GW_OIDC}" 'audience.*=.*openshell-cli' "audience in TOML"
assert_contains "${GW_OIDC}" 'allow_unauthenticated_users.*=.*false' "unauth users disabled"
assert_contains "${GW_OIDC}" 'openshell.gateway.mtls_auth' "mTLS auth section in TOML"
assert_not_contains "${GW_OIDC}" "cp -f.*MTLS_DIR" "mTLS certs not copied"
assert_contains "${GW_OIDC}" 'oidc_issuer.*keycloak.apps.cluster/realms/openshell' "OIDC issuer in metadata.json"
assert_contains "${GW_OIDC}" 'oidc_client_id.*openshell-cli' "OIDC client_id in metadata.json"

# Test: oidc.enabled=true without issuerUrl must fail
echo ""
echo "=== Gateway Chart (OIDC without issuerUrl) ==="
echo -n "  oidc.enabled without issuerUrl fails... "
GW_FAIL_OUTPUT="$(helm template openshell-gateway "${HELM_DIR}/openshell-gateway" \
    --set sshPublicKey="${SSH_KEY}" \
    --set oidc.enabled=true 2>&1 || true)"
if echo "${GW_FAIL_OUTPUT}" | grep -q "issuerUrl is required"; then
  echo "OK"
  PASS=$((PASS + 1))
else
  echo "FAILED (expected validation error)"
  FAIL=$((FAIL + 1))
fi

# ============================================================
echo ""
echo "=== Sandbox Chart (no OIDC) ==="
# ============================================================

SB_DEFAULT="$(helm template my-sandbox "${HELM_DIR}/openshell-sandbox" \
  --set sandboxName=my-sandbox \
  --set sshPublicKey="${SSH_KEY}" \
  --set inference.provider=gemini \
  --set inference.model=flash \
  --set inference.apiKey=test-key 2>&1)"
run_test "renders without OIDC" \
  helm template my-sandbox "${HELM_DIR}/openshell-sandbox" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set inference.provider=gemini \
    --set inference.model=flash \
    --set inference.apiKey=test-key

assert_not_contains "${SB_DEFAULT}" "OIDC_TOKEN=ey" "no OIDC token value in setup-env secret"

# ============================================================
echo ""
echo "=== Sandbox Chart (with OIDC) ==="
# ============================================================

SB_OIDC="$(helm template my-sandbox "${HELM_DIR}/openshell-sandbox" \
  --set sandboxName=my-sandbox \
  --set sshPublicKey="${SSH_KEY}" \
  --set inference.provider=gemini \
  --set inference.model=flash \
  --set inference.apiKey=test-key \
  --set-string oidc.token=eyJhbGciOiJSUzI1NiJ9.test 2>&1)"
run_test "renders with OIDC token" \
  helm template my-sandbox "${HELM_DIR}/openshell-sandbox" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set inference.provider=gemini \
    --set inference.model=flash \
    --set inference.apiKey=test-key \
    --set-string oidc.token=eyJhbGciOiJSUzI1NiJ9.test

assert_contains "${SB_OIDC}" "OIDC_TOKEN=eyJhbGciOiJSUzI1NiJ9.test" "OIDC token in setup env"
assert_contains "${SB_OIDC}" "OIDC_PASSTHROUGH=true" "OIDC passthrough enabled"
assert_contains "${SB_OIDC}" 'export OIDC_TOKEN' "OIDC token exported in run-create.sh"
assert_contains "${SB_OIDC}" "/sandbox/.oidc/token.json" "OIDC token written to sandbox"
assert_contains "${SB_OIDC}" "oidc_token.json" "OIDC token written to CLI token store"
assert_contains "${SB_OIDC}" 'access_token' "OIDC token file contains access_token JSON key"
assert_contains "${SB_OIDC}" 'OIDC_ISSUER' "OIDC issuer exported"
assert_contains "${SB_OIDC}" 'OIDC_CLIENT_ID' "OIDC client_id exported"

# ============================================================
echo ""
echo "=== Summary ==="
echo "${PASS} passed, ${FAIL} failed"
if (( FAIL > 0 )); then
  echo ""
  echo "Failures:"
  echo -e "${ERRORS}"
  exit 1
fi
echo "All template tests passed."
