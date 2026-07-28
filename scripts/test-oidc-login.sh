#!/usr/bin/env bash
# Unit tests for oidc-login.sh helper functions.
# These tests run offline -- no OIDC provider or cluster needed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOGIN_SCRIPT="${SCRIPT_DIR}/oidc-login.sh"
PASS=0
FAIL=0

ok()   { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# Create a temp dir for token storage
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT

# A valid-looking JWT for testing (header.payload.signature)
# Payload: {"sub":"test-user","preferred_username":"developer","email":"dev@test.com","iss":"http://127.0.0.1:19999/realms/openshell","realm_access":{"roles":["openshell-user"]},"exp":9999999999}
JWT_PAYLOAD='{"sub":"test-user","preferred_username":"developer","email":"dev@test.com","iss":"http://127.0.0.1:19999/realms/openshell","realm_access":{"roles":["openshell-user"]},"exp":9999999999}'
JWT_PAYLOAD_B64="$(echo -n "${JWT_PAYLOAD}" | base64 | tr '+/' '-_' | tr -d '=')"
TEST_JWT="eyJhbGciOiJSUzI1NiJ9.${JWT_PAYLOAD_B64}.fake-signature"

# An expired JWT
EXPIRED_PAYLOAD='{"sub":"test-user","preferred_username":"developer","exp":1000000000}'
EXPIRED_PAYLOAD_B64="$(echo -n "${EXPIRED_PAYLOAD}" | base64 | tr '+/' '-_' | tr -d '=')"
EXPIRED_JWT="eyJhbGciOiJSUzI1NiJ9.${EXPIRED_PAYLOAD_B64}.fake-signature"

# ============================================================
echo "=== Test: Token storage and validation ==="
# ============================================================

echo "--- Test: save and read valid token ---"
export OIDC_TOKEN_DIR="${TEST_DIR}/tokens"
export OIDC_ISSUER="http://127.0.0.1:19999/realms/openshell"
export OIDC_CLIENT_ID="openshell-cli"

# Write a token file directly (simulating save_token output)
mkdir -p "${OIDC_TOKEN_DIR}"
NOW="$(date +%s)"
cat > "${OIDC_TOKEN_DIR}/token.json" <<EOF
{
  "access_token": "${TEST_JWT}",
  "refresh_token": "test-refresh-token",
  "expires_in": 900,
  "token_type": "Bearer",
  "issuer_url": "${OIDC_ISSUER}",
  "saved_at": ${NOW}
}
EOF
chmod 600 "${OIDC_TOKEN_DIR}/token.json"

# Test: token command should output the access token
TOKEN_OUTPUT="$(OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR}" bash "${LOGIN_SCRIPT}" token 2>/dev/null)"
if [[ "${TOKEN_OUTPUT}" == "${TEST_JWT}" ]]; then
  ok "token command returns access_token"
else
  fail "token command returned unexpected output: ${TOKEN_OUTPUT}"
fi

# Test: token file permissions
PERMS="$(stat -f '%A' "${OIDC_TOKEN_DIR}/token.json" 2>/dev/null || stat -c '%a' "${OIDC_TOKEN_DIR}/token.json" 2>/dev/null)"
if [[ "${PERMS}" == "600" ]]; then
  ok "token file has mode 600"
else
  fail "token file has mode ${PERMS}, expected 600"
fi

# ============================================================
echo ""
echo "=== Test: whoami with valid token ==="
# ============================================================

WHOAMI_OUTPUT="$(OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR}" bash "${LOGIN_SCRIPT}" whoami 2>&1)"
if echo "${WHOAMI_OUTPUT}" | grep -q "developer"; then
  ok "whoami shows preferred_username"
else
  fail "whoami missing username: ${WHOAMI_OUTPUT}"
fi

if echo "${WHOAMI_OUTPUT}" | grep -q "dev@test.com"; then
  ok "whoami shows email"
else
  fail "whoami missing email"
fi

if echo "${WHOAMI_OUTPUT}" | grep -q "openshell-user"; then
  ok "whoami shows roles"
else
  fail "whoami missing roles"
fi

if echo "${WHOAMI_OUTPUT}" | grep -q "valid"; then
  ok "whoami shows valid status"
else
  fail "whoami missing valid status"
fi

# ============================================================
echo ""
echo "=== Test: Expired token detection ==="
# ============================================================

cat > "${OIDC_TOKEN_DIR}/token.json" <<EOF
{
  "access_token": "${EXPIRED_JWT}",
  "refresh_token": "test-refresh-token",
  "expires_in": 900,
  "token_type": "Bearer",
  "issuer_url": "${OIDC_ISSUER}",
  "saved_at": 1000000000
}
EOF

WHOAMI_EXPIRED="$(OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR}" bash "${LOGIN_SCRIPT}" whoami 2>&1)"
if echo "${WHOAMI_EXPIRED}" | grep -qi "expired"; then
  ok "whoami detects expired token"
else
  fail "whoami did not detect expired token: ${WHOAMI_EXPIRED}"
fi

# ============================================================
echo ""
echo "=== Test: Logout clears token ==="
# ============================================================

# Write a fresh token for logout test
cat > "${OIDC_TOKEN_DIR}/token.json" <<EOF
{
  "access_token": "${TEST_JWT}",
  "refresh_token": "test-refresh-token",
  "expires_in": 900,
  "issuer_url": "http://127.0.0.1:19999/realms/openshell",
  "saved_at": ${NOW}
}
EOF

OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR}" OIDC_CLIENT_ID="${OIDC_CLIENT_ID}" bash "${LOGIN_SCRIPT}" logout 2>/dev/null
if [[ ! -f "${OIDC_TOKEN_DIR}/token.json" ]]; then
  ok "logout removes token file"
else
  fail "logout did not remove token file"
fi

# ============================================================
echo ""
echo "=== Test: Missing token errors ==="
# ============================================================

rm -f "${OIDC_TOKEN_DIR}/token.json"
if OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR}" bash "${LOGIN_SCRIPT}" token 2>/dev/null; then
  fail "token command should fail without token file"
else
  ok "token command fails without token file"
fi

if OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR}" bash "${LOGIN_SCRIPT}" whoami 2>/dev/null; then
  fail "whoami should fail without token file"
else
  ok "whoami fails without token file"
fi

# ============================================================
echo ""
echo "=== Test: Auto-detect issuer requires oc ==="
# ============================================================

# When OIDC_ISSUER is empty and oc is not available, login should fail with a clear message
LOGIN_ERR="$(OIDC_ISSUER="" OIDC_TOKEN_DIR="${TEST_DIR}/empty" PATH="/usr/bin:/bin" bash "${LOGIN_SCRIPT}" login 2>&1 || true)"
if echo "${LOGIN_ERR}" | grep -qi "OIDC_ISSUER\|not found\|not set"; then
  ok "login without OIDC_ISSUER gives helpful error"
else
  fail "login without OIDC_ISSUER did not give helpful error: ${LOGIN_ERR}"
fi

# ============================================================
echo ""
echo "=== Test: Unknown action errors ==="
# ============================================================

BOGUS_ERR="$(bash "${LOGIN_SCRIPT}" bogus-action 2>&1 || true)"
if echo "${BOGUS_ERR}" | grep -q "Unknown action"; then
  ok "unknown action gives error"
else
  fail "unknown action did not give error: ${BOGUS_ERR}"
fi

# ============================================================
echo ""
echo "=== Summary ==="
echo "${PASS} passed, ${FAIL} failed"
if (( FAIL > 0 )); then
  exit 1
fi
echo "All login script tests passed."
