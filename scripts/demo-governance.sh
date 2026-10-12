#!/usr/bin/env bash
# Demo: Governance Interceptor for Secure Agent Workspace
#
# Shows how the governance interceptor enforces provider policies —
# only approved provider profiles can be created on the sandbox.
#
# Usage: ./scripts/demo-governance.sh [OPENSHELL_SAW_NAME]

set -euo pipefail

SAW_NAME="${1:-openshell-saw}"
NS="${NS:-openshell-agents}"
SSH_KEY="${SSH_KEY:-$HOME/.generated-ssh-keys/sandbox-ssh}"
PAUSE="${PAUSE:-true}"

GREEN='\033[1;32m'
RED='\033[1;31m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

press_enter() {
  if [[ "${PAUSE}" == "true" ]]; then
    echo ""
    read -rp "  Press Enter to continue..."
    echo ""
  fi
}

banner() {
  echo ""
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${CYAN}  $1${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo ""
}

step() {
  echo -e "${BOLD}▸ $1${RESET}"
}

gw() {
  openshell --gateway "${SAW_NAME}" "$@" 2>&1
}

run_on_vm() {
  virtctl ssh -i "${SSH_KEY}" -n "${NS}" "cloud-user@vmi/${SAW_NAME}" \
    --local-ssh-opts="-o StrictHostKeyChecking=no" \
    --local-ssh-opts="-o UserKnownHostsFile=/dev/null" \
    --local-ssh-opts="-o LogLevel=ERROR" \
    --command "$1" 2>&1 \
    | grep -v 'You are using a client virtctl'
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILES_DIR="${REPO_DIR}/charts/governance-policy/profiles"

# Clean up any stale state from previous runs
gw sandbox provider detach "${SAW_NAME}" github > /dev/null 2>&1 || true
for p in demo-gemini demo-github demo-gemini-ok demo-github-restored demo-github-blocked github; do
  gw provider delete "${p}" > /dev/null 2>&1 || true
done

banner "Governance Interceptor Demo — Secure Agent Workspace"

echo -e "This demo shows how a ${BOLD}governance interceptor${RESET} enforces"
echo -e "admin-controlled policies on AI agent sandboxes."
echo ""
echo -e "The interceptor runs as a ${BOLD}Kubernetes pod${RESET} and the gateway"
echo -e "inside the VM connects to it over the pod network."
echo ""

press_enter

# --- 1. Show interceptor pod ---
banner "1. Governance Interceptor Pod"

step "Interceptor deployed by ArgoCD as a Kubernetes pod:"
echo ""
oc get pods -n "${NS}" -l app.kubernetes.io/name=governance-interceptor \
  -o custom-columns='NAME:.metadata.name,STATUS:.status.phase,IMAGE:.spec.containers[0].image' \
  --no-headers
echo ""

step "Interceptor startup logs:"
echo ""
oc logs deployment/governance-interceptor -n "${NS}" 2>&1 | head -4
echo ""

press_enter

# --- 2. Show profiles ---
banner "2. Governed Provider Profiles"

step "These profiles are enforced by the interceptor — only these provider"
step "types can be created on the sandbox:"
echo ""
gw provider list-profiles
echo ""

press_enter

# --- 3. Pass tests ---
banner "3. Allowed Providers (should succeed)"

step "Creating a Gemini provider (governed profile):"
echo ""
gw provider create --name demo-gemini --type gemini --credential GEMINI_API_KEY=demo-key
echo ""

step "Creating a GitHub provider (governed profile):"
echo ""
gw provider create --name demo-github --type github --credential GITHUB_TOKEN=demo-token
echo ""

press_enter

# --- 4. Fail tests ---
banner "4. Blocked Providers (should fail)"

step "Attempting to create a 'custom' provider (not in governance profiles):"
echo ""
gw provider create --name demo-blocked --type custom --credential key=value || true
echo ""

step "Attempting to create an Anthropic provider (not in governance profiles):"
echo ""
gw provider create --name demo-blocked2 --type claude-code --credential ANTHROPIC_API_KEY=demo-key || true
echo ""

press_enter

# --- 5. Show gateway interceptor logs ---
banner "5. Gateway Interceptor Audit Log"

step "The gateway logs every interceptor decision (allow/deny):"
echo ""
run_on_vm "journalctl --user -u openshell-gateway.service --no-pager" \
  | { grep 'interceptor.*evaluated' || true; } \
  | sed 's/.*gateway interceptor evaluated /  /' \
  | tail -6
echo ""

press_enter

# --- 6. Revoke a profile ---
banner "6. Revoking Access — Remove GitHub Profile"

step "An admin decides GitHub access should no longer be allowed."
step "Admin removes the github profile from git and pushes..."
echo ""

NS="${NS}" SAW_NAME="${SAW_NAME}" SSH_KEY="${SSH_KEY}" "${SCRIPT_DIR}/governance-profile.sh" remove github

echo -e "${YELLOW}  GitHub profile revoked via GitOps.${RESET}"
echo ""

step "Available profiles now (GitHub is gone):"
echo ""
gw provider list-profiles
echo ""

press_enter

step "Trying to create a GitHub provider (no longer in governance):"
echo ""
gw provider create --name demo-github-blocked --type github --credential GITHUB_TOKEN=demo-token || true
echo ""

step "Gemini still works (profile is still present):"
echo ""
gw provider create --name demo-gemini-ok --type gemini --credential GEMINI_API_KEY=demo-key || true
echo ""

press_enter

# --- 7. Restore profile ---
banner "7. Restoring GitHub Access"

step "Admin restores the github profile..."
echo ""

NS="${NS}" SAW_NAME="${SAW_NAME}" SSH_KEY="${SSH_KEY}" "${SCRIPT_DIR}/governance-profile.sh" add github

echo -e "${GREEN}  GitHub profile restored via GitOps.${RESET}"
echo ""

step "GitHub provider creation works again:"
echo ""
gw provider create --name demo-github-restored --type github --credential GITHUB_TOKEN=demo-token || true
echo ""

press_enter

# --- 8. GitHub API — Provider Not Attached ---
banner "8. GitHub API — Profile Present, Provider Not Attached"

step "The GitHub profile is in governance — it defines allowed endpoints:"
echo ""
cat "${PROFILES_DIR}/github.yaml" | sed 's/^/    /'
echo ""

press_enter

step "The ${SAW_NAME} sandbox was created with --provider brave."
step "GitHub is NOT attached — the proxy should block it."
echo ""
echo -e "  ${YELLOW}Open a separate terminal and run:${RESET}"
echo ""
echo -e "    ${BOLD}export OPENSHELL_SAW_NAME=${SAW_NAME}${RESET}"
echo -e "    ${BOLD}make saw-ssh${RESET}"
echo ""
echo -e "  Then inside the sandbox, run:"
echo ""
echo -e "    ${BOLD}curl -sv https://api.github.com${RESET}"
echo ""
echo -e "  ${RED}Expected: HTTP/1.1 403 Forbidden (proxy blocks the CONNECT)${RESET}"
echo ""

press_enter

# --- 9. GitHub API — Attach Provider ---
banner "9. GitHub API — Create Provider and Attach to Sandbox"

step "Step 1: Create a GitHub provider on the gateway:"
echo ""
gw provider create --name github --type github --credential GITHUB_TOKEN=demo-token || true
echo ""

step "Step 2: Attach the github provider to the running sandbox:"
echo ""
gw sandbox provider attach "${SAW_NAME}" github || true
echo ""

step "Providers attached to ${SAW_NAME}:"
echo ""
gw sandbox provider list "${SAW_NAME}" || true
echo ""

press_enter

step "Now try the GitHub API again from the same sandbox terminal:"
echo ""
echo -e "    ${BOLD}curl -sv https://api.github.com${RESET}"
echo ""
echo -e "  ${GREEN}Expected: HTTP/1.1 200 Connection Established (proxy allows the CONNECT)${RESET}"
echo ""

press_enter

# --- 10. GitHub API — Detach Provider ---
banner "10. GitHub API — Detach Provider and Verify Access Revoked"

step "Detach github from the sandbox:"
echo ""
gw sandbox provider detach "${SAW_NAME}" github || true
echo ""

step "Delete the github provider:"
echo ""
gw provider delete github > /dev/null 2>&1 || true
echo -e "${GREEN}  GitHub provider removed.${RESET}"
echo ""

step "Try the GitHub API one more time from the same sandbox terminal:"
echo ""
echo -e "    ${BOLD}curl -sv https://api.github.com${RESET}"
echo ""
echo -e "  ${RED}Expected: HTTP/1.1 403 Forbidden (access revoked)${RESET}"
echo ""

press_enter

# --- 11. Cleanup ---
banner "11. Cleanup"

for p in demo-gemini demo-github demo-gemini-ok demo-github-restored demo-github-blocked github; do
  gw provider delete "${p}" > /dev/null 2>&1 || true
done
echo -e "${GREEN}  Demo providers cleaned up.${RESET}"
echo ""

banner "Demo Complete"

echo -e "Summary:"
echo -e "  ${GREEN}✓${RESET} Governance interceptor deployed as a Kubernetes pod (ArgoCD)"
echo -e "  ${GREEN}✓${RESET} VM gateway connects to interceptor over pod network (HTTP/2)"
echo -e "  ${GREEN}✓${RESET} Governed providers (github, gemini, brave) — ${GREEN}allowed${RESET}"
echo -e "  ${RED}✗${RESET} Ungoverned providers (custom, claude-code) — ${RED}blocked${RESET}"
echo -e "  ${YELLOW}!${RESET} Revoked profile (github removed) — ${RED}blocked until restored${RESET}"
echo -e "  ${RED}✗${RESET} GitHub API without provider attached — ${RED}denied by proxy${RESET}"
echo -e "  ${GREEN}✓${RESET} GitHub API after attach — ${GREEN}allowed through proxy${RESET}"
echo -e "  ${RED}✗${RESET} GitHub API after detach — ${RED}denied again${RESET}"
echo -e "  ${GREEN}✓${RESET} Sandbox proxy allows governed endpoints, blocks everything else"
echo -e "  ${GREEN}✓${RESET} Policy separated from interceptor — just drop a profile YAML"
echo -e "  ${GREEN}✓${RESET} Signed policy injected into sandbox creation (patch_count=2)"
echo -e "  ${GREEN}✓${RESET} Full audit trail in gateway logs"
echo ""
