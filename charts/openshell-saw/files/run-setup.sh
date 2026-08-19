#!/usr/bin/env bash
# Job entrypoint: orchestrates VM setup by sourcing phase scripts in order.
# Chart values are resolved by Helm tpl() at render time.
set -euo pipefail

# --- Chart values (resolved by Helm at render time) ---
VM_NAME="{{ include "openshell-sandbox.fullname" . }}"
NS="{{ .Release.Namespace }}"
SSH_USER="{{ .Values.sshUser }}"
SSH_SECRET="{{ .Values.sshSecret }}"
RUNTIME="{{ .Values.containerRuntime }}"
ONBOARD_CLI="{{ .Values.onboardCli }}"
VIRTCTL_VERSION="{{ .Values.virtctlVersion }}"
GOLDEN_DS="{{ include "openshell-sandbox.dataSourceName" . }}"
GOLDEN_NS="{{ .Values.source.dataSourceNamespace | default .Release.Namespace }}"
GOLDEN_DISK_SIZE="{{ .Values.vm.diskSize }}"
GOLDEN_IMAGE_URL="{{ .Values.source.goldenImageURL }}"
PULL_METHOD="{{ .Values.source.pullMethod | default "node" }}"
GATEWAY_IMAGE="{{ .Values.openshell.gatewayImage }}"
SUPERVISOR_IMAGE="{{ .Values.openshell.supervisorImage }}"
OPENSHELL_PIP_VERSION="{{ .Values.openshell.version }}"
PIP_INDEX_URL="{{ .Values.openshell.pipIndexUrl }}"
GOVERNANCE_ENABLED="{{ .Values.governance.enabled }}"
GOVERNANCE_ENDPOINT="{{ .Values.governance.endpoint | default (printf "http://governance-interceptor.%s.svc.cluster.local:%v" .Release.Namespace (.Values.governance.port | default 18081)) }}"
DASHBOARD_ENABLED="{{ .Values.dashboard.enabled }}"
DASHBOARD_IMAGE="{{ .Values.dashboard.image }}"
DASHBOARD_PROXY_IMAGE="{{ .Values.dashboard.proxyImage }}"
DASHBOARD_CLIENT_ID="{{ .Values.dashboard.clientId }}"
DASHBOARD_INSECURE_SKIP_TLS="{{ .Values.dashboard.insecureSkipIssuerTlsVerify | default false }}"
OIDC_ISSUER_URL="{{ include "openshell-sandbox.oidcIssuerUrl" . }}"
OIDC_KEYCLOAK_NAME="{{ .Values.oidc.keycloakName }}"
OIDC_REALM="{{ .Values.oidc.realm }}"
KEYCLOAK_NS="{{ .Values.dashboard.keycloakNamespace | default .Release.Namespace }}"
KEYCLOAK_NAME="{{ .Values.dashboard.keycloakName | default "openshell-keycloak" }}"
OWNER="{{ .Values.accessControl.owner | default "alice" }}"
NEMOCLAW_CLI_IMAGE="{{ .Values.nemoclawCliImage }}"
VM_GPU_ENABLED="{{ .Values.vm.gpu.enabled }}"

if [[ "${RUNTIME}" == "podman" && "${ONBOARD_CLI}" == "nemoclaw" ]]; then
  echo "ERROR: NemoClaw onboarding requires Docker. Set containerRuntime=docker or use onboardCli=openclaw." >&2
  exit 1
fi

SCRIPTS_DIR="/scripts"
SECRETS_DIR="/secrets"
WORK_DIR="/tmp/setup-work"
mkdir -p "${WORK_DIR}"

# --- Phase 1: Install dependencies ---
source "${SCRIPTS_DIR}/install-deps.sh"

# --- Extract SSH identity from Secret ---
echo "Extracting SSH identity..."
SSH_KEY="${WORK_DIR}/id_ssh"
cp /ssh-key/key "${SSH_KEY}"
chmod 600 "${SSH_KEY}"

# --- Define guest access functions ---
guest_ssh() {
  virtctl -n "${NS}" ssh "${SSH_USER}@vm/${VM_NAME}" \
    --identity-file="${SSH_KEY}" \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
    --command="$1"
}

guest_scp() {
  virtctl -n "${NS}" scp "$1" \
    "${SSH_USER}@vm/${VM_NAME}:$2" \
    --identity-file="${SSH_KEY}" \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null
}

# --- Phase 2: Bootstrap golden image ---
source "${SCRIPTS_DIR}/bootstrap-golden-image.sh"

# --- Phase 3: Wait for VM ---
source "${SCRIPTS_DIR}/wait-for-vm.sh"

# --- Phase 4: Upgrade OpenShell binaries ---
source "${SCRIPTS_DIR}/upgrade-openshell.sh"

# --- Phase 5: Governance check + SSH key fallback ---
source "${SCRIPTS_DIR}/check-governance.sh"

# --- Phase 6: BOM profile setup ---
source "${SCRIPTS_DIR}/setup-bom-profiles.sh"

# --- Phase 7: Dashboard setup ---
if [[ "${DASHBOARD_ENABLED}" == "true" ]]; then
  source "${SCRIPTS_DIR}/setup-keycloak-redirect.sh"
fi

echo "Setup complete on vm/${VM_NAME}"
