#!/usr/bin/env bash
# Open the OpenClaw web UI via virtctl port-forward.
# Fetches the dashboard auth token and prints the URL.
# Uses virtctl SSH + local port-forward — no OIDC token needed.

set -euo pipefail

NS="${NS:-openshell-agents}"
SANDBOX_NAME="${SANDBOX_NAME:?SANDBOX_NAME is required}"
SSH_KEY_PATH="${SSH_KEY_PATH:-.generated-ssh-keys/sandbox-ssh}"
GUI_PORT="${GUI_PORT:-18789}"

SSH_OPTS=(
  --identity-file="${SSH_KEY_PATH}"
  --local-ssh-opts="-oStrictHostKeyChecking=no"
  --local-ssh-opts="-oUserKnownHostsFile=/dev/null"
  --local-ssh-opts="-oConnectTimeout=15"
)

guest_ssh() {
  virtctl -n "${NS}" ssh "cloud-user@vm/${SANDBOX_NAME}" "${SSH_OPTS[@]}" --command="$1" 2>/dev/null
}

# Kill any existing port-forward on this port
pids=$(lsof -ti :"${GUI_PORT}" 2>/dev/null || true)
if [[ -n "${pids}" ]]; then
  kill "${pids}" 2>/dev/null || true
  sleep 1
fi

ssh-keygen -R "vm.${SANDBOX_NAME}.${NS}" 2>/dev/null || true

# Fetch dashboard token
echo "Fetching dashboard token..."
TOKEN=$(guest_ssh "cat ~/.openclaw-token-${SANDBOX_NAME} 2>/dev/null" | tr -d '[:space:]' || true)

if [[ -z "${TOKEN}" ]]; then
  DASHBOARD_URL=$(guest_ssh "nemoclaw sandbox dashboard-url ${SANDBOX_NAME}" 2>/dev/null | grep -o 'http[^ ]*' | tail -1 || true)
  TOKEN=$(echo "${DASHBOARD_URL}" | grep -o '#token=.*' | sed 's/#token=//' || true)
fi

if [[ -z "${TOKEN}" ]]; then
  echo "Error: Could not extract dashboard token."
  echo "  Make sure the sandbox setup Job has completed successfully."
  echo ""
  echo "  Alternatively, access the dashboard directly via the route:"
  DASH_HOST=$(oc get route "${SANDBOX_NAME}-dashboard" -n "${NS}" -o jsonpath='{.spec.host}' 2>/dev/null || true)
  if [[ -n "${DASH_HOST}" ]]; then
    echo "  https://${DASH_HOST}"
  fi
  exit 1
fi

echo ""
echo "OpenClaw UI: http://localhost:${GUI_PORT}/#token=${TOKEN}"
echo "Press Ctrl-C to stop."
echo ""

# Port-forward via virtctl SSH — tunnels localhost:GUI_PORT to VM's 18789
# Uses SSH key auth only, no OIDC token required.
virtctl -n "${NS}" ssh "cloud-user@vm/${SANDBOX_NAME}" \
  --identity-file="${SSH_KEY_PATH}" \
  --local-ssh-opts="-oStrictHostKeyChecking=no" \
  --local-ssh-opts="-oUserKnownHostsFile=/dev/null" \
  --local-ssh-opts="-L${GUI_PORT}:127.0.0.1:18789" \
  --command="sleep infinity"
