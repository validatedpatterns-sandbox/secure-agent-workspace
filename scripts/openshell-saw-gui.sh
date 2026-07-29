#!/usr/bin/env bash
# Open the OpenClaw web UI via openshell ssh-proxy port-forward.
# Uses the local openshell CLI with fresh OIDC token — no virtctl needed.

set -euo pipefail

OPENSHELL_SAW_NAME="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
GATEWAY_NAME="${GATEWAY_NAME:-${OPENSHELL_SAW_NAME}}"
GUI_PORT="${GUI_PORT:-18789}"
SSH_USER="${SSH_USER:-sandbox}"

command -v openshell >/dev/null 2>&1 || {
  echo "Error: openshell CLI not found. Install from https://github.com/NVIDIA/OpenShell/releases"
  exit 1
}

# Kill any existing port-forward on this port
pids=$(lsof -ti :"${GUI_PORT}" 2>/dev/null || true)
if [[ -n "${pids}" ]]; then
  kill "${pids}" 2>/dev/null || true
  sleep 1
fi

# Fetch dashboard token via openshell sandbox exec
echo "Fetching dashboard token..."
TOKEN=$(openshell --gateway-insecure sandbox exec -n "${OPENSHELL_SAW_NAME}" --no-tty -- \
  cat /sandbox/.openclaw/openclaw.json 2>/dev/null \
  | python3 -c "import sys,json; c=json.load(sys.stdin); print((c.get('gateway',{}).get('auth',{}).get('token','')))" 2>/dev/null | grep -oE '^[a-f0-9]+$' || true)

if [[ -z "${TOKEN}" ]]; then
  TOKEN=$(openshell --gateway-insecure sandbox exec -n "${OPENSHELL_SAW_NAME}" --no-tty -- \
    cat /tmp/auth-token 2>/dev/null | grep -oE '[a-f0-9]{32,}' || true)
fi

if [[ -z "${TOKEN}" ]]; then
  echo "Error: Could not extract dashboard token."
  echo "  Make sure the sandbox setup has completed and openclaw is configured."
  echo ""
  echo "  Try: openshell --gateway-insecure sandbox list"
  exit 1
fi

echo ""
echo "OpenClaw UI: http://localhost:${GUI_PORT}/#token=${TOKEN}"
echo "Press Ctrl-C to stop."
echo ""

# Port-forward via openshell ssh-proxy — uses local OIDC token
ssh -o "ProxyCommand=openshell --gateway-insecure ssh-proxy --gateway-name ${GATEWAY_NAME} --name ${OPENSHELL_SAW_NAME}" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -L "${GUI_PORT}:127.0.0.1:18789" \
  -N "${SSH_USER}@openshell-${OPENSHELL_SAW_NAME}.default"
