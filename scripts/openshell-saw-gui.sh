#!/usr/bin/env bash
# Open the OpenClaw web UI through a forward owned by this process.
set -euo pipefail

gateway="${GATEWAY_NAME:?GATEWAY_NAME is required}"
sandbox="${SANDBOX_NAME:?SANDBOX_NAME is required}"
workspace="${WORKSPACE:-default}"
port="${GUI_PORT:-18789}"
user="${SSH_USER:-sandbox}"

command -v openshell >/dev/null || { echo "Error: openshell is required." >&2; exit 1; }
if [[ ! "${port}" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
  echo "Error: GUI_PORT must be a TCP port from 1 to 65535." >&2
  exit 1
fi

if command -v lsof >/dev/null && lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null; then
  echo "Error: local port ${port} is in use. Set GUI_PORT to a free port." >&2
  exit 1
fi

config="$(openshell --gateway "${gateway}" sandbox exec -n "${sandbox}" \
  --workspace "${workspace}" --no-tty -- cat /sandbox/.openclaw/openclaw.json)"
mode="$(jq -r '.gateway.auth.mode // empty' <<<"${config}")"
token=""
if [[ "${mode}" != "trusted-proxy" ]]; then
  token="$(jq -er '.gateway.auth.token | select(type == "string" and length > 0)' <<<"${config}")"
fi

url="http://localhost:${port}/"
if [[ -n "${token}" ]]; then
  url+="#token=${token}"
fi

ssh -o "ProxyCommand=openshell ssh-proxy --gateway-name ${gateway} --name ${sandbox} --workspace ${workspace}" \
  -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  -L "${port}:127.0.0.1:18789" -N "${user}@openshell-${sandbox}.${workspace}" &
forward_pid=$!
cleanup_forward() {
  if kill -0 "${forward_pid}" 2>/dev/null; then
    kill "${forward_pid}"
  fi
}
trap cleanup_forward EXIT
sleep 2
if ! kill -0 "${forward_pid}" 2>/dev/null; then
  wait "${forward_pid}"
  echo "Error: the UI forward stopped." >&2
  exit 1
fi

if command -v open >/dev/null; then
  open "${url}"
elif command -v xdg-open >/dev/null; then
  xdg-open "${url}"
else
  echo "Error: no browser opener is available." >&2
  exit 1
fi
unset token url config
echo "OpenClaw UI is available on local port ${port}. Press Ctrl-C to stop."
wait "${forward_pid}"
