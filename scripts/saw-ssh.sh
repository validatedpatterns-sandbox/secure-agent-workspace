#!/usr/bin/env bash
# Open a sandbox shell through the selected SAW gateway.
set -euo pipefail

gateway="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
sandbox="${SANDBOX_NAME:-notebook}"
workspace="${WORKSPACE:-default}"
for value in "${gateway}" "${sandbox}" "${workspace}"; do
  if [[ ! "${value}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    echo "Error: SAW, sandbox, and workspace names must be DNS labels." >&2
    exit 1
  fi
done

exec ssh \
  -o "ProxyCommand=openshell ssh-proxy --gateway-name ${gateway} --name ${sandbox} --workspace ${workspace}" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  "sandbox@openshell-${sandbox}.${workspace}"
