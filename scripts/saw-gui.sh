#!/usr/bin/env bash
set -euo pipefail

gateway="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
sandbox="${SANDBOX_NAME:-}"
workspace="${WORKSPACE:-default}"
if [[ -z "${sandbox}" ]]; then
  sandbox="$(openshell --gateway "${gateway}" sandbox list \
    --workspace "${workspace}" --names | sed -n '1p')"
fi
if [[ -z "${sandbox}" ]]; then
  echo "Error: no sandbox was found on ${gateway} in ${workspace}." >&2
  exit 1
fi
export GATEWAY_NAME="${gateway}" SANDBOX_NAME="${sandbox}"
exec "$(dirname "$0")/openshell-saw-gui.sh"
