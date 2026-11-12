#!/usr/bin/env bash
set -euo pipefail

mode="${1:?Specify nemoclaw or openclaw}"
gateway="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
workspace="${WORKSPACE:-default}"
sandbox="${SANDBOX_NAME:-}"
if [[ -z "${sandbox}" ]]; then
  sandbox="$(openshell --gateway "${gateway}" sandbox list \
    --workspace "${workspace}" --names | sed -n '1p')"
fi
if [[ -z "${sandbox}" ]]; then
  echo "Error: no sandbox was found on ${gateway} in ${workspace}." >&2
  exit 1
fi

case "${mode}" in
  nemoclaw|openclaw)
    # Both images run OpenClaw's gateway. A route uses trusted-proxy auth;
    # local TUI clients authenticate with its loopback password instead.
    exec openshell --gateway "${gateway}" sandbox exec -n "${sandbox}" \
      --workspace "${workspace}" --tty -- /bin/bash -ic \
      'set -e
       export HOME=/sandbox OPENCLAW_HOME=/sandbox OPENCLAW_CONFIG_PATH=/sandbox/.openclaw/openclaw.json
       export SQLITE_TMPDIR=/sandbox/.openclaw/state TMPDIR=/sandbox/.openclaw/state OPENCLAW_NIX_MODE=0 TERM=xterm-256color
       password="$(node -e "const a=require(\"/sandbox/.openclaw/openclaw.json\").gateway.auth; if(typeof a.password===\"string\") process.stdout.write(a.password)")"
       if [ -n "$password" ]; then export OPENCLAW_GATEWAY_PASSWORD="$password"; fi
       unset password
       exec openclaw tui'
    ;;
  *) echo "Error: mode must be nemoclaw or openclaw." >&2; exit 2 ;;
esac
