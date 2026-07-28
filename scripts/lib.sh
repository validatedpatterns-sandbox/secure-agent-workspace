#!/usr/bin/env bash
# Shared helpers for repo entrypoints.
# shellcheck disable=SC2034
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ROOT="${LAB_ROOT:-${REPO_ROOT}/lab}"

require_cmd() {
  local c
  for c in "$@"; do
    command -v "${c}" >/dev/null 2>&1 || {
      echo "missing required command: ${c}" >&2
      exit 1
    }
  done
}

require_oc_login() {
  require_cmd oc
  oc whoami >/dev/null 2>&1 || {
    echo "oc is not logged in. For demo.redhat.com: copy kubeconfig from the lab guide, then:" >&2
    echo "  export KUBECONFIG=/path/to/kubeconfig" >&2
    exit 1
  }
  echo "cluster: $(oc whoami --show-console 2>/dev/null || oc whoami -c)  user=$(oc whoami)"
}

require_sa_json() {
  local p="${GCP_SA_JSON:-${GOOGLE_APPLICATION_CREDENTIALS:-}}"
  if [[ -z "${p}" || ! -f "${p}" ]]; then
    echo "Set GCP_SA_JSON (or GOOGLE_APPLICATION_CREDENTIALS) to a Vertex SA JSON file." >&2
    echo "Do not commit that file." >&2
    exit 1
  fi
  # Validate shape without printing secrets
  python3 - "$p" <<'PY'
import json,sys
p=sys.argv[1]
d=json.load(open(p))
assert d.get("type")=="service_account" and d.get("private_key") and d.get("client_email"), "not a usable SA JSON"
print("SA JSON OK (project=%s)" % d.get("project_id","?"))
PY
}

ensure_ssh_pubkey() {
  if [[ -z "${SSH_PUBKEY:-}" ]]; then
    if [[ -f "${HOME}/.ssh/id_ed25519.pub" ]]; then
      SSH_PUBKEY="$(cat "${HOME}/.ssh/id_ed25519.pub")"
    elif [[ -f "${HOME}/.ssh/id_rsa.pub" ]]; then
      SSH_PUBKEY="$(cat "${HOME}/.ssh/id_rsa.pub")"
    else
      echo "Set SSH_PUBKEY or create ~/.ssh/id_ed25519.pub" >&2
      exit 1
    fi
  fi
  export SSH_PUBKEY
}
