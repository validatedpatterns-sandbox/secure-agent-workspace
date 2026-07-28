#!/usr/bin/env bash
# Path 1 — Gateway only (no RHDH / no AAP).
# Installs CNV if needed, creates the Fedora OpenShell gateway VM, wires Vertex + Claude Code.
#
# Required (local, never committed):
#   oc login (cluster-admin)
#   GCP_SA_JSON=/path/to/vertex-sa.json
#   SSH key (~/.ssh/id_ed25519 or SSH_PUBKEY / SSH_IDENTITY)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib.sh
source "${ROOT}/scripts/lib.sh"

require_oc_login
require_cmd jq python3 curl
ensure_ssh_pubkey
require_sa_json
export PATH="${HOME}/bin:${PATH}"

INSTALL_CNV="${INSTALL_CNV:-1}"
if [[ "${INSTALL_CNV}" == "1" ]]; then
  "${ROOT}/scripts/install-cnv.sh"
fi

export NS="${NS:-openshell-agents}"
export SSH_PUBKEY
export GCP_SA_JSON="${GCP_SA_JSON:-${GOOGLE_APPLICATION_CREDENTIALS}}"
export VERTEX_AI_REGION="${VERTEX_AI_REGION:-global}"
export VERTEX_MODEL="${VERTEX_MODEL:-claude-sonnet-4-6}"

echo "== Path 1: OpenShell Fedora gateway + Claude =="
"${LAB_ROOT}/scripts/bootstrap-lab.sh" "${GCP_SA_JSON}"

echo
echo "Gateway-only install OK."
echo "Connect:"
echo "  virtctl -n ${NS} ssh cloud-user@vm/openshell-fedora"
echo "  ./claude-sandbox.sh"
