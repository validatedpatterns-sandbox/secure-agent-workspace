#!/usr/bin/env bash
# One entrypoint for a cluster provisioned from demo.redhat.com
# (e.g. Experience OpenShift Virtualization Roadshow 2026).
#
# Usage:
#   export KUBECONFIG=/path/from/lab-guide
#   export GCP_SA_JSON=/path/to/vertex-sa.json   # never commit
#   ./scripts/install-from-demo-redhat.sh              # gateway + self-service
#   ./scripts/install-from-demo-redhat.sh gateway      # Path 1 only
#   ./scripts/install-from-demo-redhat.sh self-service # Path 2 (gateway first if missing)
#
# Optional:
#   POOL_SIZE=3   # parallel Claude sandboxes (extra gateway VMs)
#   INSTALL_CNV=0 # skip CNV install when the roadshow already has it
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib.sh
source "${ROOT}/scripts/lib.sh"

MODE="${1:-all}"
export PATH="${HOME}/bin:${PATH}"
export INSTALL_CNV="${INSTALL_CNV:-1}"
export POOL_SIZE="${POOL_SIZE:-3}"

require_oc_login

case "${MODE}" in
  gateway|1|path1)
    "${ROOT}/scripts/01-install-gateway.sh"
    ;;
  self-service|2|path2|rhdh|aap)
    export BOOTSTRAP_GATEWAY=1
    "${ROOT}/scripts/02-install-self-service.sh"
    ;;
  all|full|"")
    "${ROOT}/scripts/01-install-gateway.sh"
    export BOOTSTRAP_GATEWAY=0
    "${ROOT}/scripts/02-install-self-service.sh"
    ;;
  *)
    echo "usage: $0 [gateway|self-service|all]" >&2
    exit 2
    ;;
esac

echo
echo "install-from-demo-redhat (${MODE}) complete."
