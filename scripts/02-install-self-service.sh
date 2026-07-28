#!/usr/bin/env bash
# Path 2 — Self-service (RHDH + AWX/AAP + gateway pool) on top of Path 1.
# Assumes at least one Ready openshell-fedora* gateway (run 01-install-gateway.sh first),
# or set BOOTSTRAP_GATEWAY=1 to run Path 1 first.
#
# Optional: POOL_SIZE=3 to clone extra gateways for parallel Creates.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib.sh
source "${ROOT}/scripts/lib.sh"

require_oc_login
require_cmd jq python3 curl tar git base64
export PATH="${HOME}/bin:${PATH}"
export NS="${NS:-openshell-agents}"

BOOTSTRAP_GATEWAY="${BOOTSTRAP_GATEWAY:-0}"
POOL_SIZE="${POOL_SIZE:-1}"
WIRE_RHDH="${WIRE_RHDH:-1}"

if [[ "${BOOTSTRAP_GATEWAY}" == "1" ]]; then
  "${ROOT}/scripts/01-install-gateway.sh"
fi

if ! oc -n "${NS}" get vmi -l openshell.pattern/role=gateway -o name 2>/dev/null | grep -q .; then
  # Label may be missing before apply-labels; accept any openshell-fedora* Ready VMI
  if ! oc -n "${NS}" get vmi openshell-fedora -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Running; then
    echo "No Ready gateway VM. Run: ./scripts/01-install-gateway.sh" >&2
    exit 1
  fi
fi

echo "== RHDH + AAP operators =="
# Defer content import until after pool scale + RHDH is up.
BOOTSTRAP_CONTENT=0 "${LAB_ROOT}/scripts/install-platform.sh"

echo "== Gateway pool labels + leases =="
"${LAB_ROOT}/gateway-pool/apply-labels.sh"

if [[ "${POOL_SIZE}" =~ ^[0-9]+$ ]] && (( POOL_SIZE > 1 )); then
  echo "== Scale gateway pool to ${POOL_SIZE} =="
  "${LAB_ROOT}/gateway-pool/scale-pool.sh" "${POOL_SIZE}"
fi

echo "== AAP content (project, create/delete JTs) + wire RHDH =="
# Writes lab/aap/.bootstrap/aap.env locally (gitignored) — never commit it.
WIRE_RHDH="${WIRE_RHDH}" "${LAB_ROOT}/aap/scripts/bootstrap-aap-content.sh"

# Ensure route timeout for long scaffolder polls
ROUTE="$(oc -n rhdh get route -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -n "${ROUTE}" ]]; then
  oc -n rhdh annotate route "${ROUTE}" haproxy.router.openshift.io/timeout=10m --overwrite
fi

echo
echo "Self-service install OK."
RHDH_HOST="$(oc -n rhdh get route -o jsonpath='{.items[0].spec.host}' 2>/dev/null || true)"
AAP_HOST="$(oc -n awx get route -o jsonpath='{.items[0].spec.host}' 2>/dev/null \
  || oc -n aap get route -o jsonpath='{.items[0].spec.host}' 2>/dev/null || true)"
[[ -n "${RHDH_HOST}" ]] && echo "  RHDH: https://${RHDH_HOST}"
[[ -n "${AAP_HOST}" ]] && echo "  AWX/AAP: https://${AAP_HOST}"
echo "  Create sandboxes: RHDH → Self-service → Create Claude Code sandbox"
echo "  Credentials: see lab/aap/README.md (admin password from cluster Secret; not committed)"
