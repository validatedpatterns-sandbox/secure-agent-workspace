#!/usr/bin/env bash
# Power off in the guest so runStrategy: Always starts a new VMI with fresh
# mounted inputs. Do not fall back to host termination if guest access fails.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAW_NS="${SAW_NS:?SAW_NS is required}"
VM_NAME="${VM_NAME:?VM_NAME is required}"
RESTART_TIMEOUT="${RESTART_TIMEOUT:-600}"
[[ "${RESTART_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || { echo "RESTART_TIMEOUT must be positive seconds" >&2; exit 1; }

strategy="$(oc get vm "${VM_NAME}" -n "${SAW_NS}" -o jsonpath='{.spec.runStrategy}')"
if [[ "${strategy}" != Always ]]; then
  echo "Guest restart requires runStrategy: Always; ${SAW_NS}/${VM_NAME} uses '${strategy}'." >&2
  exit 1
fi
snapshot="$(oc get vmi "${VM_NAME}" -n "${SAW_NS}" -o jsonpath='{.metadata.uid}{" "}{.status.phase}')"
read -r old_uid phase <<<"${snapshot}"
if [[ -z "${old_uid}" || "${phase}" != Running ]]; then
  echo "${SAW_NS}/${VM_NAME} must have a Running instance before restart." >&2
  exit 1
fi

"${SCRIPT_DIR}/openshell-saw-vm-ssh.sh" 'sudo systemctl poweroff'
echo "Guest poweroff requested; waiting for a replacement VM instance."
deadline=$((SECONDS + RESTART_TIMEOUT))
while (( SECONDS < deadline )); do
  snapshot="$(oc get vmi "${VM_NAME}" -n "${SAW_NS}" --ignore-not-found \
    -o jsonpath='{.metadata.uid}{" "}{.status.phase}')"
  read -r uid phase <<<"${snapshot}"
  if [[ -n "${uid}" && "${uid}" != "${old_uid}" && "${phase}" == Running ]]; then
    echo "Replacement VM ${SAW_NS}/${VM_NAME} is Running. Check make saw-status for boot install/apply."
    exit 0
  fi
  sleep 5
done
echo "No replacement Running VMI observed within ${RESTART_TIMEOUT}s; inspect the guest/VM state." >&2
exit 1
