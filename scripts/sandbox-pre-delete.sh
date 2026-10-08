#!/usr/bin/env bash
set -euo pipefail

name="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
namespace="${SAW_NS:-saw-${name}}"
namespaces="$(oc get namespaces -o json)"
if ! jq -e --arg ns "${namespace}" '.items | any(.metadata.name == $ns)' \
  <<<"${namespaces}" >/dev/null; then
  echo "Namespace ${namespace} is already absent."
  exit 0
fi
echo "Scheduling VM and disk deletion in ${namespace}."
resources="$(oc api-resources -o name)"
if grep -q '^virtualmachines.kubevirt.io$' <<<"${resources}"; then
  oc delete vm "${name}" -n "${namespace}" --wait=false --ignore-not-found=true
fi
if grep -q '^datavolumes.cdi.kubevirt.io$' <<<"${resources}"; then
  oc delete dv "${name}-root" -n "${namespace}" --wait=false --ignore-not-found=true
fi
