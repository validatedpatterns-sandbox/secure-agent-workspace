#!/usr/bin/env bash
set -euo pipefail

name="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
namespace="${SAW_NS:-saw-${name}}"
script_dir="$(cd "$(dirname "$0")" && pwd)"

"${script_dir}/helm-uninstall-if-present.sh" "${name}" "${namespace}"
namespaces="$(oc get namespaces -o json)"
owned="$(jq -r --arg ns "${namespace}" \
  '.items[] | select(.metadata.name == $ns) |
   .metadata.labels["openshell.pattern/saw"] // "false"' <<<"${namespaces}")"
if [[ "${owned}" == true ]]; then
  oc delete namespace "${namespace}" --wait=false
elif [[ -n "${owned}" ]]; then
  echo "Keeping ${namespace}: it does not have the SAW ownership label."
fi
