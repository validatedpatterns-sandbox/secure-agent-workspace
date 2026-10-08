#!/usr/bin/env bash
# Stop only VMs in SAW namespaces owned by this pattern before app removal.
set -euo pipefail

argo_namespace="${ARGOCD_NS:-vp-gitops}"
namespaces="$(oc get namespaces -o json)"
resources="$(oc api-resources -o name)"
if ! grep -q '^virtualmachines.kubevirt.io$' <<<"${resources}"; then
  echo "KubeVirt VM resources are absent."
  exit 0
fi

owned_namespace_rows="$(jq -r --arg argo "${argo_namespace}" \
  '.items[] | select(.metadata.labels["openshell.pattern/saw"] == "true" and
    .metadata.labels["argocd.argoproj.io/managed-by"] == $argo) |
    [.metadata.name, .metadata.labels["openshell.pattern/owner"] // ""] |
    select(.[1] != "" and .[0] == "saw-" + .[1]) | @tsv' \
  <<<"${namespaces}")"
while IFS=$'\t' read -r namespace owner; do
  [[ -n "${namespace}" ]] || continue
  vms="$(oc get vm -n "${namespace}" -l openshell.pattern/role=gateway -o json)"
  if jq -e --arg name "${owner}" \
      '.items | any(.metadata.name == $name and
        .metadata.labels["app.kubernetes.io/instance"] == $name)' \
      <<<"${vms}" >/dev/null; then
    echo "Deleting owned gateway VM ${namespace}/${owner}."
    oc delete vm "${owner}" -n "${namespace}" --wait=false
  else
    echo "No owned gateway VM in ${namespace}."
  fi
  if grep -q '^datavolumes.cdi.kubevirt.io$' <<<"${resources}"; then
    oc delete dv "${owner}-root" -n "${namespace}" \
      --wait=false --ignore-not-found=true
  fi
  if grep -q '^virtualmachineinstances.kubevirt.io$' <<<"${resources}"; then
    vmis="$(oc get vmi -n "${namespace}" -o json)"
    if jq -e --arg name "${owner}" \
        '.items | any(.metadata.name == $name)' <<<"${vmis}" >/dev/null; then
      oc wait --for=delete vmi "${owner}" -n "${namespace}" --timeout=120s
    fi
  fi
done <<<"${owned_namespace_rows}"
