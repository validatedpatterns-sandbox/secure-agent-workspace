#!/usr/bin/env bash
set -euo pipefail

releases="$(helm list -A -o json)"
vms="$(oc get vm -A -l openshell.pattern/role=gateway -o json)"
rows="$(jq -nr --argjson releases "${releases}" --argjson vms "${vms}" '
  ($releases | map(select(.chart | startswith("openshell-saw")))) as $helm |
  ($vms.items | map({name: .metadata.name, namespace: .metadata.namespace,
    vm: (.status.printableStatus // "unknown"),
    created: (.metadata.creationTimestamp // "")})) as $gateways |
  ($helm | map(. as $release |
    ($gateways | map(select(.name == $release.name and
      .namespace == $release.namespace)) | first) as $vm |
    [$release.name, $release.namespace, $release.status,
      ($vm.vm // "missing"), ($release.updated | split(".")[0])])) as $manual |
  ($gateways | map(. as $vm |
    select($helm | any(.name == $vm.name and .namespace == $vm.namespace) | not) |
    [.name, .namespace, "Pattern", .vm, .created])) as $pattern |
  ($manual + $pattern)[] |
  @tsv')"
printf '%-20s %-24s %-12s %-12s %s\n' NAME NAMESPACE STATUS VM UPDATED
while IFS=$'\t' read -r name namespace status vm updated; do
  [[ -n "${name}" ]] || continue
  printf '%-20s %-24s %-12s %-12s %s\n' \
    "${name}" "${namespace}" "${status}" "${vm}" "${updated}"
done <<<"${rows}"
