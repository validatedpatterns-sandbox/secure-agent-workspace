#!/usr/bin/env bash
# Restart the SAW VMs whose spec changed while they were running.
#
# KubeVirt does not restart a running VM when its template changes (a new
# gateway.toml after switching global.governance.engine, a BOM or profile
# change without vm.liveInputs): it sets the RestartRequired condition and the
# guest keeps its old config until the next boot. This lists those VMs and,
# with CONFIRM=yes, restarts them. Users' running sandboxes stop with the VM.
set -euo pipefail

vms="$(oc get vm -A -l openshell.pattern/role=gateway -o json)"
pending="$(jq -r '.items[]
  | select(any(.status.conditions[]?; .type == "RestartRequired" and .status == "True"))
  | [.metadata.namespace, .metadata.name] | @tsv' <<<"${vms}")"

if [[ -z "${pending}" ]]; then
  echo "No SAW VM is waiting for a restart."
  exit 0
fi

echo "SAW VMs waiting for a restart (RestartRequired):"
while IFS=$'\t' read -r ns name; do
  printf '  %-20s %s\n' "${name}" "${ns}"
done <<<"${pending}"

if [[ "${CONFIRM:-}" != "yes" ]]; then
  echo "Run again with CONFIRM=yes to restart them (their sandboxes stop while the VM reboots)."
  exit 0
fi

while IFS=$'\t' read -r ns name; do
  virtctl -n "${ns}" restart "${name}"
done <<<"${pending}"
