#!/usr/bin/env bash
# Read-only GPU passthrough gate: the HCO entry and node allocatable.
set -euo pipefail

name="${GPU_DEVICE_NAME:-}"
count="${GPU_COUNT-1}"
[[ -n "$name" ]] || { echo "Error: GPU_ENABLED=true needs GPU_DEVICE_NAME (the HyperConverged resourceName)." >&2; exit 1; }
[[ "$count" =~ ^[1-9][0-9]*$ ]] || { echo "Error: GPU_COUNT must be a positive integer." >&2; exit 1; }
hco="$(oc get hyperconverged kubevirt-hyperconverged -n openshift-cnv -o json)"
if ! jq -e --arg r "$name" '(.spec.virtualization.permittedHostDevices.pciHostDevices // .spec.permittedHostDevices.pciHostDevices // []) | any(.resourceName == $r)' <<<"$hco" >/dev/null; then
  echo "Error: HyperConverged permittedHostDevices has no pciHostDevices entry for ${name}." >&2
  exit 1
fi
echo "HyperConverged GPU entry: ${name}"
nodes="$(oc get nodes -o json)"
if ! jq -e --arg r "$name" --argjson n "$count" \
    '.items | any(((.status.allocatable[$r] // "0") | tonumber) >= $n)' <<<"$nodes" >/dev/null; then
  echo "Error: no node advertises ${count} allocatable ${name}." >&2
  exit 1
fi
echo "Allocatable ${name}: at least ${count} on one node"
