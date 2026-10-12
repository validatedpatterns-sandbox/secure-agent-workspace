#!/usr/bin/env bash
set -euo pipefail

namespace="${NS:-openshell-agents}"
echo '=== SAW namespaces ==='
oc get ns -l openshell.pattern/saw=true
echo '=== Helm releases ==='
helm list -A
echo '=== Gateway VMs ==='
oc get vm,vmi -A -l openshell.pattern/role=gateway
echo '=== Prepare Jobs ==='
oc get jobs -A -l app.kubernetes.io/part-of=openshell-cnv-fedora
echo "=== Images and builds (${namespace}) ==="
namespaces="$(oc get namespaces -o json)"
if jq -e --arg ns "${namespace}" '.items | any(.metadata.name == $ns)' \
  <<<"${namespaces}" >/dev/null; then
  oc get is,builds -n "${namespace}"
fi
