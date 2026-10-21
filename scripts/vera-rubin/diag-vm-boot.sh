#!/usr/bin/env bash
set -uo pipefail
NS=saw-alice
echo "=== VM / VMI status (should move off DataVolumeError -> Starting/Running) ==="
oc get vm,vmi -n $NS 2>&1
echo
oc get vm alice -n $NS -o jsonpath='VM printableStatus={.status.printableStatus} ready={.status.ready}{"\n"}' 2>&1
oc get vmi alice -n $NS -o jsonpath='VMI phase={.status.phase} ip={.status.interfaces[0].ipAddress} node={.status.nodeName}{"\n"}' 2>&1
echo
echo "=== virt-launcher pod (the running VM) ==="
oc get pods -n $NS 2>&1 | grep -iE "virt-launcher|NAME" || echo "(no virt-launcher yet)"
echo
echo "=== VM events (boot / scheduling) ==="
oc get events -n $NS --sort-by=.lastTimestamp 2>&1 | grep -iE "alice|VirtualMachine|DataVolume|started|scheduled|error" | tail -12
echo
echo "=== OpenShell install progress: generator /status for alice ==="
GPOD=$(oc get pods -n saw-portal -l app.kubernetes.io/name=saw-workspaces-generator -o name | tail -1)
oc exec -n saw-portal "$GPOD" -c generator -- curl -s http://localhost:4355/catalog.yaml 2>/dev/null \
  | grep -iE "alice|saw-workspace-owners|member|owner|openshell|url" | head -20 || echo "(catalog read failed)"
