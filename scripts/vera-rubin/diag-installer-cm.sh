#!/usr/bin/env bash
set -uo pipefail
echo "=== saw-alice app: sync status + syncOptions + error ==="
oc get application saw-alice -n vp-gitops -o jsonpath='sync={.status.sync.status} health={.status.health.status}
syncOptions={.spec.syncPolicy.syncOptions}
msg={.status.operationState.message}{"\n"}' 2>&1
echo
echo "=== alice-installer ConfigMap: exists? which annotation is too big? ==="
oc get configmap alice-installer -n saw-alice -o json 2>/dev/null | python3 -c '
import sys,json
d=json.load(sys.stdin)
ann=d.get("metadata",{}).get("annotations",{})
print("annotations:")
for k,v in sorted(ann.items(), key=lambda kv:-len(kv[1])): print(f"  {len(v):>8} bytes  {k}")
data=d.get("data",{})
print("data total:", sum(len(v) for v in data.values()), "bytes across", len(data), "keys")
mf=d.get("metadata",{}).get("managedFields",[])
print("managedFields managers:", [m.get("manager") for m in mf])
' 2>&1 || echo "(alice-installer not applied — the sync failed before creating/patching it)"
echo
echo "=== does ANY configmap in saw-alice carry last-applied-configuration? ==="
oc get configmap -n saw-alice -o json 2>/dev/null | python3 -c '
import sys,json
for it in json.load(sys.stdin).get("items",[]):
    a=it.get("metadata",{}).get("annotations",{})
    lac=a.get("kubectl.kubernetes.io/last-applied-configuration")
    if lac: print(it["metadata"]["name"], "has last-applied-configuration:", len(lac), "bytes")
' 2>&1
