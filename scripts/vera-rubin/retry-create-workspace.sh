#!/usr/bin/env bash
# Clear the failed create run (from the pre-netpol-fix window) so a fresh
# template submit starts a clean pipeline. Does NOT touch the deployment.
set -uo pipefail
NS=saw-portal
echo "=== failed create pipelineruns to remove ==="
oc get pipelineruns -n $NS 2>&1 | grep -iE "saw-create|False|Failed" || echo "(none)"
for pr in $(oc get pipelineruns -n $NS -o name 2>/dev/null | grep saw-create); do
  SUCC=$(oc get $pr -n $NS -o jsonpath='{.status.conditions[?(@.type=="Succeeded")].status}' 2>/dev/null)
  if [ "$SUCC" = "False" ]; then echo "deleting failed $pr"; oc delete $pr -n $NS; fi
done
echo
echo "=== stale request secrets (template step 1), if any ==="
oc get secrets -n $NS -l saw.redhat.com/request 2>/dev/null || true
for s in $(oc get secrets -n $NS -o name 2>/dev/null | grep -iE "saw-request|request-"); do
  echo "deleting stale request $s"; oc delete $s -n $NS 2>&1 || true
done
echo
echo "=== confirm no saw-ws-alice yet (should be absent) ==="
oc get configmap -n $NS -l saw.redhat.com 2>&1 | grep -i "saw-ws" || echo "(no workspace registry entries — clean slate)"
echo
echo ">>> Now re-submit the Create workspace template in the UI (fresh run)."
echo ">>> Watch for a NEW pipelinerun:  oc get pipelineruns -n $NS -w"
