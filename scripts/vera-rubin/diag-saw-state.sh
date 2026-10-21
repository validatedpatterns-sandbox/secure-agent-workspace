#!/usr/bin/env bash
set -uo pipefail
echo "=== ALL pipelineruns in saw-portal (status) ==="
oc get pipelineruns -n saw-portal --sort-by=.metadata.creationTimestamp 2>&1 | tail -8
echo
LATEST=$(oc get pipelineruns -n saw-portal --sort-by=.metadata.creationTimestamp -o name 2>/dev/null | tail -1)
echo "=== latest run: $LATEST — taskruns + results ==="
if [ -n "${LATEST:-}" ]; then
  RUN=${LATEST##*/}
  for tr in $(oc get taskruns -n saw-portal -l tekton.dev/pipelineRun=$RUN -o name 2>/dev/null); do
    echo "--- $tr ---"
    oc get $tr -n saw-portal -o jsonpath='task={.metadata.labels.tekton\.dev/pipelineTask}  {.status.conditions[*].reason}: {.status.conditions[*].message}{"\n"}' 2>&1
  done
  echo "--- register task pod log (tail) ---"
  for p in $(oc get pods -n saw-portal -l tekton.dev/pipelineRun=$RUN -o name 2>/dev/null | grep -i register); do
    oc logs -n saw-portal $p --all-containers --tail=40 2>&1 | tail -40
  done
fi
echo
echo "=== workspace registry (what register writes in saw-portal) ==="
oc get secrets,configmaps -n saw-portal 2>&1 | grep -iE "workspace|registry|alice|regist" || echo "(no workspace registry objects)"
echo
echo "=== broad resource check ==="
echo "-- all argo apps --"; oc get applications -n vp-gitops 2>&1
echo "-- all VMs --"; oc get vm,vmi -A 2>&1 | head
echo "-- namespaces (openshell/saw/ws/alice) --"; oc get ns 2>&1 | grep -iE "openshell|saw|ws-|alice" || echo "(none)"
echo
echo "=== what does /status report for the latest run? ==="
GPOD=$(oc get pods -n saw-portal -l app.kubernetes.io/name=saw-workspaces-generator -o name | tail -1)
oc logs -n saw-portal "$GPOD" -c generator --tail=40 2>&1 | grep -iE "error|traceback|register|workspace|status|exception|forbidden|alice" | tail -20 || echo "(no matching generator log)"
