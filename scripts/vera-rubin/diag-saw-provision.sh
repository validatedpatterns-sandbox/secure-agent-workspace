#!/usr/bin/env bash
set -uo pipefail
NS=saw-portal
echo "=== request secrets (the template's step 1) ==="
oc get secrets -n $NS 2>&1 | grep -iE "saw|z9722|request|create" || echo "(none)"
echo
echo "=== pipelineruns in $NS ==="
oc get pipelineruns -n $NS --sort-by=.metadata.creationTimestamp 2>&1 | tail -10 || echo "(none / tekton not ready)"
echo
PR=$(oc get pipelineruns -n $NS --sort-by=.metadata.creationTimestamp -o name 2>/dev/null | tail -1)
if [ -n "${PR:-}" ]; then
  echo "=== latest pipelinerun: $PR ==="
  oc get $PR -n $NS -o jsonpath='{.status.conditions[*].reason}: {.status.conditions[*].message}{"\n"}' 2>&1
  echo "--- taskruns / pods ---"
  oc describe $PR -n $NS 2>&1 | sed -n '/Task Runs\|Conditions\|Events/,$p' | tail -40
else
  echo "=== NO pipelinerun was created — step 2 (start pipeline) failed ==="
fi
echo
echo "=== generator pod + recent logs (status endpoint) ==="
GPOD=$(oc get pods -n $NS -l app.kubernetes.io/name=saw-workspaces-generator -o name 2>/dev/null | tail -1)
echo "generator pod: ${GPOD:-NONE}"
if [ -n "${GPOD:-}" ]; then
  oc logs -n $NS "$GPOD" --tail=50 2>&1 | grep -iE "status|z9722|run|error|traceback|exception|forbidden|pipelinerun" | tail -30 || echo "(no matching log lines)"
  echo "--- last 20 raw generator log lines ---"
  oc logs -n $NS "$GPOD" --tail=20 2>&1
fi
echo
echo "=== can the generator SA read pipelineruns? (RBAC) ==="
GSA=$(oc get deploy -n $NS -l app.kubernetes.io/name=saw-workspaces-generator -o jsonpath='{.items[0].spec.template.spec.serviceAccountName}' 2>/dev/null)
echo "generator SA: ${GSA:-default}"
oc auth can-i get pipelineruns.tekton.dev -n $NS --as=system:serviceaccount:$NS:${GSA:-default} 2>&1
