#!/usr/bin/env bash
set -uo pipefail
NS=saw-portal
echo "=== taskruns for saw-create-z9722 (which task failed) ==="
for tr in $(oc get taskruns -n $NS -l tekton.dev/pipelineRun=saw-create-z9722 -o name 2>/dev/null); do
  echo "--- $tr ---"
  oc get $tr -n $NS -o jsonpath='task={.metadata.labels.tekton\.dev/pipelineTask}  {.status.conditions[*].reason}: {.status.conditions[*].message}{"\n"}' 2>&1
done
echo
echo "=== failed task pod logs ==="
for p in $(oc get pods -n $NS -l tekton.dev/pipelineRun=saw-create-z9722 -o name 2>/dev/null); do
  PH=$(oc get $p -n $NS -o jsonpath='{.status.phase}' 2>/dev/null)
  echo "===== $p  (phase=$PH) ====="
  oc logs -n $NS $p --all-containers --tail=50 2>&1 | tail -50
done
echo
echo "############ JWKS / internal-URL reachability ############"
echo "=== backend service ports in rhdh ns (does :80 exist?) ==="
oc get svc -n rhdh backstage-developer-hub -o jsonpath='{range .spec.ports[*]}name={.name} port={.port} targetPort={.targetPort}{"\n"}{end}' 2>&1
echo
GPOD=$(oc get pods -n $NS -l app.kubernetes.io/name=saw-workspaces-generator -o name 2>/dev/null | tail -1)
echo "generator RHDH_INTERNAL_URL env:"
oc exec -n $NS "$GPOD" -c generator -- printenv RHDH_INTERNAL_URL 2>&1
echo "=== can the generator reach :80 JWKS? (expect this to hang/fail) ==="
oc exec -n $NS "$GPOD" -c generator -- python3 -c "
import urllib.request,sys
for port in (80,7007):
    u='http://backstage-developer-hub.rhdh.svc:%d/api/auth/.well-known/jwks.json'%port
    try:
        r=urllib.request.urlopen(u,timeout=6); print(port,'OK',r.status)
    except Exception as e: print(port,'FAIL',type(e).__name__,e)
" 2>&1
