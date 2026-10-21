#!/usr/bin/env bash
set -uo pipefail
echo "=== latest create pipelinerun status (should be Succeeded now) ==="
oc get pipelineruns -n saw-portal --sort-by=.metadata.creationTimestamp 2>&1 | tail -5
echo
echo "=== the actual scaffolder / http:backstage:request error (backend log) ==="
POD=$(oc get pods -n rhdh -o name | grep backstage-developer-hub | grep -v psql | tail -1)
oc logs -n rhdh "$POD" -c backstage-backend --since=30m 2>&1 \
  | grep -iE "scaffolder .*error|http:backstage:request|status code|statusCode|401|403|404|5[0-9][0-9]|token|unauthorized|saw-status|/run/saw-create" \
  | tail -30
echo
echo "=== DID ALICE'S WORKSPACE PROVISION? ==="
echo "--- argo apps for the workspace ---"
oc get applications -n vp-gitops 2>&1 | grep -iE "alice|workspace" || echo "(none matched alice/workspace)"
echo "--- workspace namespaces ---"
oc get ns 2>&1 | grep -iE "alice|saw-ws|workspace" || echo "(none)"
echo "--- VMs / VMIs ---"
oc get vm,vmi -A 2>&1 | grep -iE "alice|workspace|saw" || echo "(no VM matched)"
echo
echo "=== generator catalog.yaml: is alice now a workspace owner w/ a Component? ==="
GPOD=$(oc get pods -n saw-portal -l app.kubernetes.io/name=saw-workspaces-generator -o name | tail -1)
oc exec -n saw-portal "$GPOD" -c generator -- curl -s http://localhost:4355/catalog.yaml 2>/dev/null \
  | grep -iE "name|owner|saw-workspace-owners|alice|kind" | head -30 || echo "(couldn't read)"
