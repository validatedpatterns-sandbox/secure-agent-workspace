#!/usr/bin/env bash
# Make the large installer ConfigMap reconcile via Replace (full PUT) so the
# workspace Argo app can go Synced on OCP 5.0's Argo.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "repo: $(pwd)   branch: $(git branch --show-current)"
git add charts/openshell-saw/templates/configmap-installer.yaml
git commit -m "fix(ocp5-rc5): Replace the large installer ConfigMap instead of patching

The ~300 KiB installer ConfigMap relies on the app's ServerSideApply=true, but
OCP 5.0's Argo CD client-side-applies it anyway (managedFields empty) and the
last-applied-configuration annotation exceeds the 256 KiB metadata limit, so
the workspace app sync fails. Annotate the ConfigMap with
sync-options: Replace=true (full PUT, no last-applied annotation).

Assisted-By: Claude" || echo "(nothing to commit)"
git push
oc annotate application saw-alice -n vp-gitops argocd.argoproj.io/refresh=hard --overwrite
oc patch application saw-alice -n vp-gitops --type merge \
  -p '{"operation":{"sync":{"revision":"ocp-5.0"}}}'
echo "waiting for saw-alice to sync..."
for i in $(seq 1 18); do
  sleep 10
  S=$(oc get application saw-alice -n vp-gitops -o jsonpath='{.status.sync.status}' 2>/dev/null)
  H=$(oc get application saw-alice -n vp-gitops -o jsonpath='{.status.health.status}' 2>/dev/null)
  echo "[$((i*10))s] saw-alice sync=$S health=$H"
  [ "$S" = "Synced" ] && break
done
echo
echo "=== app operation message (should be clean now) ==="
oc get application saw-alice -n vp-gitops -o jsonpath='{.status.operationState.message}{"\n"}' 2>&1
echo
echo "=== workspace status via generator (should move off 'failed') ==="
GPOD=$(oc get pods -n saw-portal -l app.kubernetes.io/name=saw-workspaces-generator -o name | tail -1)
oc exec -n saw-portal "$GPOD" -c generator -- curl -s http://localhost:4355/catalog.yaml 2>/dev/null \
  | grep -iE "openshell.pattern/status|description|installing|ready|failed" | head -6 || echo "(catalog read failed)"
