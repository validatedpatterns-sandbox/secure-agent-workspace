#!/usr/bin/env bash
# Point the workspace VM disk at the GHCR multi-arch golden image, then
# re-import alice's root disk (no full 20-min re-run).
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "repo: $(pwd)   branch: $(git branch --show-current)"
git add charts/openshell-saw/values.yaml
git commit -m "fix(ocp5-rc5): pull golden VM disk from GHCR multi-arch image

On verac2 the CDI importer resolves via node/host DNS and can't reach the
in-cluster image registry (cluster-only name), and the golden image was never
mirrored there, so the VM DataVolume fails with ImagePullFailed. Point
source.registryURL at the public GHCR multi-arch image (amd64+arm64); the
arm64 node pulls its own arch. quay rh-ai-quickstart is amd64-only.

Assisted-By: Claude" || echo "(nothing to commit)"
git push

echo "=== sync the workspace app so the VM template picks up the GHCR source ==="
oc annotate application saw-alice -n vp-gitops argocd.argoproj.io/refresh=hard --overwrite 2>/dev/null || true
oc patch application saw-alice -n vp-gitops --type merge \
  -p '{"operation":{"sync":{"revision":"ocp-5.0"}}}' 2>/dev/null || true
echo "waiting ~20s for the VM manifest to update..."; sleep 20
echo "VM dataVolumeTemplate source now:"
oc get vm alice -n saw-alice -o jsonpath='{.spec.dataVolumeTemplates[0].spec.source.registry.url}{"\n"}' 2>&1

echo "=== recreate alice's root DataVolume from the new source ==="
oc delete datavolume alice-root -n saw-alice --ignore-not-found
# prime PVC + importer pod are owned by the DV / CDI; clean any leftovers
oc delete pvc -n saw-alice -l cdi.kubevirt.io=importer --ignore-not-found 2>/dev/null || true
echo "KubeVirt will recreate alice-root from the dataVolumeTemplate. Watching ~90s..."
for i in $(seq 1 9); do
  sleep 10
  PH=$(oc get dv alice-root -n saw-alice -o jsonpath='{.status.phase}' 2>/dev/null || echo "-")
  PROG=$(oc get dv alice-root -n saw-alice -o jsonpath='{.status.progress}' 2>/dev/null || echo "")
  SRC=$(oc get dv alice-root -n saw-alice -o jsonpath='{.spec.source.registry.url}' 2>/dev/null || echo "")
  echo "[$((i*10))s] alice-root phase=$PH progress=$PROG src=$SRC"
  case "$PH" in Succeeded|ImportInProgress) ;; esac
done
echo
echo "=== importer pod status (should be pulling from ghcr now, not the svc) ==="
oc get pods -n saw-alice 2>&1 | grep -iE "importer|prime" || echo "(no importer pod)"
P=$(oc get pods -n saw-alice -o name 2>/dev/null | grep -iE "importer|prime" | tail -1)
[ -n "$P" ] && oc logs "$P" -n saw-alice --all-containers --tail=15 2>&1 | tail -15
