#!/usr/bin/env bash
set -uo pipefail
GNS=openshell-agents
echo "=== golden image in the internal registry (istag) ==="
oc get istag openshell-gateway:latest -n $GNS -o jsonpath='ref={.image.dockerImageReference}
arch={.image.dockerImageMetadata.Architecture}
created={.image.dockerImageMetadata.Created}
{"\n"}' 2>&1 || echo "(no istag openshell-gateway:latest in $GNS)"
echo
echo "=== DataSource / DataImportCron / DataVolume for the golden image ==="
oc get datasource,datavolume,dataimportcron -n $GNS 2>&1 | grep -iE "gateway|golden|NAME" || echo "(none)"
echo
echo "=== was it BUILT on-cluster (arm64-correct) or imported? ==="
oc get buildconfig,builds -n $GNS 2>&1 | grep -iE "gateway|NAME" | tail
echo "--- build namespace (if different): check openshell-agents + any *-build ns ---"
for ns in $GNS openshell-agents-build saw-build; do
  oc get builds -n $ns 2>/dev/null | grep -i gateway | tail -2
done
echo
echo "=== CONFIRM arch of the actual image manifest (definitive) ==="
REF=$(oc get istag openshell-gateway:latest -n $GNS -o jsonpath='{.image.dockerImageReference}' 2>/dev/null)
echo "image ref: ${REF:-<none>}"
oc get istag openshell-gateway:latest -n $GNS -o jsonpath='{.image.dockerImageManifests[*].architecture}' 2>&1
echo "  (^ if this lists arm64, it is multi-arch; empty = single-arch, check 'arch=' above)"
echo
echo "=== the stuck test-vm: is it a STORAGE bind issue (separate from arch)? ==="
oc get dv,pvc -n test-vm 2>&1
oc get dv -n test-vm -o jsonpath='{range .items[*]}{.metadata.name}: {.status.phase} - {.status.conditions[*].message}{"\n"}{end}' 2>&1
