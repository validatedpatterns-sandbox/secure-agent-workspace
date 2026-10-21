#!/usr/bin/env bash
set -uo pipefail
echo "=== alice's VM / DataVolume / PVC (which namespace) ==="
oc get vm,dv,pvc -A 2>&1 | grep -iE "NAMESPACE|alice|saw-"
echo
echo "=== alice DataVolume phase + error reason ==="
while read -r ns name; do
  [ -z "$name" ] && continue
  echo "--- $ns/$name ---"
  oc get dv "$name" -n "$ns" -o jsonpath='phase={.status.phase}
progress={.status.progress}
conditions={range .status.conditions[*]}[{.type}={.status} {.reason}: {.message}]{end}
sourceRegistry={.spec.source.registry.url}
sourceRef={.spec.sourceRef.kind}/{.spec.sourceRef.name}@{.spec.sourceRef.namespace}
storageClass={.spec.storage.storageClassName}{.spec.pvc.storageClassName}
{"\n"}' 2>&1
done < <(oc get dv -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name}{"\n"}{end}' 2>/dev/null | grep -i alice)
echo
echo "=== CDI importer / prime pod logs (the real import failure) ==="
for row in $(oc get pods -A 2>/dev/null | grep -iE "importer|prime" | grep -iE "alice|saw-" | awk '{print $1"/"$2}'); do
  ns=${row%/*}; pod=${row#*/}
  echo "--- $ns/$pod ($(oc get pod $pod -n $ns -o jsonpath='{.status.phase}') ) ---"
  oc logs "$pod" -n "$ns" --all-containers --tail=25 2>&1 | tail -25
  oc get pod "$pod" -n "$ns" -o jsonpath='{range .status.containerStatuses[*]}{.name}: {.state.waiting.reason} {.state.terminated.reason} {.state.waiting.message}{"\n"}{end}' 2>&1
done
echo
echo "=== golden image: exists? arch? (the import source) ==="
oc get istag openshell-gateway:latest -n openshell-agents -o jsonpath='ref={.image.dockerImageReference}
arch={.image.dockerImageMetadata.Architecture}
manifests={.image.dockerImageManifests[*].architecture}
{"\n"}' 2>&1 || echo "(no golden istag in openshell-agents)"
echo
echo "=== storageclasses (VM DV binding) ==="
oc get storageclass 2>&1
echo "--- any CDI storageprofile for the SC the DV uses ---"
oc get storageprofile -A 2>&1 | head

echo
echo "=== would 'make copy-images' give us arm64? check UPSTREAM golden image arch ==="
for U in docker://ghcr.io/validatedpatterns-sandbox/openshell-gateway:latest \
         docker://quay.io/rh-ai-quickstart/openshell-gateway:latest; do
  echo "--- $U ---"
  skopeo inspect --raw "$U" 2>/dev/null | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
except Exception as e:
    print("  (could not read manifest:",e,")"); sys.exit()
if "manifests" in d:
    arches=sorted({m.get("platform",{}).get("architecture","?") for m in d["manifests"]})
    print("  multi-arch index:", ", ".join(arches))
else:
    print("  single-arch manifest (likely amd64) — mirroring would NOT give arm64")
' 2>&1 || echo "  (skopeo failed / not reachable)"
done
