#!/usr/bin/env bash
# One-shot: capture the manual-step objects from the live cluster so the
# pre/post-install scripts reproduce exactly what's deployed. Writes cleaned
# manifests into scripts/vera-rubin/manifests/ and prints the key values.
set -uo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
OUT=scripts/vera-rubin/manifests; mkdir -p "$OUT"
clean(){ python3 -c '
import sys,yaml
out=[]
for d in yaml.safe_load_all(sys.stdin):
    if not d: continue
    m=d.get("metadata",{}) or {}
    for k in ("resourceVersion","uid","creationTimestamp","generation","managedFields","ownerReferences","selfLink"): m.pop(k,None)
    ann=m.get("annotations",{}) or {}
    for k in list(ann):
        if k.startswith("kubectl.kubernetes.io/last-applied") or "kopf.zalando" in k: ann.pop(k,None)
    if ann=={}: m.pop("annotations",None)
    d.pop("status",None); d["metadata"]=m
    out.append(d)
print(yaml.safe_dump_all(out,default_flow_style=False,sort_keys=False))
'; }

echo "### patterns-operator image + install style"
oc get deploy -n openshift-operators patterns-operator-controller-manager -o jsonpath='image={.spec.template.spec.containers[?(@.name=="manager")].image}{"\n"}' 2>&1
oc get subscription -A 2>&1 | grep -i patterns || echo "(no patterns-operator Subscription -> still the out-of-catalog raw install; run migrate-patterns-operator.sh)"

echo "### RHDH community CatalogSource -> $OUT/rhdh-community-catalog.yaml"
oc get catalogsource rhdh-community-catalog -n openshift-marketplace -o yaml 2>/dev/null | clean > "$OUT/rhdh-community-catalog.yaml" && cat "$OUT/rhdh-community-catalog.yaml"

echo "### other non-default CatalogSources (anything we added)"
oc get catalogsource -n openshift-marketplace -o custom-columns=NAME:.metadata.name,IMAGE:.spec.image 2>&1

echo "### RHDH subscription config.env (arm64 pg15)"
oc get subscription rhdh -n rhdh-operator -o jsonpath='{.spec.config.env}{"\n"}' 2>&1
oc get subscription rhdh -n rhdh-operator -o yaml 2>/dev/null | clean > "$OUT/rhdh-subscription.yaml"

echo "### saw-hostpath StorageClass -> $OUT/storageclass-saw-hostpath.yaml"
oc get storageclass saw-hostpath -o yaml 2>/dev/null | clean > "$OUT/storageclass-saw-hostpath.yaml" && grep -E "provisioner|name:|volumeBindingMode|reclaimPolicy" "$OUT/storageclass-saw-hostpath.yaml"

echo "### HPP CR (hostpath provisioner) if present"
oc get hostpathprovisioner -o name 2>&1 | head
oc get hostpathprovisioner -o yaml 2>/dev/null | clean > "$OUT/hostpath-provisioner.yaml" 2>/dev/null || true

echo "### Pattern CR -> $OUT/pattern-cr.yaml"
oc get pattern -A -o yaml 2>/dev/null | clean > "$OUT/pattern-cr.yaml" && grep -E "name:|clusterGroupName|targetRepo|targetRevision" "$OUT/pattern-cr.yaml" | head

echo "### webhook (service-CA) state for patterns-operator"
oc get validatingwebhookconfiguration -o name 2>&1 | grep -i pattern
oc get svc -n openshift-operators 2>&1 | grep -i patterns

echo; echo "=== wrote: ==="; ls -la "$OUT"
