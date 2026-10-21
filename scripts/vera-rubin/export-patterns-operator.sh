#!/usr/bin/env bash
# Export the live patterns-operator install (ns=patterns-operator) into clean,
# re-appliable manifests. CRD is dumped raw (big; re-applies fine); the rest is cleaned.
set -uo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
OUT=scripts/vera-rubin/manifests; mkdir -p "$OUT"
NS=patterns-operator
OC="oc --request-timeout=20s"

clean(){ python3 -c '
import sys,yaml
out=[]
for d in yaml.safe_load_all(sys.stdin):
    if not d: continue
    k=d.get("kind",""); m=d.get("metadata",{}) or {}
    for f in ("resourceVersion","uid","creationTimestamp","generation","managedFields","ownerReferences","selfLink"): m.pop(f,None)
    ann=m.get("annotations",{}) or {}
    for a in list(ann):
        if a.startswith("kubectl.kubernetes.io/last-applied") or "kopf.zalando" in a or a=="deployment.kubernetes.io/revision": ann.pop(a,None)
    if ann=={}: m.pop("annotations",None)
    if m.get("labels")=={}: m.pop("labels",None)
    d.pop("status",None); d["metadata"]=m
    sp=d.get("spec",{}) or {}
    if k=="Service":
        for f in ("clusterIP","clusterIPs","ipFamilies","ipFamilyPolicy","internalTrafficPolicy","sessionAffinity"): sp.pop(f,None)
    if k in ("ValidatingWebhookConfiguration","MutatingWebhookConfiguration"):
        for w in d.get("webhooks",[]) or []: w.get("clientConfig",{}).pop("caBundle",None)
    out.append(d)
print(yaml.safe_dump_all(out,default_flow_style=False,sort_keys=False))
'; }

echo "[1/4] CRD (raw) ..."
$OC get crd patterns.gitops.hybrid-cloud-patterns.io -o yaml > "$OUT/patterns-crd.yaml" 2>/dev/null && echo "  ok ($(wc -l < "$OUT/patterns-crd.yaml") lines)" || echo "  (crd get failed)"

echo "[2/4] namespaced resources ..."
tmp=$(mktemp)
for x in $($OC get serviceaccount,role,rolebinding,configmap,service,deployment -n $NS -o name 2>/dev/null | grep -iE "pattern"); do
  echo "    $x"; $OC get "$x" -n $NS -o yaml >> "$tmp" 2>/dev/null; echo "---" >> "$tmp"
done

echo "[3/4] cluster RBAC + webhooks ..."
for r in $($OC get clusterrole -o name 2>/dev/null | grep -iE "pattern"); do echo "    $r"; $OC get "$r" -o yaml >> "$tmp"; echo "---" >> "$tmp"; done
for b in $($OC get clusterrolebinding -o name 2>/dev/null | grep -iE "pattern"); do echo "    $b"; $OC get "$b" -o yaml >> "$tmp"; echo "---" >> "$tmp"; done
for w in $($OC get validatingwebhookconfiguration,mutatingwebhookconfiguration -o name 2>/dev/null | grep -iE "pattern"); do echo "    $w"; $OC get "$w" -o yaml >> "$tmp"; echo "---" >> "$tmp"; done

echo "[4/4] cleaning ..."
$OC get namespace $NS -o yaml 2>/dev/null | cat - "$tmp" | clean > "$OUT/patterns-operator-arm64.yaml"
rm -f "$tmp"

echo "=== images ==="; grep -E "image:" "$OUT/patterns-operator-arm64.yaml" | sort -u
echo "=== kinds ==="; grep -E "^kind:" "$OUT/patterns-operator-arm64.yaml" | sort | uniq -c
echo "=== service-CA annotations ==="; grep -E "service.beta.openshift.io|inject-cabundle|serving-cert" "$OUT/patterns-operator-arm64.yaml" | sort -u | head
echo "=== files ==="; ls -la "$OUT"
