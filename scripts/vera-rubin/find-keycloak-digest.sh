#!/usr/bin/env bash
# Find the amd64 manifest digest for the Keycloak catalog backend module,
# to pin it as an arch-neutral OCI dynamic plugin on arm64.
set -uo pipefail
IMG=quay.io/rhdh/backstage-community-plugin-catalog-backend-module-keycloak
echo "=== candidate tags (2.2 / next / latest) for $IMG ==="
skopeo list-tags docker://$IMG 2>/dev/null \
  | python3 -c 'import sys,json
tags=json.load(sys.stdin)["Tags"]
cand=[t for t in tags if ("2.2" in t) or t in ("next","latest")]
print("\n".join(cand) if cand else "(no 2.2/next/latest tags; showing last 15)\n"+"\n".join(tags[-15:]))' 2>/dev/null \
  || echo "(skopeo list-tags failed)"
echo
echo "=== amd64 digest per candidate tag ==="
for TAG in $(skopeo list-tags docker://$IMG 2>/dev/null | python3 -c 'import sys,json;print(" ".join([t for t in json.load(sys.stdin)["Tags"] if ("2.2" in t) or t in ("next","latest")]))' 2>/dev/null); do
  echo "--- $TAG ---"
  RAW=$(skopeo inspect --raw docker://$IMG:$TAG 2>/dev/null)
  echo "$RAW" | python3 -c 'import sys,json
d=json.load(sys.stdin)
if "manifests" in d:
    for m in d["manifests"]:
        p=m.get("platform",{})
        if p.get("architecture")=="amd64" and p.get("os")=="linux":
            print("amd64 digest:", m["digest"])
else:
    print("(single-arch manifest; config-level inspect:)")' 2>/dev/null || echo "(inspect failed)"
done
echo
echo "=== plugin package name (from image config labels, for the !suffix) ==="
skopeo inspect docker://$IMG:latest 2>/dev/null | python3 -c 'import sys,json
d=json.load(sys.stdin)
labels=d.get("Labels",{}) or {}
for k,v in labels.items():
    if "name" in k.lower() or "plugin" in k.lower(): print(k,"=",v)' 2>/dev/null || echo "(no labels / latest missing)"
