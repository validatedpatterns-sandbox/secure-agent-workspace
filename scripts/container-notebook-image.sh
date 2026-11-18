#!/usr/bin/env bash
# Publish the reviewed notebook image with a searchable /sandbox for namespace UIDs.
# stdout is a public values fragment; progress and build diagnostics go to stderr.
set -euo pipefail

: "${BUILD_NS:?set BUILD_NS to the component build namespace}"
arch="${BUILD_ARCH:-amd64}"
case "$arch" in amd64|arm64) ;; *) echo "BUILD_ARCH must be amd64 or arm64" >&2; exit 1 ;; esac
oc get namespace "$BUILD_NS" -o name >&2
source_image=$(uv run --locked python -c '
import yaml
from pathlib import Path
p = Path("charts/saw-bom/profiles/data-science/default/sandbox.yaml")
print(next(s["image"] for s in yaml.safe_load(p.read_text())["spec"]["sandboxes"] if s["name"] == "notebook"))')
if [[ ! "$source_image" =~ ^[a-z0-9][a-z0-9./:_-]+@sha256:([0-9a-f]{64})$ ]]; then
  echo "The notebook BOM must pin its source image by digest." >&2
  exit 1
fi
source_digest="${BASH_REMATCH[1]}"
stream="saw-openclaw-${source_digest:0:12}-$arch"
image_user=$(oc image info --filter-by-os="linux/$arch" "$source_image" -o json | jq -er '.config.config.User | select(type=="string" and length>0)')
if [[ ! "$image_user" =~ ^[a-zA-Z0-9_-]+(:[a-zA-Z0-9_-]+)?$ || "${image_user%%:*}" == root || "${image_user%%:*}" == 0 ]]; then
  echo "The notebook image must declare its non-root user." >&2
  exit 1
fi
helm template notebook-image image-builder-charts/helm/openshift-home-access \
  --namespace "$BUILD_NS" --set configChangeTrigger=false --set-string buildArchitecture="$arch" \
  --set-string "images[0].name=$stream" --set-string "images[0].from=$source_image" \
  --set-string "images[0].imageUser=$image_user" | oc -n "$BUILD_NS" apply -f - >&2
build=$(oc -n "$BUILD_NS" start-build "$stream" -o name)
echo "Building $build from $source_image ($arch)" >&2
oc -n "$BUILD_NS" wait --for=jsonpath='{.status.phase}'=Complete --timeout=30m "$build" >&2
digest=$(oc -n "$BUILD_NS" get "$build" -o json | jq -er '.status.output.to.imageDigest | select(test("^sha256:[a-f0-9]{64}$"))')
repository=$(oc -n "$BUILD_NS" get imagestream "$stream" -o json | jq -er '.status.dockerImageRepository | select(length>0)')
cat <<YAML
profileImageOverrides:
  data-science:
    notebook: "$repository@$digest"
imagePull:
  namespace: "$BUILD_NS"
  streams: ["$stream"]
YAML
