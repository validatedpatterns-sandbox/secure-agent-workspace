#!/usr/bin/env bash
# Build and publish SAW harness bundles as OCI images.
#
#   scripts/harness-bundle.sh build   <bundle>            # local image saw-harness-<bundle>:dev
#   scripts/harness-bundle.sh push    <bundle> <repo>     # push, print the digest-pinned ref
#   scripts/harness-bundle.sh ref     <bundle> <repo>     # digest-pinned ref of what is pushed
#
# A bundle is harness-bundles/<bundle>/ (harness.yaml, skills/, plugins/,
# mcp.json, plugin.json). The image is FROM scratch with the bundle tree at
# its root (harness-bundles/Containerfile); a sandbox mounts it read-only at
# /sandbox/harness. Reference the printed ref from a SAW-BOM sandbox:
#   harnessRef: { image: <repo>@sha256:<digest> }
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENGINE="${CONTAINER_ENGINE:-$(command -v podman || command -v docker || true)}"
[[ -n "$ENGINE" ]] || { echo "podman or docker is required" >&2; exit 1; }

cmd="${1:-}"; bundle="${2:-}"
[[ -n "$cmd" && -n "$bundle" ]] || { sed -n '2,12p' "$0" >&2; exit 2; }
dir="$ROOT/harness-bundles/$bundle"
[[ -f "$dir/harness.yaml" ]] || { echo "no harness bundle at $dir (harness.yaml missing)" >&2; exit 1; }
local_tag="saw-harness-$bundle:dev"

build() {
  COPYFILE_DISABLE=1 "$ENGINE" build -q -f "$ROOT/harness-bundles/Containerfile" -t "$local_tag" "$dir" >/dev/null
  echo "built $local_tag"
}

case "$cmd" in
  build)
    build ;;
  push)
    repo="${3:?push needs a repository, e.g. ghcr.io/<owner>/saw-harness-$bundle}"
    build
    version=$(sed -n 's/^ *version: *//p' "$dir/harness.yaml" | head -1)
    tag="$repo:${version:-dev}"
    "$ENGINE" tag "$local_tag" "$tag"
    digestfile=$(mktemp)
    if [[ "$(basename "$ENGINE")" == podman ]]; then
      podman push --digestfile "$digestfile" "$tag" >/dev/null
      digest=$(cat "$digestfile")
    else
      docker push "$tag" >/dev/null
      digest=$(docker inspect --format '{{index .RepoDigests 0}}' "$tag" | sed 's/.*@//')
    fi
    rm -f "$digestfile"
    echo "pushed $tag"
    echo "harnessRef:"
    echo "  image: $repo@$digest"
    ;;
  ref)
    repo="${3:?ref needs a repository}"
    version=$(sed -n 's/^ *version: *//p' "$dir/harness.yaml" | head -1)
    if command -v skopeo >/dev/null; then
      digest=$(skopeo inspect --format '{{.Digest}}' "docker://$repo:${version:-dev}")
    else
      digest=$("$ENGINE" manifest inspect "$repo:${version:-dev}" >/dev/null && \
               "$ENGINE" pull -q "$repo:${version:-dev}" >/dev/null && \
               "$ENGINE" inspect --format '{{index .RepoDigests 0}}' "$repo:${version:-dev}" | sed 's/.*@//')
    fi
    echo "$repo@$digest"
    ;;
  *)
    sed -n '2,12p' "$0" >&2; exit 2 ;;
esac
