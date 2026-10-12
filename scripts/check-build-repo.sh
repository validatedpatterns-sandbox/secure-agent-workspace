#!/usr/bin/env bash
# CI owns the upstream namespace; manual builds may publish only elsewhere.
set -euo pipefail
repo="${1:-}"
source "$(dirname "$0")/lib/image-repo.sh"
[[ -z "$repo" ]] && exit 0
normalized="$(printf '%s' "$repo" | tr '[:upper:]' '[:lower:]')"
registry="${normalized%%/*}"
namespace="${normalized#*/}"
normalized="${registry%%:*}/$namespace"
case "$normalized" in
  ghcr.io/validatedpatterns-sandbox|ghcr.io/validatedpatterns-sandbox/*)
    echo "Error: the upstream GHCR namespace is reserved for CI. Set IMAGE_REPO to your own namespace, or omit it to keep the build in-cluster." >&2
    exit 1
    ;;
esac
validate_image_repo "$repo"
