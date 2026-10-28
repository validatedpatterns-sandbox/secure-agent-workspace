#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${1:?Usage: push-image.sh <namespace> <image-name> <image-repo>}"
IMAGE="${2:?}"
IMAGE_REPO="${3:?}"
"$(dirname "$0")/check-build-repo.sh" "$IMAGE_REPO"

# Ensure the default image-registry route exists
oc patch configs.imageregistry.operator.openshift.io/cluster \
  --patch '{"spec":{"defaultRoute":true}}' --type=merge >/dev/null

REGISTRY=""
for i in $(seq 1 30); do
  REGISTRY=$(oc get routes -n openshift-image-registry -o json |
    jq -r '.items[] | select(.metadata.name == "default-route") | .spec.host')
  if [ -n "$REGISTRY" ]; then break; fi
  echo "  Waiting for image registry route... ($i/30)"
  sleep 5
done

if [ -z "$REGISTRY" ]; then
  echo "Error: Image registry route not available after waiting." >&2
  exit 1
fi

# Authenticate to the internal registry using the current user's token
source "$(dirname "$0")/registry-tls.sh"
saw_registry_tls_init "${REGISTRY}"
oc registry login --registry="${REGISTRY}"

# oc image mirror uses the current containers auth file. It reports any
# missing GHCR credentials with a nonzero exit status below.

VERSION_TAG="${4:-}"

oc image mirror "${REGISTRY}/${NAMESPACE}/${IMAGE}:latest" \
  "${IMAGE_REPO}/${IMAGE}:latest" "${REGISTRY_TLS_OPTS[@]}"

if [[ -n "$VERSION_TAG" && "$VERSION_TAG" != latest ]]; then
  echo "  Tagging ${IMAGE_REPO}/${IMAGE}:${VERSION_TAG}..."
  oc image mirror "${REGISTRY}/${NAMESPACE}/${IMAGE}:latest" \
    "${IMAGE_REPO}/${IMAGE}:${VERSION_TAG}" "${REGISTRY_TLS_OPTS[@]}"
fi
