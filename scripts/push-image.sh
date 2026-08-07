#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${1:?Usage: push-image.sh <namespace> <image-name> <quay-repo>}"
IMAGE="${2:?}"
QUAY_REPO="${3:?}"

# Ensure the default image-registry route exists
oc patch configs.imageregistry.operator.openshift.io/cluster \
  --patch '{"spec":{"defaultRoute":true}}' --type=merge >/dev/null 2>&1 || true

REGISTRY=""
for i in $(seq 1 30); do
  REGISTRY=$(oc get route default-route -n openshift-image-registry \
    -o jsonpath='{.spec.host}' 2>/dev/null)
  if [ -n "$REGISTRY" ]; then break; fi
  echo "  Waiting for image registry route... ($i/30)"
  sleep 5
done

if [ -z "$REGISTRY" ]; then
  echo "Error: Image registry route not available after waiting." >&2
  exit 1
fi

# Authenticate to the internal registry using the current user's token
oc registry login --registry="${REGISTRY}" --insecure=true

# Verify quay.io authentication before mirroring
if ! podman login --get-login "${QUAY_REPO%%/*}" >/dev/null 2>&1 && \
   ! docker login --get-login "${QUAY_REPO%%/*}" >/dev/null 2>&1; then
  echo "WARN: Not authenticated to ${QUAY_REPO%%/*} — run 'podman login ${QUAY_REPO%%/*}' first" >&2
fi

VERSION_TAG="${4:-}"

oc image mirror "${REGISTRY}/${NAMESPACE}/${IMAGE}:latest" \
  "${QUAY_REPO}/${IMAGE}:latest" --insecure=true

if [ -n "$VERSION_TAG" ]; then
  echo "  Tagging ${QUAY_REPO}/${IMAGE}:${VERSION_TAG}..."
  oc image mirror "${REGISTRY}/${NAMESPACE}/${IMAGE}:latest" \
    "${QUAY_REPO}/${IMAGE}:${VERSION_TAG}" --insecure=true
fi
