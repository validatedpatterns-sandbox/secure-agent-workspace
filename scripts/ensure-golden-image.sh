#!/usr/bin/env bash
# Ensure the golden bootc image exists. Builds it if missing, waits for CDI import.
# Safe to re-run — picks up where it left off (running build, pending import, etc.)

set -euo pipefail

NS="${NS:-openshell-agents}"
HELM_DIR="${HELM_DIR:-image-builder-charts/helm}"

# Wait for the latest build to leave Pending/New, then follow logs and verify completion
follow_and_verify_build() {
  echo "Waiting for build to start..."
  local deadline=$((SECONDS + 300))
  while true; do
    local phase
    phase="$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
      --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].status.phase}' 2>/dev/null || true)"
    if [[ "${phase}" == "Running" ]]; then break; fi
    if [[ "${phase}" == "Complete" ]]; then echo "Build complete."; return 0; fi
    if [[ "${phase}" == "Failed" || "${phase}" == "Error" ]]; then echo "ERROR: Build ${phase}"; return 1; fi
    if (( SECONDS > deadline )); then echo "ERROR: Build stuck in ${phase:-unknown}"; return 1; fi
    sleep 5
  done
  echo "Following build logs..."
  oc logs -f "bc/openshell-gateway" -n "${NS}" 2>/dev/null || true
  for _ in $(seq 1 12); do
    local phase
    phase="$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
      --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].status.phase}' 2>/dev/null || true)"
    if [[ "${phase}" == "Complete" ]]; then echo "Build complete."; return 0; fi
    if [[ "${phase}" == "Failed" || "${phase}" == "Error" ]]; then echo "ERROR: Build ${phase}"; return 1; fi
    sleep 5
  done
  echo "ERROR: Build did not complete"
  return 1
}

# Ensure the internal image registry has an external route
if ! oc get route default-route -n openshift-image-registry >/dev/null 2>&1; then
  echo "Enabling external image registry route..."
  oc patch configs.imageregistry.operator.openshift.io/cluster \
    --patch '{"spec":{"defaultRoute":true}}' --type=merge 2>/dev/null
  sleep 10
fi

# Check if CDI CRDs are available (requires OpenShift Virtualization / CNV)
CDI_AVAILABLE=true
if ! oc api-resources --api-group=cdi.kubevirt.io 2>/dev/null | grep datavolumes >/dev/null 2>&1; then
  CDI_AVAILABLE=false
  echo "WARNING: CDI CRDs not available (OpenShift Virtualization not installed yet)."
  echo "  Will build the container image only. Golden image import will happen"
  echo "  after OpenShift Virtualization is installed (re-run this or let ArgoCD sync)."
fi

echo "=== Checking golden image in namespace '${NS}' ==="

HELM_GOLDEN_FLAG=""
if [[ "${CDI_AVAILABLE}" == "false" ]]; then
  HELM_GOLDEN_FLAG="--set goldenImage.enabled=false"
fi

# 1. Already ready?
if [[ "${CDI_AVAILABLE}" == "true" ]]; then
  DV_PHASE=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [[ "${DV_PHASE}" == "Succeeded" ]]; then
    echo "Golden image: ready"
    exit 0
  fi
fi

# 2. Build exists and running? Follow it.
BUILD_PHASE=$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
  --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].status.phase}' 2>/dev/null || true)

if [[ "${BUILD_PHASE}" == "Running" || "${BUILD_PHASE}" == "Pending" ]]; then
  BUILD_NAME=$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
    --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || true)
  echo "Build '${BUILD_NAME}' in progress (phase=${BUILD_PHASE})."
  follow_and_verify_build || exit 1

elif [[ "${BUILD_PHASE}" == "New" || "${BUILD_PHASE}" == "Failed" || "${BUILD_PHASE}" == "Error" || "${BUILD_PHASE}" == "Cancelled" ]]; then
  BUILD_NAME=$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
    --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || true)
  echo "Build '${BUILD_NAME}' is stale (phase=${BUILD_PHASE}). Cleaning up and restarting..."
  oc delete build "${BUILD_NAME}" -n "${NS}" 2>/dev/null || true
  sleep 2
  helm upgrade --install openshell-gateway-image "${HELM_DIR}/openshell-gateway-image" \
    --namespace "${NS}" --create-namespace ${HELM_GOLDEN_FLAG}
  oc start-build openshell-gateway -n "${NS}" 2>/dev/null || true
  follow_and_verify_build || exit 1

elif [[ "${BUILD_PHASE}" == "Complete" ]]; then
  echo "Build already complete. Checking golden image import..."
  # Ensure golden image resources exist (may have been deployed with goldenImage.enabled=false)
  if [[ "${CDI_AVAILABLE}" == "true" ]] && ! oc get datasource openshell-gateway -n "${NS}" >/dev/null 2>&1; then
    echo "  Golden image DataSource missing. Re-deploying chart with goldenImage enabled..."
    helm upgrade --install openshell-gateway-image "${HELM_DIR}/openshell-gateway-image" \
      --namespace "${NS}" --create-namespace --set goldenImage.enabled=true
  fi

else
  # 3. No build — start from scratch
  echo "Golden image: not found. Building bootc image..."

  # Create namespace if needed
  oc create namespace "${NS}" --dry-run=client -o yaml | oc apply -f - 2>/dev/null

  # Deploy BuildConfig + ImageStream (+ golden image DataVolume if CDI is available)
  echo "  Installing openshell-gateway-image chart..."
  helm upgrade --install openshell-gateway-image "${HELM_DIR}/openshell-gateway-image" \
    --namespace "${NS}" --create-namespace ${HELM_GOLDEN_FLAG}

  # Trigger build
  echo "  Starting build..."
  oc start-build openshell-gateway -n "${NS}" 2>/dev/null || true
  follow_and_verify_build || exit 1
fi

# 4. Wait for CDI golden image import (skip if CDI not available)
if [[ "${CDI_AVAILABLE}" == "false" ]]; then
  echo "Container image built. Golden image import deferred until OpenShift Virtualization is installed."
  echo "  Re-run 'make images-mirror' or 'make gateway-build' after CNV is ready."
  exit 0
fi

DV_PHASE=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [[ "${DV_PHASE}" == "Succeeded" ]]; then
  echo "Golden image: ready"
  exit 0
fi

echo "  Waiting for golden image CDI import..."
deadline=$((SECONDS + 600))
while true; do
  DV_PHASE=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  PROGRESS=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.progress}' 2>/dev/null || true)
  echo "    DV phase=${DV_PHASE:-pending} progress=${PROGRESS:-N/A}"

  if [[ "${DV_PHASE}" == "Succeeded" ]]; then
    echo "Golden image: ready"
    exit 0
  fi
  if [[ "${DV_PHASE}" == "Failed" ]]; then
    echo "  ERROR: Golden image import failed"
    exit 1
  fi
  if (( SECONDS > deadline )); then
    echo "  WARNING: Golden image import not complete yet. It will finish in the background."
    exit 0
  fi
  sleep 15
done
