#!/usr/bin/env bash
# Import a bootc golden image from a container registry into a CDI DataSource.
# Subsequent VMs clone from this DataSource (fast CSI clone) instead of
# re-pulling from the registry each time.

set -euo pipefail

NS="${NS:-openshell-agents}"
GOLDEN_IMAGE_NAME="${GOLDEN_IMAGE_NAME:-openshell-gateway}"
GOLDEN_IMAGE_URL="${GOLDEN_IMAGE_URL:-docker://${IMAGE_REPO:-ghcr.io/validatedpatterns-sandbox}/${GOLDEN_IMAGE_NAME}:${IMAGE_TAG:-latest}}"
DISK_SIZE="${DISK_SIZE:-40Gi}"

echo "============================================="
echo " Import Golden Image"
echo "============================================="
echo "  Namespace:  ${NS}"
echo "  Name:       ${GOLDEN_IMAGE_NAME}"
echo "  Source:      ${GOLDEN_IMAGE_URL}"
echo "  Disk size:  ${DISK_SIZE}"
echo ""

# Check if DataVolume already exists and succeeded
EXISTING_PHASE=$(oc get dv "${GOLDEN_IMAGE_NAME}-golden" -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [[ "${EXISTING_PHASE}" == "Succeeded" ]]; then
  echo "Golden image '${GOLDEN_IMAGE_NAME}-golden' already exists and is ready."
  echo "  To reimport, delete it first:"
  echo "    oc delete dv ${GOLDEN_IMAGE_NAME}-golden -n ${NS}"
  echo "    oc delete datasource ${GOLDEN_IMAGE_NAME} -n ${NS}"
  exit 0
fi

# Delete any failed previous attempt
if [[ -n "${EXISTING_PHASE}" ]]; then
  echo "Cleaning up previous attempt (phase=${EXISTING_PHASE})..."
  oc delete dv "${GOLDEN_IMAGE_NAME}-golden" -n "${NS}" 2>/dev/null || true
  oc delete datasource "${GOLDEN_IMAGE_NAME}" -n "${NS}" 2>/dev/null || true
  sleep 5
fi

# Mirror image to internal registry so CDI can import with pullMethod: node
INTERNAL_REGISTRY="image-registry.openshift-image-registry.svc:5000"
INTERNAL_IMAGE="${INTERNAL_REGISTRY}/${NS}/${GOLDEN_IMAGE_NAME}:latest"

echo "Mirroring image to internal registry..."
oc image mirror \
  "${GOLDEN_IMAGE_URL#docker://}" \
  "${INTERNAL_IMAGE}" \
  --insecure=true 2>&1 | tail -3 || {
  echo "Mirror failed. Trying oc import-image..."
  oc import-image "${GOLDEN_IMAGE_NAME}:latest" \
    --from="${GOLDEN_IMAGE_URL#docker://}" \
    --confirm -n "${NS}" 2>&1 | tail -3
}

echo ""
echo "Creating DataVolume and DataSource..."

cat <<EOF | oc apply -f -
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataVolume
metadata:
  name: ${GOLDEN_IMAGE_NAME}-golden
  namespace: ${NS}
  annotations:
    cdi.kubevirt.io/storage.bind.immediate.requested: "true"
spec:
  source:
    registry:
      url: "docker://${INTERNAL_IMAGE}"
      pullMethod: node
  storage:
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: ${DISK_SIZE}
---
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataSource
metadata:
  name: ${GOLDEN_IMAGE_NAME}
  namespace: ${NS}
  labels:
    instancetype.kubevirt.io/default-instancetype: u1.medium
    instancetype.kubevirt.io/default-preference: fedora
spec:
  source:
    pvc:
      name: ${GOLDEN_IMAGE_NAME}-golden
      namespace: ${NS}
EOF

echo ""
echo "Waiting for import to complete (this may take 5-10 minutes)..."

deadline=$((SECONDS + 600))
while true; do
  phase=$(oc get dv "${GOLDEN_IMAGE_NAME}-golden" -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  progress=$(oc get dv "${GOLDEN_IMAGE_NAME}-golden" -n "${NS}" -o jsonpath='{.status.progress}' 2>/dev/null || echo "")
  echo "  phase=${phase:-pending} progress=${progress:-N/A}"

  if [[ "${phase}" == "Succeeded" ]]; then
    echo ""
    echo "Golden image imported successfully."
    echo "  DataVolume:  ${GOLDEN_IMAGE_NAME}-golden"
    echo "  DataSource:  ${GOLDEN_IMAGE_NAME}"
    echo ""
    echo "VMs can now clone from this DataSource for fast provisioning."
    exit 0
  fi

  if [[ "${phase}" == "Failed" ]]; then
    echo ""
    echo "ERROR: Import failed."
    oc get dv "${GOLDEN_IMAGE_NAME}-golden" -n "${NS}" -o yaml | grep -A3 "message:" || true
    exit 1
  fi

  if (( SECONDS > deadline )); then
    echo ""
    echo "ERROR: Import timed out after 10 minutes."
    exit 1
  fi

  sleep 15
done
