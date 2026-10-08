#!/usr/bin/env bash
# Mirror images from quay.io to the internal registry using in-cluster skopeo Jobs.
# Use this on macOS where podman-machine TCP connections drop mid-upload for large layers.
set -euo pipefail

BUILD_NS="${BUILD_NS:-openshell-agents}"
QUAY_REPO="${QUAY_REPO:-quay.io/rh-ai-quickstart}"
VERSION="${OPENSHELL_VERSION:-v0.0.116}"
# Only the gateway VM disk image is needed in the cluster (golden image);
# sandbox and NemoClaw CLI images are pulled from quay by the VM itself.
IMAGES="${IMAGES:-openshell-gateway}"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Setting up image-mirror ServiceAccount..."
oc apply -n "${BUILD_NS}" -f "${SCRIPTS_DIR}/mirror-images-rbac.yaml"
# nonroot SCC (not anyuid) is sufficient: HOME and XDG_RUNTIME_DIR are redirected
# to /tmp in the Job spec so skopeo never touches /run/containers (the root-only
# path that previously forced anyuid). The namespace's restricted PodSecurity still
# blocks root; nonroot overrides it for this SA without granting broader privileges.
oc adm policy add-scc-to-user nonroot -z image-mirror -n "${BUILD_NS}"

for IMAGE in ${IMAGES}; do
  export IMAGE BUILD_NS QUAY_REPO VERSION
  echo "Mirroring ${IMAGE}:${VERSION}..."
  oc delete job "mirror-${IMAGE}" -n "${BUILD_NS}" --ignore-not-found=true
  # Only substitute template vars; leave runtime shell vars (e.g. ${TOKEN}) intact
  # shellcheck disable=SC2016
  envsubst '${IMAGE} ${BUILD_NS} ${QUAY_REPO} ${VERSION}' \
    < "${SCRIPTS_DIR}/mirror-images-job.yaml" \
    | oc apply -n "${BUILD_NS}" -f -
  # `oc wait --for=condition=complete` would sit out its timeout on a failed Job.
  deadline=$(( $(date +%s) + 900 ))
  while :; do
    ok=$(oc get job "mirror-${IMAGE}" -n "${BUILD_NS}" -o jsonpath='{.status.succeeded}')
    bad=$(oc get job "mirror-${IMAGE}" -n "${BUILD_NS}" -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}')
    [[ "${ok}" == 1 ]] && break
    if [[ "${bad}" == True || $(date +%s) -gt ${deadline} ]]; then
      echo "ERROR: mirroring ${IMAGE} failed:"
      oc logs -n "${BUILD_NS}" "job/mirror-${IMAGE}" --tail=10 2>&1
      exit 1
    fi
    sleep 5
  done
  oc logs -n "${BUILD_NS}" "job/mirror-${IMAGE}" --tail=2
  oc tag "${BUILD_NS}/${IMAGE}:${VERSION}" "${BUILD_NS}/${IMAGE}:latest"
  echo "  ${IMAGE} done."
done

echo "All images mirrored (tag: ${VERSION}, also tagged as :latest)."
