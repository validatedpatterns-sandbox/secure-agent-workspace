#!/usr/bin/env bash
# Mirror images from GHCR to the internal registry using in-cluster skopeo Jobs.
# Use this on macOS where podman-machine TCP connections drop mid-upload for large layers.
set -euo pipefail

BUILD_NS="${BUILD_NS:-openshell-agents}"
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/validatedpatterns-sandbox}"
VERSION="${IMAGE_TAG:-latest}"
# Only the gateway VM disk image is needed in the cluster (golden image);
# sandbox and NemoClaw CLI images are pulled from GHCR by the VM itself.
IMAGES="${IMAGES:-openshell-gateway}"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

source "${SCRIPTS_DIR}/lib/image-repo.sh"
validate_image_repo "$IMAGE_REPO"
[[ "$BUILD_NS" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#BUILD_NS} -le 63 ]] || { echo 'Error: invalid BUILD_NS.' >&2; exit 1; }
[[ "$VERSION" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ && ${#VERSION} -le 128 ]] || { echo 'Error: invalid IMAGE_TAG.' >&2; exit 1; }
read -r -a images <<< "${IMAGES//$'\n'/ }"
[[ ${#images[@]} -gt 0 ]] || { echo 'Error: IMAGES must name at least one image.' >&2; exit 1; }
for IMAGE in "${images[@]}"; do
  [[ "$IMAGE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#IMAGE} -le 56 ]] || { echo 'Error: invalid IMAGES entry (mirror Job names must fit 63 characters).' >&2; exit 1; }
done

echo "Setting up image-mirror ServiceAccount..."
oc apply -n "${BUILD_NS}" -f "${SCRIPTS_DIR}/mirror-images-rbac.yaml"
# nonroot SCC (not anyuid) is sufficient: HOME and XDG_RUNTIME_DIR are redirected
# to /tmp in the Job spec so skopeo never touches /run/containers (the root-only
# path that previously forced anyuid). The namespace's restricted PodSecurity still
# blocks root; nonroot overrides it for this SA without granting broader privileges.
oc adm policy add-scc-to-user nonroot -z image-mirror -n "${BUILD_NS}"

for IMAGE in "${images[@]}"; do
  export IMAGE BUILD_NS IMAGE_REPO VERSION
  echo "Mirroring ${IMAGE}:${VERSION}..."
  oc delete job "mirror-${IMAGE}" -n "${BUILD_NS}" --ignore-not-found=true
  # Only substitute template vars; leave runtime shell vars (e.g. ${TOKEN}) intact
  # shellcheck disable=SC2016
  envsubst '${IMAGE} ${BUILD_NS} ${IMAGE_REPO} ${VERSION}' \
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
  if [[ "${VERSION}" != latest ]]; then
    oc tag "${BUILD_NS}/${IMAGE}:${VERSION}" "${BUILD_NS}/${IMAGE}:latest"
    echo "Mirrored ${IMAGE}:${VERSION} as ${IMAGE}:${VERSION} and ${IMAGE}:latest."
  else
    echo "Mirrored ${IMAGE}:${VERSION} as ${IMAGE}:${VERSION}."
  fi
done

echo "All images mirrored (tag: ${VERSION})."
