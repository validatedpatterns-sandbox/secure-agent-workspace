#!/usr/bin/env bash
set -euo pipefail

build_ns="${BUILD_NS:-openshell-agents}"
repo="${IMAGE_REPO:-ghcr.io/validatedpatterns-sandbox}"
version="${IMAGE_TAG:-latest}"
images="${MIRROR_IMAGES:-openshell-gateway}"
script_dir="$(cd "$(dirname "$0")" && pwd)"

oc create namespace "${build_ns}" --dry-run=client -o yaml | oc apply -f -
oc patch configs.imageregistry.operator.openshift.io/cluster \
  --patch '{"spec":{"defaultRoute":true}}' --type=merge >/dev/null

if [[ "$(uname -s)" == Darwin ]]; then
  echo "Using in-cluster image mirror jobs."
  IMAGES="${images}" "${script_dir}/mirror-images-incluster.sh"
  exit
fi

registry=""
for ((i=1; i<=30; i++)); do
  registry="$(oc get routes -n openshift-image-registry -o json |
    jq -r '.items[] | select(.metadata.name == "default-route") | .spec.host')"
  [[ -n "${registry}" ]] && break
  sleep 5
done
if [[ -z "${registry}" ]]; then
  echo "Error: image registry route did not become available." >&2
  exit 1
fi

log="$(mktemp)"
trap 'rm -f "${log}"' EXIT
for image in ${images}; do
  if [[ ! "${image}" =~ ^[a-z0-9][a-z0-9._-]*$ ]]; then
    echo "Error: invalid image name: ${image}." >&2
    exit 1
  fi
  if ! oc image mirror "${repo}/${image}:${version}" \
    "${registry}/${build_ns}/${image}:${version}" \
    --insecure=true --keep-manifest-list=true >"${log}" 2>&1; then
    cat "${log}" >&2
    echo "Error: image mirror failed for ${repo}/${image}:${version}. Check the tag and registry access." >&2
    exit 1
  fi
  if [[ "${version}" != latest ]]; then
    oc tag "${build_ns}/${image}:${version}" "${build_ns}/${image}:latest"
    echo "Mirrored ${image}:${version} as ${image}:${version} and ${image}:latest."
  else
    echo "Mirrored ${image}:${version} as ${image}:${version}."
  fi
done
