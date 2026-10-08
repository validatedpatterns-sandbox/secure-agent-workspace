#!/usr/bin/env bash
set -euo pipefail

build_ns="${BUILD_NS:-openshell-agents}"
repo="${QUAY_REPO:-quay.io/rh-ai-quickstart}"
version="${OPENSHELL_VERSION:-0.0.116}"
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
oc registry login --registry="${registry}" --insecure=true >/dev/null

log="$(mktemp)"
trap 'rm -f "${log}"' EXIT
for image in ${images}; do
  if [[ ! "${image}" =~ ^[a-z0-9][a-z0-9._-]*$ ]]; then
    echo "Error: invalid image name: ${image}." >&2
    exit 1
  fi
  chosen=""
  for tag in "${version}" "v${version#v}" latest; do
    [[ "${tag}" == "${chosen}" ]] && continue
    if oc image mirror "${repo}/${image}:${tag}" \
      "${registry}/${build_ns}/${image}:${version}" --insecure=true >"${log}" 2>&1; then
      chosen="${tag}"
      break
    fi
    if ! grep -Eiq 'manifest unknown|not found|name unknown|does not exist' "${log}"; then
      echo "Error: image mirror failed for ${image}:${tag}. Check registry access and permissions." >&2
      exit 1
    fi
    echo "Tag ${image}:${tag} is absent. Trying the next tag."
  done
  if [[ -z "${chosen}" ]]; then
    echo "Error: no published tag was found for ${image}." >&2
    exit 1
  fi
  oc tag "${build_ns}/${image}:${version}" "${build_ns}/${image}:latest"
  echo "Mirrored ${image}:${chosen} as ${image}:${version} and ${image}:latest."
done
