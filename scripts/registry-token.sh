#!/usr/bin/env bash
set -euo pipefail

# Prepare credentials for pushing into the cluster's internal image registry and
# write them to ${REGISTRY_AUTH_FILE}, which `images-mirror.sh`'s `oc image mirror`
# then reads. Keeping this out of images-mirror.sh lets that script stay in sync
# with upstream (its only diff vs main is the removed `oc registry login` line).
#
# On macOS the mirror runs as an in-cluster skopeo Job (see images-mirror.sh's
# Darwin branch and mirror-images-rbac.yaml), which uses its own mounted SA token,
# so there is nothing to do here.
if [[ "$(uname -s)" == Darwin ]]; then
  echo "macOS: in-cluster mirror jobs manage their own auth; skipping registry-token."
  exit 0
fi

if [[ -z "${REGISTRY_AUTH_FILE:-}" ]]; then
  echo "Error: REGISTRY_AUTH_FILE must be set (exported by the Makefile)." >&2
  exit 1
fi

build_ns="${BUILD_NS:-openshell-agents}"

# This target runs before images-mirror.sh, so enable the registry default route
# here too (idempotent). images-mirror.sh repeats these for its own standalone use.
oc create namespace "${build_ns}" --dry-run=client -o yaml | oc apply -f -
oc patch configs.imageregistry.operator.openshift.io/cluster \
  --patch '{"spec":{"defaultRoute":true}}' --type=merge >/dev/null

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

# A bearer-token kubeconfig (e.g. `oc login` with user/password) already has a
# usable token. A client-cert kubeconfig does not, and there is no way to mint one
# for a cert identity (TokenRequest only issues ServiceAccount tokens), so create
# an SA and request a token for it. The SA is created only when needed.
token="$(oc whoami -t 2>/dev/null || true)"
if [[ -z "${token}" ]]; then
  oc create serviceaccount image-mirror -n "${build_ns}" \
    --dry-run=client -o yaml | oc apply -f -
  oc policy add-role-to-user system:image-builder \
    "system:serviceaccount:${build_ns}:image-mirror" -n "${build_ns}" >/dev/null
  token="$(oc create token image-mirror -n "${build_ns}" --duration=60m)"
fi

# Write the auth file ourselves via `oc registry login --auth-basic`: passing
# explicit credentials avoids the client-cert error of a bare `oc registry login`,
# and --to lets us target a writable path (the default /run/containers is not
# writable inside the utility container). The internal registry accepts basic auth
# of the form <user>:<token>.
mkdir -p "$(dirname "${REGISTRY_AUTH_FILE}")"
oc registry login --registry="${registry}" \
  --auth-basic="registry-user:${token}" \
  --to="${REGISTRY_AUTH_FILE}" --insecure=true --skip-check
echo "Wrote registry credentials for ${registry} to ${REGISTRY_AUTH_FILE}."
