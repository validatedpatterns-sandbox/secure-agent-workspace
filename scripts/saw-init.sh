#!/usr/bin/env bash
# Prepare a cluster for SAW before `./pattern.sh make install` or `make saw-create`.
#
# Runs only what the configured users need. VM-only configurations stop after
# the default StorageClass check (storage-class-check, a make prerequisite).
# When any user in the saw-users values selects deployment.mode container or
# kata, it also checks:
#   - OVN-Kubernetes, AdminNetworkPolicy and ValidatingAdmissionPolicy;
#   - a shared-filesystem (ReadWriteMany) StorageClass, offering to create one
#     (scripts/shared-storage.sh);
#   - that the runtime image in containerDefaults can be pulled anonymously
#     from inside the cluster.
# Steps that need a running Keycloak (the relay registrar, the network overlay)
# come after install; see docs/container-installation.md.
#
# Env: SAW_USERS_VALUES_FILE (default overrides/saw-users.yaml),
#      SAW_CONTAINER_DEFAULTS_FILE (default overrides/saw-container-defaults.yaml),
#      SAW_INIT_NAMESPACE (namespace for the short-lived image check Pod, default),
#      SAW_INIT_SKIP_IMAGE_CHECK=1, SAW_STORAGE_ASSUME_YES=1 (unattended).
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
users_file="${SAW_USERS_VALUES_FILE:-${root}/overrides/saw-users.yaml}"
defaults_file="${SAW_CONTAINER_DEFAULTS_FILE:-${root}/overrides/saw-container-defaults.yaml}"
failed=0

ok() { echo "  ok    $*"; }
warn() { echo "  warn  $*" >&2; }
fail() { echo "  FAIL  $*" >&2; failed=1; }

# Users and the runtime image from the same files the pattern reads.
# SAW_USERS_VALUES_FILE may name either file (make container-topology reads the
# defaults file through it), so read users and defaults from all of them.
read -r container_users image < <(python3 - "$users_file" "${root}/overrides/saw-users.yaml" "$defaults_file" <<'EOF'
import sys, yaml
names, image, seen = [], "", set()
for path in sys.argv[1:]:
    if path in seen:
        continue
    seen.add(path)
    try:
        doc = yaml.safe_load(open(path)) or {}
    except FileNotFoundError:
        continue
    for u in doc.get("users") or []:
        mode = ((u.get("values") or {}).get("deployment") or {}).get("mode")
        if mode in ("container", "kata") and u.get("name") not in names:
            names.append(u.get("name", "?"))
    image = image or ((doc.get("containerDefaults") or {}).get("automaticEnrollment") or {}).get("image", "")
print(",".join(names) or "-", image or "-")
EOF
)

if [ "$container_users" = "-" ]; then
  echo "SAW init: no container or Kata users; nothing more to prepare."
  exit 0
fi
echo "SAW init: container workspaces for ${container_users//,/, }"

network="$(oc get network.config.openshift.io cluster -o jsonpath='{.status.networkType}' 2>/dev/null || true)"
[ "$network" = OVNKubernetes ] && ok "network: OVN-Kubernetes" \
  || fail "network type is '${network:-unknown}'; container mode needs OVN-Kubernetes"

version="$(oc get clusterversion version -o jsonpath='{.status.desired.version}' 2>/dev/null || true)"
if [ -n "$version" ] && printf '4.22\n%s\n' "${version%%-*}" | sort -V -C; then
  ok "OpenShift ${version}"
else
  warn "OpenShift ${version:-unknown}; container mode is qualified on 4.22 and later"
fi

oc get crd adminnetworkpolicies.policy.networking.k8s.io >/dev/null 2>&1 \
  && ok "AdminNetworkPolicy API" || fail "AdminNetworkPolicy API is missing (OVN-Kubernetes on OpenShift 4.14+)"
oc api-resources --api-group=admissionregistration.k8s.io -o name 2>/dev/null \
  | grep -q '^validatingadmissionpolicies' \
  && ok "ValidatingAdmissionPolicy API" || fail "ValidatingAdmissionPolicy API is missing"

if "${script_dir}/shared-storage.sh"; then :; else failed=1; fi

if [ "${SAW_INIT_SKIP_IMAGE_CHECK:-0}" = 1 ]; then
  warn "runtime image check skipped"
elif [ "$image" = "-" ] || [[ "$image" != *@sha256:* ]]; then
  fail "containerDefaults.automaticEnrollment.image must be a pinned image (…@sha256:…) in ${defaults_file#${root}/}"
else
  # Anonymous registry v2 handshake from a short-lived Pod: what the nodes see
  # without a pull secret for that registry.
  probe='img=$1; host=${img%%/*}; rest=${img#*/}; repo=${rest%@*}; ref=${rest#*@}
url="https://$host/v2/$repo/manifests/$ref"
A="Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "$A" "$url")
if [ "$code" = 401 ]; then
  h=$(curl -sI -H "$A" "$url" | tr -d "\r" | grep -i "^www-authenticate:")
  realm=$(echo "$h" | sed -n "s/.*realm=\"\([^\"]*\)\".*/\1/p")
  service=$(echo "$h" | sed -n "s/.*service=\"\([^\"]*\)\".*/\1/p")
  scope=$(echo "$h" | sed -n "s/.*scope=\"\([^\"]*\)\".*/\1/p")
  tok=$(curl -s "$realm?service=$service&scope=$scope" | sed -n "s/.*\"token\":\"\([^\"]*\)\".*/\1/p")
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "$A" -H "Authorization: Bearer $tok" "$url")
fi
echo "image-check:$code"'
  result="$(oc run "saw-init-image-check-$$" -n "${SAW_INIT_NAMESPACE:-default}" --rm -i --restart=Never \
      --image=registry.access.redhat.com/ubi9/ubi-minimal --command -- sh -c "$probe" sh "$image" 2>/dev/null \
    | sed -n 's/^image-check://p' | tail -n1)"
  case "$result" in
    200) ok "runtime image pullable from the cluster" ;;
    401|403) fail "runtime image is not anonymously pullable (HTTP ${result}): make the package public or add a pull secret: ${image}" ;;
    404) fail "runtime image not found: ${image}" ;;
    *) warn "could not check the runtime image from inside the cluster (${result:-no result}); set SAW_INIT_SKIP_IMAGE_CHECK=1 to skip" ;;
  esac
fi

echo
if [ "$failed" != 0 ]; then
  echo "SAW init: fix the items above, then run make saw-init again." >&2
  exit 1
fi
cat <<'EOF'
SAW init: the cluster is ready for container workspaces. After install, once Keycloak is up:
  - make keycloak-add-user KC_USER=<name>; make keycloak-user-info KC_USER=<name>  (ownerSubject)
  - make container-topology > overrides/container-network.yaml  (network overlay; commit it on
    your fork and list it after /overrides/saw-users.yaml in saw-users' extraValueFiles)
EOF
