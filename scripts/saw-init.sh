#!/usr/bin/env bash
# Prepare a cluster for SAW before `./pattern.sh make install` or `make saw-create`.
# Safe to run again. After the default StorageClass check (a make prerequisite):
#   - SSH keys and ~/values-secret.yaml (generate-keys.sh; never replaces a key);
#   - whether workspaces will trust the OIDC issuer (check-oidc-ca.sh);
#   - the gateway VM image in the internal registry (images-mirror.sh), when a
#     user is a VM user or no users are listed yet (the portal may create VMs);
#   - for container or Kata users: OVN-Kubernetes, AdminNetworkPolicy and
#     ValidatingAdmissionPolicy and a pullable runtime image; with auditReceipts,
#     also a shared-filesystem (ReadWriteMany) StorageClass (offers to create one);
#   - StorageClass saw-shared, a copy of the shared-filesystem class: the fixed
#     name the container charts use, so no class name goes into Git.
#
# Env: SAW_USERS_VALUES_FILE (default overrides/saw-users.yaml),
#      SAW_CONTAINER_DEFAULTS_FILE (default overrides/saw-container-defaults.yaml),
#      SAW_INIT_NAMESPACE (namespace for the short-lived image check Pod, default),
#      DEPLOYMENT_MODE=container|kata with OPENSHELL_SAW_NAME (quickstart),
#      SAW_INIT_SKIP_MIRROR=1, SAW_INIT_SKIP_IMAGE_CHECK=1,
#      SAW_STORAGE_ASSUME_YES=1 (unattended).
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
# SAW_USERS_VALUES_FILE may name either file, so read users and defaults from
# all of them.
read -r container_users vm_needed image receipts < <(python3 - "$users_file" "${root}/overrides/saw-users.yaml" "$defaults_file" <<'EOF'
import sys, yaml
names, image, seen, users, vm, receipts = [], "", set(), 0, False, False
for path in sys.argv[1:]:
    if path in seen:
        continue
    seen.add(path)
    try:
        doc = yaml.safe_load(open(path)) or {}
    except FileNotFoundError:
        continue
    for u in doc.get("users") or []:
        users += 1
        mode = ((u.get("values") or {}).get("deployment") or {}).get("mode")
        if mode in ("container", "kata"):
            if u.get("name") not in names:
                names.append(u.get("name", "?"))
        else:
            vm = True
    image = image or ((doc.get("containerDefaults") or {}).get("automaticEnrollment") or {}).get("image", "")
    sites = [doc.get("containerDefaults") or {}] + list((doc.get("containerSites") or {}).values())
    receipts = receipts or any(isinstance(s, dict) and s.get("auditReceipts") is True for s in sites)
print(",".join(names) or "-", "yes" if vm or not users else "no", image or "-", "yes" if receipts else "no")
EOF
)

# Quickstart (make saw-create) names its one user with DEPLOYMENT_MODE.
case "${DEPLOYMENT_MODE:-}" in
  container|kata)
    if [ "$container_users" = "-" ]; then
      container_users="${OPENSHELL_SAW_NAME:-${DEPLOYMENT_MODE}}"
      vm_needed=no
    fi ;;
esac

cd "$root"
"${script_dir}/generate-keys.sh" >/dev/null && ok "SSH keys and ~/values-secret.yaml" \
  || fail "could not create the SSH keys (scripts/generate-keys.sh)"

rc=0; oidc="$("${script_dir}/check-oidc-ca.sh" 2>&1)" || rc=$?
case "$rc" in
  0|3) ok "OIDC issuer certificate" ;;
  2) fail "workspaces will not trust the OIDC issuer; add oidc.caBundle:"; echo "$oidc" >&2 ;;
  *) warn "could not check the OIDC issuer certificate (make check-oidc-ca for details)" ;;
esac

if [ "$vm_needed" = no ]; then
  ok "gateway VM image not needed (container/Kata users only)"
elif [ "${SAW_INIT_SKIP_MIRROR:-0}" = 1 ]; then
  warn "gateway VM image mirror skipped (make images-mirror before VM workspaces)"
elif echo "  ...   mirroring the gateway VM image (a few minutes the first time)" && "${script_dir}/images-mirror.sh" >/dev/null; then
  ok "gateway VM image in the internal registry"
else
  fail "could not mirror the gateway VM image (make images-mirror for details)"
fi

if [ "$container_users" = "-" ]; then
  # Ready for container workspaces requested later (the portal), where the
  # cluster can already back them; silent otherwise.
  "${script_dir}/shared-storage.sh" --classes-only || true
  echo
  [ "$failed" = 0 ] || { echo "SAW init: fix the items above, then run make saw-init again." >&2; exit 1; }
  echo "SAW init: ready."
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

# A shared filesystem is only needed for signed audit receipts (auditReceipts).
if [ "$receipts" = yes ]; then
  if "${script_dir}/shared-storage.sh"; then :; else failed=1; fi
else
  "${script_dir}/shared-storage.sh" --classes-only || true
fi

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
echo "SAW init: ready. After install, see 'Add a user' in the README."
