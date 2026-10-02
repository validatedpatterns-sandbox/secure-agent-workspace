#!/usr/bin/env bash
# Let the self-service portal's pipeline write users' keys to Vault.
#
# Creates (idempotently) the Vault policy saw-portal-writer, which may write
# and delete only <kv>/data/<base>/saw-* and <kv>/metadata/<base>/saw-*, and
# the Kubernetes auth role saw-portal-writer bound to the portal's
# provisioner service account. Uses the pattern's Vault root token (secret
# vaultkeys in namespace imperative), passed to the Vault pod on stdin, not
# on a command line. The imperative job saw-portal-vault runs the same steps
# (ansible/playbooks/saw-portal-vault.yaml); this is for clusters without it.
#
#   scripts/portal-vault-setup.sh    (as a cluster admin, `oc` logged in)
set -euo pipefail
VAULT_NS="${VAULT_NS:-vault}"
VAULT_POD="${VAULT_POD:-vault-0}"
KEYS_NS="${KEYS_NS:-imperative}"
AUTH_MOUNT="${AUTH_MOUNT:-hub}"
KV_MOUNT="${KV_MOUNT:-secret}"
PREFIX_BASE="${PREFIX_BASE:-hub}"
ROLE="${ROLE:-saw-portal-writer}"
PORTAL_NS="${PORTAL_NS:-saw-portal}"
PORTAL_SA="${PORTAL_SA:-saw-portal-provisioner}"

root_token="$(oc get secret vaultkeys -n "${KEYS_NS}" -o jsonpath='{.data.vault_data_json}' \
  | base64 -d | python3 -c 'import json,sys; print(json.load(sys.stdin)["root_token"])')"
[[ -n "${root_token}" ]] || { echo "no root token in ${KEYS_NS}/vaultkeys" >&2; exit 1; }

oc exec -i -n "${VAULT_NS}" "${VAULT_POD}" -- sh -s <<SCRIPT
set -e
export VAULT_TOKEN='${root_token}'
vault policy write ${ROLE} - <<'POLICY'
path "${KV_MOUNT}/data/${PREFIX_BASE}/saw-*" {
  capabilities = ["create", "update", "read"]
}
path "${KV_MOUNT}/metadata/${PREFIX_BASE}/saw-*" {
  capabilities = ["read", "list", "delete"]
}
POLICY
vault write auth/${AUTH_MOUNT}/role/${ROLE} \
  bound_service_account_names=${PORTAL_SA} \
  bound_service_account_namespaces=${PORTAL_NS} \
  policies=${ROLE} ttl=15m
echo "Vault: policy and role ${ROLE} ready (auth/${AUTH_MOUNT}, ${KV_MOUNT}/data/${PREFIX_BASE}/saw-*)"
SCRIPT
