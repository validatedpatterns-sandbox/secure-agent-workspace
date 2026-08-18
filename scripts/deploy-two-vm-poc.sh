#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-$(oc project -q 2>/dev/null || true)}"
NS="${NS:-openshell-agents}"
SSH_KEY_PATH="${SSH_KEY_PATH:-${HOME}/.generated-ssh-keys/sandbox-ssh}"
DATA_SOURCE="${DATA_SOURCE:-openshell-gateway}"
DATA_SOURCE_NAMESPACE="${DATA_SOURCE_NAMESPACE:-${NS}}"
CHART="${CHART:-charts/openshell-saw}"

if [[ ! -f "${SSH_KEY_PATH}" || ! -f "${SSH_KEY_PATH}.pub" ]]; then
  echo "SSH keypair not found at ${SSH_KEY_PATH}[.pub]. Run 'make generate-keys' first." >&2
  exit 1
fi

oc whoami >/dev/null

if ! oc get datasource "${DATA_SOURCE}" -n "${DATA_SOURCE_NAMESPACE}" >/dev/null 2>&1; then
  echo "DataSource ${DATA_SOURCE_NAMESPACE}/${DATA_SOURCE} does not exist." >&2
  echo "Set DATA_SOURCE and DATA_SOURCE_NAMESPACE to a ready Podman golden image." >&2
  exit 1
fi

if [[ "${DATA_SOURCE_NAMESPACE}" != "${NS}" ]] && \
   [[ "$(oc auth can-i create datavolumes/source -n "${DATA_SOURCE_NAMESPACE}")" != "yes" ]]; then
  echo "Cross-namespace CDI clone permission is required in ${DATA_SOURCE_NAMESPACE}." >&2
  exit 1
fi

oc create namespace "${NS}" --dry-run=client -o yaml | oc apply -f -
oc -n "${NS}" create secret generic openshell-aap-ssh \
  --from-file=key="${SSH_KEY_PATH}" \
  --from-file=public_key="${SSH_KEY_PATH}.pub" \
  --dry-run=client -o yaml | oc apply -f -

common_args=(
  --namespace "${NS}"
  --set "source.dataSource=${DATA_SOURCE}"
  --set "source.dataSourceNamespace=${DATA_SOURCE_NAMESPACE}"
  --set-file "sshPublicKey=${SSH_KEY_PATH}.pub"
)

if [[ "${DATA_SOURCE_NAMESPACE}" != "${NS}" ]]; then
  common_args+=(--set "source.bootstrap=false")
fi

helm upgrade --install saw-agent "${CHART}" \
  --values deploy/two-vm/agent-values.yaml \
  "${common_args[@]}"

helm upgrade --install saw-integrations "${CHART}" \
  --values deploy/two-vm/integrations-values.yaml \
  "${common_args[@]}"

echo "Two gateway-only VMs submitted in namespace ${NS}."
echo "Golden image: ${DATA_SOURCE_NAMESPACE}/${DATA_SOURCE}"
echo "Wait for setup with:"
echo "  oc -n ${NS} wait --for=condition=complete job/saw-agent-setup job/saw-integrations-setup --timeout=30m"
echo "Then continue with docs/two-vm-gmail-read-poc.md."
