#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="${ROOT}/charts/openshell-saw"
AGENT_VALUES="${ROOT}/deploy/two-vm/agent-values.yaml"
INTEGRATIONS_VALUES="${ROOT}/deploy/two-vm/integrations-values.yaml"
GMAIL_READ_NETWORK_POLICY="${ROOT}/deploy/two-vm/gmail-read-networkpolicy.yaml"
RUNBOOK="${ROOT}/docs/two-vm-gmail-read-poc.md"

agent_render="$(mktemp)"
integrations_render="$(mktemp)"
ssh_public_key="$(mktemp)"
trap 'rm -f "${agent_render}" "${integrations_render}" "${ssh_public_key}"' EXIT

printf '%s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest two-vm-test' > "${ssh_public_key}"

helm template saw-agent "${CHART}" --values "${AGENT_VALUES}" \
  --set source.dataSourceNamespace=openshell-agents \
  --set source.bootstrap=false \
  --set-file sshPublicKey="${ssh_public_key}" > "${agent_render}"
helm template saw-integrations "${CHART}" --values "${INTEGRATIONS_VALUES}" > "${integrations_render}"

grep -q 'Gateway-only setup complete' "${agent_render}"
grep -q 'golden-image bootstrap is disabled' "${agent_render}"
grep -q 'Gateway-only setup complete' "${integrations_render}"
grep -q 'name: gmail-read' "${integrations_render}"
grep -q 'port: 18080' "${integrations_render}"
grep -q 'name: saw-integrations-ingress' "${GMAIL_READ_NETWORK_POLICY}"
grep -q 'app.kubernetes.io/name: saw-agent' "${GMAIL_READ_NETWORK_POLICY}"
grep -q 'port: 18080' "${GMAIL_READ_NETWORK_POLICY}"
grep -q 'port: 22' "${GMAIL_READ_NETWORK_POLICY}"

bash -n "${ROOT}/scripts/deploy-gmail-read-proxy.sh"
bash -n "${ROOT}/scripts/deploy-openclaw-sandbox.sh"

grep -q 'export NS=secure-agent-workspace-poc' "${RUNBOOK}"
grep -q 'export LOCAL_UI_PORT=28789' "${RUNBOOK}"
if grep -q 'sallyom-saw' "${RUNBOOK}"; then
  echo "two-VM runbook must not use a personal namespace" >&2
  exit 1
fi

if grep -q '^kind: Route$' "${agent_render}" || grep -q '^kind: Route$' "${integrations_render}"; then
  echo "gateway-only POC must not render external Routes" >&2
  exit 1
fi

helm lint "${CHART}" --values "${AGENT_VALUES}"
helm lint "${CHART}" --values "${INTEGRATIONS_VALUES}"

echo "two-VM template tests passed"
