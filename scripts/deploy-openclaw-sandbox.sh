#!/usr/bin/env bash
# shellcheck disable=SC2016 # Single-quoted commands expand on the remote VM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${NS:-$(oc project -q 2>/dev/null || true)}"
AGENT_VM="${AGENT_VM:-saw-agent}"
VIRTCTL="${VIRTCTL:-virtctl}"
SSH_KEY_PATH="${SSH_KEY_PATH:-${HOME}/.generated-ssh-keys/sandbox-ssh}"
OPENCLAW_IMAGE="${OPENCLAW_IMAGE:-quay.io/sallyom/openclaw-openshell@sha256:fcd2a6b618293a4fc62c158cc2e7113e93d8d592addc5470ad75e586116cf592}"

if [[ -z "${NS}" ]]; then
  echo "No OpenShift namespace selected. Set NS or run 'oc project <namespace>'." >&2
  exit 1
fi

if [[ ! "${NS}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "Namespace is not a valid DNS label: ${NS}" >&2
  exit 1
fi

if [[ ! -x "${VIRTCTL}" ]] && ! command -v "${VIRTCTL}" >/dev/null 2>&1; then
  echo "virtctl not found: ${VIRTCTL}" >&2
  exit 1
fi

if [[ ! -f "${SSH_KEY_PATH}" ]]; then
  echo "SSH private key not found: ${SSH_KEY_PATH}" >&2
  exit 1
fi

ssh_agent() {
  "${VIRTCTL}" -n "${NS}" ssh "cloud-user@vm/${AGENT_VM}" \
    --identity-file="${SSH_KEY_PATH}" \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
    --command="$*"
}

copy_to_agent() {
  local source="$1"
  local destination="$2"
  local encoded
  encoded="$(base64 < "${source}" | tr -d '\n')"
  ssh_agent "umask 077; printf '%s' '${encoded}' | base64 -d > '${destination}'"
}

oc whoami >/dev/null
oc get vm "${AGENT_VM}" -n "${NS}" >/dev/null

if ssh_agent 'export PATH="$HOME/.local/bin:$PATH"; openshell sandbox get openclaw-csb >/dev/null 2>&1'; then
  echo "Sandbox openclaw-csb already exists; refusing to replace it implicitly." >&2
  exit 1
fi

profile_file="$(mktemp)"
trap 'rm -f "${profile_file}"' EXIT
sed "s/__NAMESPACE__/${NS}/g" \
  "${ROOT}/deploy/two-vm/gmail-read-proxy-provider.yaml.tmpl" > "${profile_file}"
copy_to_agent "${profile_file}" /tmp/gmail-read-proxy-provider.yaml
copy_to_agent "${ROOT}/deploy/two-vm/openclaw-policy.yaml" /tmp/openclaw-policy.yaml

ssh_agent 'set -eu; test -s /home/cloud-user/.config/secure-agent-workspace/inter-vm-bearer; export PATH="$HOME/.local/bin:$PATH"; if ! openshell provider profile export gmail-read-proxy >/dev/null 2>&1; then openshell provider profile lint -f /tmp/gmail-read-proxy-provider.yaml; openshell provider profile import -f /tmp/gmail-read-proxy-provider.yaml; fi; if ! openshell provider get gmail-read-proxy >/dev/null 2>&1; then GOG_ACCESS_TOKEN=$(cat /home/cloud-user/.config/secure-agent-workspace/inter-vm-bearer); export GOG_ACCESS_TOKEN; openshell provider create --name gmail-read-proxy --type gmail-read-proxy --credential GOG_ACCESS_TOKEN; unset GOG_ACCESS_TOKEN; fi; openshell settings set --global --key providers_v2_enabled --value true --yes'

echo "Preparing the pinned OpenClaw image and persistent volume on ${AGENT_VM}."
ssh_agent "set -eu; podman volume create --ignore openclaw-csb-data >/dev/null; podman run --rm --user 0 --entrypoint /bin/sh -v openclaw-csb-data:/data '${OPENCLAW_IMAGE}' -c 'chmod 0777 /data'; token_dir=/home/cloud-user/.config/secure-agent-workspace; token_file=\${token_dir}/openclaw-gateway-token; install -d -m 700 \"\${token_dir}\"; if ! test -s \"\${token_file}\"; then umask 077; openssl rand -hex 32 | tr -d '\n' > \"\${token_file}\"; fi; chmod 600 \"\${token_file}\""

ssh_agent "set -eu; export PATH=\"\$HOME/.local/bin:\$PATH\"; gateway_token=\$(cat /home/cloud-user/.config/secure-agent-workspace/openclaw-gateway-token); openshell sandbox create --name openclaw-csb --from '${OPENCLAW_IMAGE}' --cpu 2 --memory 4Gi --policy /tmp/openclaw-policy.yaml --provider gmail-read-proxy --driver-config-json '{\"podman\":{\"mounts\":[{\"type\":\"volume\",\"source\":\"openclaw-csb-data\",\"target\":\"/sandbox/persist\",\"read_only\":false}]}}' --env \"OPENCLAW_GATEWAY_TOKEN=\${gateway_token}\" --env OPENCLAW_STATE_DIR=/sandbox/persist/.openclaw --env OPENCLAW_WORKSPACE_DIR=/sandbox/persist/workspace --env OPENCLAW_WIDGET_PORT=18790 --env 'GOG_GMAIL_BASE_URL=http://saw-integrations-gateway.${NS}.svc.cluster.local:18080/' --env GOG_READONLY=1 --env 'OPENCLAW_ALLOWED_PLUGINS=[\"openai\",\"codex\"]' --env OPENCLAW_DEFAULT_MODEL=openai/gpt-5.6-sol --env 'OPENCLAW_PROVIDERS={\"openai\":{\"api\":\"openai-responses\",\"baseUrl\":\"https://inference.local/v1\",\"apiKey\":\"unused\",\"models\":[{\"id\":\"gpt-5.6-sol\",\"name\":\"GPT-5.6 Sol\"}]}}' -- /bin/true"

ssh_agent 'export PATH="$HOME/.local/bin:$PATH"; openshell sandbox exec -n openclaw-csb --no-tty -- /bin/sh -lc "mkdir -p /sandbox/persist/workspace/skills; rm -rf /sandbox/persist/workspace/skills/gog; cp -R /app/skills/gog /sandbox/persist/workspace/skills; nohup /app/entrypoint.sh >/tmp/openclaw-gateway.log 2>&1 </dev/null &"'

sleep 5
ssh_agent 'export PATH="$HOME/.local/bin:$PATH"; openshell sandbox exec -n openclaw-csb --no-tty -- curl -fsS http://127.0.0.1:18789/healthz >/dev/null'
ssh_agent 'export PATH="$HOME/.local/bin:$PATH"; nohup openshell forward start -d 0.0.0.0:18789 openclaw-csb >/tmp/openclaw-ui-forward.log 2>&1 </dev/null &'
sleep 2
ssh_agent 'export PATH="$HOME/.local/bin:$PATH"; openshell forward list | grep -q "openclaw-csb.*18789.*running"'

echo "OpenClaw is ready at saw-agent-gateway.${NS}.svc.cluster.local:18789."
echo "OpenAI inference remains disabled until the Gateway A provider is configured."
