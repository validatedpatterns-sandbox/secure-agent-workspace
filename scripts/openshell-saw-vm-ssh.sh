#!/usr/bin/env bash
# SSH into a SAW gateway VM with dynamically provisioned keys.
#
# Adds your public key to the Secret the VM's accessCredentials point at,
# waits until KubeVirt's guest agent has written it into cloud-user's
# authorized_keys, then runs virtctl ssh. No VM restart needed.
# https://kubevirt.io/user-guide/user_workloads/accessing_virtual_machines/
#
# Usage: openshell-saw-vm-ssh.sh [--add-key-only] [command...]
# Env:   SAW_NS, VM_NAME (required), SSH_KEY_PATH (private key; .pub next to it),
#        CMD (command to run when none is given as arguments; make passes it
#        through the environment so it is never re-parsed by the local shell),
#        KEY_NAME (Secret key for your entry, default: your login name),
#        SYNC_TIMEOUT (seconds, default 120)
set -euo pipefail

SAW_NS="${SAW_NS:?SAW_NS is required}"
VM_NAME="${VM_NAME:?VM_NAME is required}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.generated-ssh-keys/sandbox-ssh}"
SYNC_TIMEOUT="${SYNC_TIMEOUT:-120}"
# Secret data keys allow [-._a-zA-Z0-9] only.
KEY_NAME="${KEY_NAME:-$(id -un | tr -c -- '-._a-zA-Z0-9\n' '-')}"

add_only=false
if [[ "${1:-}" == "--add-key-only" ]]; then add_only=true; shift; fi
if (( $# == 0 )) && [[ -n "${CMD:-}" ]]; then set -- "${CMD}"; fi

if [[ ! -f "${SSH_KEY_PATH}.pub" ]]; then
  echo "Error: no public key at ${SSH_KEY_PATH}.pub (make ssh-key-generate, or set SSH_KEY_PATH)" >&2
  exit 1
fi
pubkey="$(tr -d '\n' < "${SSH_KEY_PATH}.pub")"

secret="$(oc get vm "${VM_NAME}" -n "${SAW_NS}" \
  -o jsonpath='{.spec.template.spec.accessCredentials[0].sshPublicKey.source.secret.secretName}')"
if [[ -z "${secret}" ]]; then
  echo "Error: VM ${SAW_NS}/${VM_NAME} has no accessCredentials Secret (chart too old?)" >&2
  exit 1
fi

synced() {
  local output rc
  if output="$(oc get vmi "${VM_NAME}" -n "${SAW_NS}" \
      -o jsonpath='{.status.conditions[?(@.type=="AccessCredentialsSynchronized")].status}' 2>&1)"; then
    printf '%s' "${output}"
    return 0
  else
    rc=$?
  fi
  if [[ "${output}" == *NotFound* || "${output}" == *"not found"* ]]; then
    return 10
  fi
  printf '%s\n' "${output}" >&2
  return "${rc}"
}

secret_data="$(oc get secret "${secret}" -n "${SAW_NS}" -o json)"
current="$(jq -r --arg key "${KEY_NAME}" '.data[$key] // empty' <<<"${secret_data}")"
if [[ -n "${current}" && "$(printf '%s' "${current}" | base64 -d)" == "${pubkey}" ]]; then
  echo "Key '${KEY_NAME}' already in Secret ${secret}." >&2
else
  echo "Adding key '${KEY_NAME}' to Secret ${secret}..." >&2
  # stringData via a patch file keeps the key out of argv.
  patch="$(mktemp)"; trap 'rm -f "${patch}"' EXIT
  printf '{"stringData":{"%s":"%s"}}' "${KEY_NAME}" "${pubkey}" > "${patch}"
  oc patch secret "${secret}" -n "${SAW_NS}" --type merge --patch-file "${patch}" >/dev/null
  # Give KubeVirt a moment to notice the change before trusting the condition.
  sleep 5
fi

echo "Waiting for the guest agent to sync the key (AccessCredentialsSynchronized)..." >&2
deadline=$(( $(date +%s) + SYNC_TIMEOUT ))
while :; do
  if sync_state="$(synced)"; then
    if [[ "${sync_state}" == True ]]; then break; fi
  else
    rc=$?
    if (( rc != 10 )); then exit "${rc}"; fi
  fi
  if (( $(date +%s) > deadline )); then
    echo "Error: key not synced after ${SYNC_TIMEOUT}s:" >&2
    oc get vmi "${VM_NAME}" -n "${SAW_NS}" \
      -o jsonpath='{.status.conditions[?(@.type=="AccessCredentialsSynchronized")].message}{"\n"}' >&2
    echo "The VM needs a running qemu-guest-agent and the SELinux boolean virt_qemu_ga_manage_ssh=on." >&2
    exit 1
  fi
  sleep 3
done

ssh_args=(-n "${SAW_NS}" ssh "cloud-user@vm/${VM_NAME}" --identity-file="${SSH_KEY_PATH}"
  --local-ssh-opts=-oStrictHostKeyChecking=no --local-ssh-opts=-oUserKnownHostsFile=/dev/null
  --local-ssh-opts=-oLogLevel=ERROR)

# The condition can already be True from an earlier sync (a fresh VM's empty
# Secret counts as synced), so confirm the key is accepted before going on.
until virtctl "${ssh_args[@]}" --local-ssh-opts=-oBatchMode=yes \
    --local-ssh-opts=-oConnectTimeout=10 --command true </dev/null >/dev/null 2>&1; do
  if (( $(date +%s) > deadline )); then
    echo "Error: the VM does not accept the key yet after ${SYNC_TIMEOUT}s" >&2
    exit 1
  fi
  sleep 3
done
echo "Key synced." >&2
${add_only} && exit 0

if (( $# )); then
  # stdin closed: `openshell sandbox exec` in the command would otherwise wait
  # for EOF on the terminal before running anything.
  exec virtctl "${ssh_args[@]}" --command "$*" </dev/null
fi
exec virtctl "${ssh_args[@]}"
