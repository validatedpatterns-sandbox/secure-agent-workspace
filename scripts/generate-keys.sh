#!/usr/bin/env bash
# Generate SSH keypair for sandbox provisioning.
# Keys are stored outside the repository by default.

set -euo pipefail

KEY_FILE="${SSH_KEY_PATH:-${KEYS_DIR:-${HOME}/.generated-ssh-keys}/sandbox-ssh}"
VALUES_SECRET="${VALUES_SECRET:-${HOME}/values-secret.yaml}"
umask 077

if [[ -f "${KEY_FILE}" ]]; then
  echo "Private SSH key already exists at ${KEY_FILE}."
else
  mkdir -p "$(dirname "${KEY_FILE}")"
  ssh-keygen -t ed25519 -f "${KEY_FILE}" -N "" -C "openshell-sandbox"
  echo "Private SSH key generated at ${KEY_FILE}."
fi

if [[ ! -f "${KEY_FILE}.pub" ]]; then
  ssh-keygen -y -f "${KEY_FILE}" > "${KEY_FILE}.pub"
  echo "Public SSH key recovered at ${KEY_FILE}.pub."
fi

if [[ ! -f "${VALUES_SECRET}" && -f "values-secret.yaml.template" ]]; then
  cp values-secret.yaml.template "${VALUES_SECRET}"
  echo "Created ${VALUES_SECRET} from the template."
fi

echo "SSH keys are ready. Existing keys and values files were preserved."
