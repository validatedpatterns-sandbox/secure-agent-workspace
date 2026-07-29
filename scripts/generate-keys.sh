#!/usr/bin/env bash
# Generate a dedicated SSH keypair for sandbox provisioning.

set -euo pipefail

KEYS_DIR="${KEYS_DIR:-.generated-ssh-keys}"
KEY_FILE="${KEYS_DIR}/sandbox-ssh"

if [[ -f "${KEY_FILE}" ]]; then
  echo "SSH keypair already exists at ${KEY_FILE}"
  echo "  Public key:  ${KEY_FILE}.pub"
  echo "  Private key: ${KEY_FILE}"
  echo "To regenerate, delete the existing key first: rm ${KEY_FILE}*"
  exit 0
fi

mkdir -p "${KEYS_DIR}"
ssh-keygen -t ed25519 -f "${KEY_FILE}" -N "" -C "openshell-sandbox"

echo ""
echo "SSH keypair generated:"
echo "  Public key:  ${KEY_FILE}.pub"
echo "  Private key: ${KEY_FILE}"
echo ""
echo "For validated pattern flow, add both keys to ~/values-secret.yaml:"
echo "  - name: ssh"
echo "    fields:"
echo "    - name: private_key"
echo "      value: |"
sed 's/^/        /' "${KEY_FILE}"
echo ""
echo "    - name: public_key"
echo "      value: $(cat "${KEY_FILE}.pub")"
echo ""
echo "For quickstart flow, keys are used automatically by make targets."
