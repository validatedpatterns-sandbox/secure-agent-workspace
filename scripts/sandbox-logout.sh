#!/usr/bin/env bash
# Clear OIDC tokens from all running sandbox VMs.
# Called after oidc-login.sh logout to clean up gateway-side tokens.

set -euo pipefail

NS="${NS:-openshell-agents}"
SSH_KEY_PATH="${SSH_KEY_PATH:-.generated-ssh-keys/sandbox-ssh}"

echo "Clearing OIDC tokens from running sandboxes..."

helm list -n "${NS}" --filter '.*' -o json 2>/dev/null \
  | jq -r '.[] | select(.chart | startswith("openshell-sandbox")) | .name' 2>/dev/null \
  | while read -r sb; do
    echo -n "  ${sb}: clearing token... "
    if virtctl -n "${NS}" ssh "cloud-user@vm/${sb}" \
        --identity-file="${SSH_KEY_PATH}" \
        --local-ssh-opts="-oStrictHostKeyChecking=no" \
        --local-ssh-opts="-oUserKnownHostsFile=/dev/null" \
        --local-ssh-opts="-oConnectTimeout=5" \
        --command="sudo rm -f /etc/openshell/gateway.toml ~/.config/openshell/gateway.toml && sudo systemctl restart openshell-gateway-setup.service" \
        2>/dev/null; then
      echo "done"
    else
      echo "skipped (VM unreachable)"
    fi
  done

echo "Logout complete."
