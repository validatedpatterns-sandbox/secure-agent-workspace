#!/usr/bin/env bash
# Phase: verify governance interceptor is reachable and inject SSH key fallback.
# Expects: GOVERNANCE_ENABLED, GOVERNANCE_ENDPOINT, guest_ssh (function)

if [[ "${GOVERNANCE_ENABLED}" == "true" ]]; then
  echo "Checking governance interceptor at ${GOVERNANCE_ENDPOINT}..."
  INTERCEPTOR_READY=0
  for i in $(seq 1 12); do
    # NOTE: this used to be a single `A || B && C` condition. In bash, &&/||
    # have equal precedence and evaluate left-to-right, so that actually
    # meant (A || B) && C — even a directly-successful curl check (A) still
    # required the journalctl grep (C) to pass, or the whole setup Job would
    # exit 1 despite the interceptor being genuinely reachable. Split into
    # explicit branches instead.
    # The interceptor speaks gRPC — curl rejects the HTTP/0.9 response on
    # recent versions. Use a bash TCP socket check: if the port accepts
    # connections, the interceptor is up.
    _ep="${GOVERNANCE_ENDPOINT#*//}"   # strip scheme
    _ep="${_ep%%/*}"                   # strip path
    _ihost="${_ep%:*}"
    _iport="${_ep##*:}"
    if timeout 5 bash -c "</dev/tcp/${_ihost}/${_iport}" 2>/dev/null; then
      INTERCEPTOR_READY=1
      break
    fi
    echo "  waiting for interceptor... (attempt $i)"
    sleep 5
  done
  if [[ "${INTERCEPTOR_READY}" -ne 1 ]]; then
    echo "ERROR: governance interceptor is unreachable at ${GOVERNANCE_ENDPOINT}" >&2
    echo "ERROR: governance.enabled=true requires a running interceptor. Deploy governance-interceptor chart first." >&2
    exit 1
  fi
  echo "Governance interceptor is reachable."
fi

# --- SSH key fallback (cloud-init may not have injected it yet) ---
if [[ -f /ssh-key/public_key ]]; then
  SSH_PUB="$(cat /ssh-key/public_key)"
  if [[ -n "${SSH_PUB}" ]]; then
    guest_ssh "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${SSH_PUB}' >> ~/.ssh/authorized_keys && sort -u -o ~/.ssh/authorized_keys ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" || true
    echo "SSH public key injected into VM"
  fi
fi
