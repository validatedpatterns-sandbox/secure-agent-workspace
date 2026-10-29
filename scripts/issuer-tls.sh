#!/usr/bin/env bash
# Source from a script with no EXIT trap; call before sending credentials.
SAW_TLS_DIR=""
saw_tls_check_url() {
  python3 "$(dirname "${BASH_SOURCE[0]}")/../cli/src/openshell_saw/tls.py" "$1"
}

saw_tls_init() {
  local url="$1" ca
  if [[ -z "${SAW_TLS_DIR:-}" ]]; then
    SAW_TLS_DIR="$(mktemp -d)" || return
    trap 'rm -f -- "${SAW_TLS_DIR}/ca.pem"; rmdir -- "${SAW_TLS_DIR}"' EXIT
  fi
  ca="$(python3 "$(dirname "${BASH_SOURCE[0]}")/../cli/src/openshell_saw/tls.py" \
    "${url}" "${SAW_TLS_DIR}/ca.pem")" || return
  CURL_TLS_OPTS=(--proto '=https' --proto-redir '=https' --max-redirs 0)
  if [[ -n "${ca}" ]]; then
    CURL_TLS_OPTS+=(--cacert "${ca}")
  fi
}
