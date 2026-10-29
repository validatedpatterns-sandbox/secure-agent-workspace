#!/usr/bin/env bash
# Source before installing an EXIT trap or sending registry credentials.
saw_registry_tls_init() {
  local registry="$1" ca explicit="${REGISTRY_CA_BUNDLE:-}"
  REGISTRY_TLS_DIR="$(mktemp -d)" || return
  trap 'rm -f -- "${REGISTRY_TLS_DIR}/ca.pem" "${REGISTRY_TLS_DIR}/service-ca.pem" "${REGISTRY_TLS_DIR}/mirror.log"; rmdir -- "${REGISTRY_TLS_DIR}"' EXIT

  if [[ -z "${explicit}" && "${registry}" == image-registry.openshift-image-registry.svc:5000 ]]; then
    oc get cm openshift-service-ca.crt -n openshift-image-registry \
      -o jsonpath='{.data.service-ca\.crt}' > "${REGISTRY_TLS_DIR}/service-ca.pem" || return
    if [[ ! -s "${REGISTRY_TLS_DIR}/service-ca.pem" ]]; then
      echo 'Error: the image registry service CA is empty.' >&2
      return 1
    fi
    explicit="${REGISTRY_TLS_DIR}/service-ca.pem"
  fi
  # oc image mirror replaces its roots when given a CA file, so SAW_CA_COMBINE
  # keeps the public CAs in the bundle too.
  ca="$(OIDC_CA_BUNDLE="${explicit}" SAW_CA_COMBINE=1 python3 \
    "$(dirname "${BASH_SOURCE[0]}")/../cli/src/openshell_saw/tls.py" \
    "https://${registry}" "${REGISTRY_TLS_DIR}/ca.pem")" || return
  REGISTRY_TLS_OPTS=()
  if [[ -n "${ca}" ]]; then
    export SSL_CERT_FILE="${ca}"
    REGISTRY_TLS_OPTS=(--certificate-authority "${ca}")
  fi
}
