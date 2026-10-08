#!/usr/bin/env bash
set -euo pipefail

name="${OPENSHELL_SAW_NAME:?OPENSHELL_SAW_NAME is required}"
namespace="${SAW_NS:-saw-${name}}"
keycloak_ns="${KEYCLOAK_NS:-saw-keycloak}"
realm="${KEYCLOAK_REALM:-openshell}"
client_id="${OIDC_CLIENT_ID:-openshell-cli}"
script_dir="$(cd "$(dirname "$0")" && pwd)"

command -v openshell >/dev/null || { echo "Error: openshell CLI is required." >&2; exit 1; }
host="$(oc get route "${name}-gateway" -n "${namespace}" -o jsonpath='{.spec.host}')"
[[ -n "${host}" ]] || { echo "Error: gateway route has no host." >&2; exit 1; }

issuer="${OIDC_ISSUER:-}"
if [[ -z "${issuer}" ]]; then
  keycloak_host="$("${script_dir}/keycloak-host.sh" "${keycloak_ns}")"
  issuer="https://${keycloak_host}/realms/${realm}"
fi

config_dir="${HOME}/.config/openshell/gateways/${name}"
NS="${namespace}" VM_NAME="${name}" \
  OUT_FILE="${config_dir}/mtls/ca.crt" "${script_dir}/extract-gateway-ca.sh"

if removal="$(openshell gateway remove "${name}" 2>&1)"; then
  :
elif [[ "${removal}" != *"not found"* && "${removal}" != *"does not exist"* &&
        "${removal}" != *"No gateway metadata found"* ]]; then
  echo "Error: could not replace the existing gateway configuration: ${removal}" >&2
  exit 1
fi
unset removal
gateway_args=("https://${host}" --name "${name}")
if [[ "${issuer}" != none ]]; then
  gateway_args+=(--oidc-issuer "${issuer}" --oidc-client-id "${client_id}")
fi
openshell gateway add "${gateway_args[@]}"
openshell gateway select "${name}"
echo "Gateway ${name} is configured at https://${host}."
