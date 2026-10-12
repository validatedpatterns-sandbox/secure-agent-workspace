#!/usr/bin/env bash
# Verify that a second OIDC user cannot reach an existing SAW gateway.
set -euo pipefail

: "${TEST_SECOND_TOKEN_DIR:?Set TEST_SECOND_TOKEN_DIR}"
: "${TEST_OWNER_SUBJECT:?Set TEST_OWNER_SUBJECT}"
: "${TEST_ACTIVE_SAW_NAME:?Set TEST_ACTIVE_SAW_NAME}"
: "${TEST_ACTIVE_SAW_NS:?Set TEST_ACTIVE_SAW_NS}"

token_file="${TEST_SECOND_TOKEN_DIR}/token.json"
if [[ ! -f "${token_file}" ]]; then
  echo "Error: second-user token file is absent." >&2
  exit 1
fi
token="$(jq -er '.access_token | select(type == "string" and length > 0)' "${token_file}")"
payload="$(cut -d. -f2 <<<"${token}" | tr '_-' '/+')"
case $(( ${#payload} % 4 )) in
  2) payload+='==' ;;
  3) payload+='=' ;;
  0) ;;
  *) echo "Error: invalid second-user token format." >&2; exit 1 ;;
esac
claims="$(printf '%s' "${payload}" | openssl base64 -d -A)"
subject="$(jq -er '.sub | select(type == "string" and length > 0)' <<<"${claims}")"
if [[ "${subject}" == "${TEST_OWNER_SUBJECT}" ]]; then
  echo "Error: the second-user token belongs to the owner." >&2
  exit 1
fi
jq -e --argjson now "$(date +%s)" '.exp | type == "number" and . > $now' \
  <<<"${claims}" >/dev/null || { echo "Error: second-user token has expired." >&2; exit 1; }

route="$(oc get route "${TEST_ACTIVE_SAW_NAME}-gateway" \
  -n "${TEST_ACTIVE_SAW_NS}" -o json)"
host="$(jq -er '.spec.host | select(type == "string" and length > 0)' <<<"${route}")"
tls_options=(--insecure)
if [[ -n "${OIDC_CA_BUNDLE:-}" ]]; then
  tls_options=(--cacert "${OIDC_CA_BUNDLE}")
fi
status="$(curl -sS "${tls_options[@]}" --connect-timeout 5 --max-time 15 \
  --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer ${token}" "https://${host}/")"
if [[ "${status}" != 403 ]]; then
  echo "Error: second-user access returned HTTP ${status}; expected 403." >&2
  exit 1
fi
printf '{"result":"denied","status_code":403}\n'
