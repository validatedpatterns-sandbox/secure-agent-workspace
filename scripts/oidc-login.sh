#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "${SCRIPT_DIR}/lib.sh" ]]; then
  source "${SCRIPT_DIR}/lib.sh"
fi

OIDC_ISSUER="${OIDC_ISSUER:-}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-openshell-cli}"
OIDC_FLOW="${OIDC_FLOW:-browser}"
OIDC_TOKEN_DIR="${OIDC_TOKEN_DIR:-${HOME}/.config/openshell/oidc}"
OIDC_TOKEN_FILE="${OIDC_TOKEN_DIR}/token.json"
OIDC_CALLBACK_PORT="${OIDC_CALLBACK_PORT:-8400}"
OIDC_CA_BUNDLE="${OIDC_CA_BUNDLE:-}"
NS="${NS:-openshell-agents}"

# TLS verification: use --cacert when OIDC_CA_BUNDLE is set, --insecure otherwise.
if [[ -n "${OIDC_CA_BUNDLE}" ]]; then
  CURL_TLS_OPTS="--cacert ${OIDC_CA_BUNDLE}"
else
  CURL_TLS_OPTS="--insecure"
fi

# --- Helper functions ---

die() { echo "Error: $*" >&2; exit 1; }

require_tools() {
  for cmd in curl jq openssl; do
    command -v "${cmd}" >/dev/null 2>&1 || die "${cmd} is required but not found"
  done
}

auto_detect_issuer() {
  if [[ -n "${OIDC_ISSUER}" ]]; then
    return
  fi
  if ! command -v oc >/dev/null 2>&1; then
    die "OIDC_ISSUER not set and 'oc' not found. Set OIDC_ISSUER or install the OpenShift CLI."
  fi
  local host
  host="$(oc get route openshell-keycloak -n "${NS}" -o jsonpath='{.spec.host}' 2>/dev/null || true)"
  if [[ -z "${host}" ]]; then
    die "OIDC_ISSUER not set and no Keycloak Route found in namespace ${NS}. Set OIDC_ISSUER or run 'make keycloak' first."
  fi
  OIDC_ISSUER="https://${host}/realms/openshell"
  echo "Auto-detected OIDC issuer: ${OIDC_ISSUER}"
}

discover_endpoints() {
  local well_known="${OIDC_ISSUER}/.well-known/openid-configuration"
  local config
  config="$(curl -fsSL ${CURL_TLS_OPTS} --connect-timeout 5 --max-time 10 "${well_known}" 2>/dev/null)" \
    || die "Failed to fetch OIDC discovery document from ${well_known}"

  AUTHORIZATION_ENDPOINT="$(echo "${config}" | jq -r '.authorization_endpoint // empty')"
  TOKEN_ENDPOINT="$(echo "${config}" | jq -r '.token_endpoint // empty')"
  DEVICE_AUTHORIZATION_ENDPOINT="$(echo "${config}" | jq -r '.device_authorization_endpoint // empty')"
  END_SESSION_ENDPOINT="$(echo "${config}" | jq -r '.end_session_endpoint // empty')"

  [[ -n "${TOKEN_ENDPOINT}" ]] || die "Token endpoint not found in discovery document"
}

base64url_encode() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

generate_pkce() {
  CODE_VERIFIER="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n' | cut -c1-128)"
  CODE_CHALLENGE="$(printf '%s' "${CODE_VERIFIER}" | openssl dgst -sha256 -binary | base64url_encode)"
}

# --- Browser flow (authorization code + PKCE) ---

do_browser_login() {
  [[ -n "${AUTHORIZATION_ENDPOINT}" ]] || die "Authorization endpoint not found"

  generate_pkce
  local state
  state="$(openssl rand -hex 16)"
  local redirect_uri="http://localhost:${OIDC_CALLBACK_PORT}/callback"

  local auth_url="${AUTHORIZATION_ENDPOINT}?response_type=code&client_id=${OIDC_CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${redirect_uri}'))")&scope=openid+email+profile&state=${state}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

  echo "Opening browser for authentication..."
  echo "If the browser does not open, visit:"
  echo "  ${auth_url}"
  echo ""

  if command -v open >/dev/null 2>&1; then
    open "${auth_url}" 2>/dev/null || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${auth_url}" 2>/dev/null || true
  fi

  echo "Waiting for callback on localhost:${OIDC_CALLBACK_PORT}..."
  local auth_code
  auth_code="$(python3 -c "
import http.server, urllib.parse, sys

code = None

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global code
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'code' in params:
            code = params['code'][0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h2>Login successful!</h2><p>You can close this tab and return to the terminal.</p></body></html>')
        else:
            error = params.get('error', ['unknown'])[0]
            desc = params.get('error_description', [''])[0]
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<html><body><h2>Login failed</h2><p>{error}: {desc}</p></body></html>'.encode())
    def log_message(self, *args):
        pass

server = http.server.HTTPServer(('127.0.0.1', ${OIDC_CALLBACK_PORT}), Handler)
server.handle_request()
server.server_close()
if code:
    print(code)
else:
    sys.exit(1)
" 2>/dev/null)" || die "Failed to receive authorization callback"

  [[ -n "${auth_code}" ]] || die "No authorization code received"

  local token_response
  token_response="$(curl -fsSL ${CURL_TLS_OPTS} --connect-timeout 5 --max-time 10 -X POST "${TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code" \
    -d "client_id=${OIDC_CLIENT_ID}" \
    -d "code=${auth_code}" \
    -d "redirect_uri=${redirect_uri}" \
    -d "code_verifier=${CODE_VERIFIER}" \
    2>/dev/null)" || die "Token exchange failed"

  save_token "${token_response}"
}

# --- Device code flow ---

do_device_login() {
  [[ -n "${DEVICE_AUTHORIZATION_ENDPOINT}" ]] || die "Device authorization endpoint not found. The OIDC provider may not support the device code flow. Try: OIDC_FLOW=browser"

  local device_response
  device_response="$(curl -fsSL ${CURL_TLS_OPTS} --connect-timeout 5 --max-time 10 -X POST "${DEVICE_AUTHORIZATION_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${OIDC_CLIENT_ID}" \
    -d "scope=openid email profile" \
    2>/dev/null)" || die "Device authorization request failed"

  local device_code user_code verification_uri interval
  device_code="$(echo "${device_response}" | jq -r '.device_code // empty')"
  user_code="$(echo "${device_response}" | jq -r '.user_code // empty')"
  verification_uri="$(echo "${device_response}" | jq -r '.verification_uri_complete // .verification_uri // empty')"
  interval="$(echo "${device_response}" | jq -r '.interval // 5')"

  [[ -n "${device_code}" ]] || die "No device code received"

  echo ""
  echo "To sign in, open this URL in a browser:"
  echo "  ${verification_uri}"
  if [[ -n "${user_code}" ]]; then
    echo ""
    echo "And enter the code: ${user_code}"
  fi
  echo ""
  echo "Waiting for authentication..."

  local deadline=$((SECONDS + 600))
  while (( SECONDS < deadline )); do
    sleep "${interval}"
    local token_response
    token_response="$(curl -fsSL ${CURL_TLS_OPTS} --connect-timeout 5 --max-time 10 -X POST "${TOKEN_ENDPOINT}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
      -d "client_id=${OIDC_CLIENT_ID}" \
      -d "device_code=${device_code}" \
      2>/dev/null)" || true

    local error
    error="$(echo "${token_response}" | jq -r '.error // empty' 2>/dev/null)"
    case "${error}" in
      authorization_pending) continue ;;
      slow_down) interval=$((interval + 5)); continue ;;
      "")
        save_token "${token_response}"
        return
        ;;
      *)
        local desc
        desc="$(echo "${token_response}" | jq -r '.error_description // empty' 2>/dev/null)"
        die "Authentication failed: ${error} -- ${desc}"
        ;;
    esac
  done
  die "Authentication timed out after 10 minutes"
}

# --- Token management ---

save_token() {
  local response="$1"
  local access_token
  access_token="$(echo "${response}" | jq -r '.access_token // empty')"
  [[ -n "${access_token}" ]] || die "No access_token in response"

  mkdir -p "${OIDC_TOKEN_DIR}"
  chmod 700 "${OIDC_TOKEN_DIR}"

  echo "${response}" | jq --arg issuer "${OIDC_ISSUER}" --arg ts "$(date +%s)" \
    '. + {issuer_url: $issuer, saved_at: ($ts | tonumber)}' \
    > "${OIDC_TOKEN_FILE}"
  chmod 600 "${OIDC_TOKEN_FILE}"

  local username
  username="$(decode_jwt_claim "preferred_username" 2>/dev/null || decode_jwt_claim "sub" 2>/dev/null || echo "unknown")"
  local expires_in
  expires_in="$(echo "${response}" | jq -r '.expires_in // 0')"
  echo ""
  echo "Logged in as: ${username}"
  echo "Token expires in: $((expires_in / 60)) minutes"
  echo "Token saved to: ${OIDC_TOKEN_FILE}"
}

is_token_valid() {
  [[ -f "${OIDC_TOKEN_FILE}" ]] || return 1
  local saved_at expires_in now
  saved_at="$(jq -r '.saved_at // 0' "${OIDC_TOKEN_FILE}")"
  expires_in="$(jq -r '.expires_in // 0' "${OIDC_TOKEN_FILE}")"
  now="$(date +%s)"
  (( saved_at + expires_in > now + 30 ))
}

do_refresh() {
  [[ -f "${OIDC_TOKEN_FILE}" ]] || die "No token file found. Run 'make login' first."

  local refresh_token
  refresh_token="$(jq -r '.refresh_token // empty' "${OIDC_TOKEN_FILE}")"
  [[ -n "${refresh_token}" ]] || die "No refresh token available. Run 'make login' again."

  local stored_issuer
  stored_issuer="$(jq -r '.issuer_url // empty' "${OIDC_TOKEN_FILE}")"
  if [[ -n "${stored_issuer}" && -z "${OIDC_ISSUER}" ]]; then
    OIDC_ISSUER="${stored_issuer}"
  fi
  discover_endpoints

  local token_response
  token_response="$(curl -fsSL ${CURL_TLS_OPTS} --connect-timeout 5 --max-time 10 -X POST "${TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token" \
    -d "client_id=${OIDC_CLIENT_ID}" \
    -d "refresh_token=${refresh_token}" \
    2>/dev/null)" || die "Token refresh failed. Run 'make login' again."

  local error
  error="$(echo "${token_response}" | jq -r '.error // empty' 2>/dev/null)"
  if [[ -n "${error}" ]]; then
    die "Token refresh failed: ${error}. Run 'make login' again."
  fi

  save_token "${token_response}"
}

get_valid_token() {
  [[ -f "${OIDC_TOKEN_FILE}" ]] || die "Not authenticated. Run 'make login' first."

  if is_token_valid; then
    jq -r '.access_token' "${OIDC_TOKEN_FILE}"
    return
  fi

  do_refresh >&2
  jq -r '.access_token' "${OIDC_TOKEN_FILE}"
}

# --- JWT decode ---

decode_jwt_payload() {
  [[ -f "${OIDC_TOKEN_FILE}" ]] || die "No token file found."
  local token
  token="$(jq -r '.access_token // empty' "${OIDC_TOKEN_FILE}")"
  [[ -n "${token}" ]] || die "No access token in token file."
  local payload
  payload="$(echo "${token}" | cut -d. -f2)"
  local pad=$((4 - ${#payload} % 4))
  if (( pad < 4 )); then
    payload="${payload}$(printf '=%.0s' $(seq 1 $pad))"
  fi
  echo "${payload}" | tr '_-' '/+' | base64 -d 2>/dev/null
}

decode_jwt_claim() {
  decode_jwt_payload | jq -r ".${1} // empty"
}

# --- Actions ---

do_login() {
  require_tools
  auto_detect_issuer
  discover_endpoints

  case "${OIDC_FLOW}" in
    browser) do_browser_login ;;
    device-code|device) do_device_login ;;
    *) die "Unknown OIDC_FLOW: ${OIDC_FLOW}. Use 'browser' or 'device-code'." ;;
  esac
}

do_whoami() {
  [[ -f "${OIDC_TOKEN_FILE}" ]] || die "Not authenticated. Run 'make login' first."

  if ! is_token_valid; then
    echo "(token expired -- showing last known identity)"
  fi

  local payload
  payload="$(decode_jwt_payload)"

  echo "Identity:"
  echo "  Subject:    $(echo "${payload}" | jq -r '.sub // "n/a"')"
  echo "  Username:   $(echo "${payload}" | jq -r '.preferred_username // "n/a"')"
  echo "  Email:      $(echo "${payload}" | jq -r '.email // "n/a"')"
  echo "  Issuer:     $(echo "${payload}" | jq -r '.iss // "n/a"')"

  local roles
  roles="$(echo "${payload}" | jq -r '.realm_access.roles // [] | join(", ")' 2>/dev/null || echo "n/a")"
  echo "  Roles:      ${roles}"

  local exp
  exp="$(echo "${payload}" | jq -r '.exp // 0')"
  if (( exp > 0 )); then
    echo "  Expires:    $(date -r "${exp}" 2>/dev/null || date -d "@${exp}" 2>/dev/null || echo "${exp}")"
  fi

  if is_token_valid; then
    echo "  Status:     valid"
  else
    echo "  Status:     EXPIRED"
  fi
}

do_logout() {
  if [[ -f "${OIDC_TOKEN_FILE}" ]]; then
    local stored_issuer
    stored_issuer="$(jq -r '.issuer_url // empty' "${OIDC_TOKEN_FILE}")"
    local refresh_token
    refresh_token="$(jq -r '.refresh_token // empty' "${OIDC_TOKEN_FILE}")"

    if [[ -n "${stored_issuer}" && -n "${refresh_token}" ]]; then
      local end_session_ep=""
      end_session_ep="$(curl -fsSL ${CURL_TLS_OPTS} --connect-timeout 2 --max-time 3 \
        "${stored_issuer}/.well-known/openid-configuration" 2>/dev/null \
        | jq -r '.end_session_endpoint // empty' 2>/dev/null)" || true
      if [[ -n "${end_session_ep}" ]]; then
        curl -fsSL ${CURL_TLS_OPTS} --connect-timeout 2 --max-time 3 -X POST "${end_session_ep}" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -d "client_id=${OIDC_CLIENT_ID}" \
          -d "refresh_token=${refresh_token}" \
          2>/dev/null || true
      fi
    fi

    rm -f "${OIDC_TOKEN_FILE}"
    echo "Logged out. Token revoked and cleared."
  else
    echo "Not logged in."
  fi
}

do_token() {
  get_valid_token
}

# --- Main ---

ACTION="${1:-login}"
case "${ACTION}" in
  login)   do_login ;;
  whoami)  do_whoami ;;
  logout)  do_logout ;;
  refresh) do_refresh ;;
  token)   do_token ;;
  *)       die "Unknown action: ${ACTION}. Use: login, whoami, logout, refresh, token" ;;
esac
