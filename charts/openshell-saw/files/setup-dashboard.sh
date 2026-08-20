#!/usr/bin/env bash
# Runs OpenShell Dashboard + oauth2-proxy inside the VM via the configured
# container runtime (docker or podman), managed as `systemctl --user` services.
# Requires OIDC to be configured on the gateway (the dashboard's gRPC client
# has no mTLS support).
set -euo pipefail

: "${RUNTIME:?RUNTIME not set — must be docker or podman}"

if [[ "${DASHBOARD_ENABLED:-false}" != "true" ]]; then
  echo "Dashboard disabled, skipping."
  exit 0
fi

if [[ -z "${OIDC_ISSUER:-}" ]]; then
  echo "Dashboard skipped: oidc.issuerUrl not configured (deploy Keycloak and set oidc.issuerUrl to enable)."
  exit 0
fi

: "${DASHBOARD_IMAGE:?}"
: "${DASHBOARD_PROXY_IMAGE:?}"
: "${DASHBOARD_COOKIE_SECRET:?}"
: "${DASHBOARD_REDIRECT_URL:?DASHBOARD_REDIRECT_URL not set — was the *-webui route created?}"
DASHBOARD_CLIENT_ID="${DASHBOARD_CLIENT_ID:-openshell-dashboard}"

mkdir -p "${HOME}/.config/systemd/user" "${HOME}/.config/openshell"

# Copy just the CA cert (public, not sensitive — never the private key) to a
# dedicated, world-readable location instead of exposing the whole TLS dir.
CA_SRC="${HOME}/.local/state/openshell/tls/ca.crt"
CA_FOR_DASHBOARD="${HOME}/.config/openshell/dashboard-gateway-ca.crt"
if [[ -f "${CA_SRC}" ]]; then
  install -m 0644 "${CA_SRC}" "${CA_FOR_DASHBOARD}"
else
  echo "WARN: gateway CA cert not found at ${CA_SRC}, dashboard gRPC connection will likely fail"
fi
chmod o+x "${HOME}" "${HOME}/.config" "${HOME}/.config/openshell" 2>/dev/null || true

cat > "${HOME}/.config/openshell/dashboard.env" <<ENVEOF
PORT=8090
OPENSHELL_GATEWAY_URL=grpcs://localhost:17670
GATEWAY_CA_CERT=/tls/ca.crt
AUTH_DISABLED=false
ADMIN_ROLE=openshell-admin
ENVEOF

cat > "${HOME}/.config/openshell/dashboard-proxy.env" <<ENVEOF
OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:8080
OAUTH2_PROXY_UPSTREAMS=http://localhost:8090
OAUTH2_PROXY_PROVIDER=oidc
OAUTH2_PROXY_OIDC_ISSUER_URL=${OIDC_ISSUER}
OAUTH2_PROXY_CLIENT_ID=${DASHBOARD_CLIENT_ID}
OAUTH2_PROXY_CLIENT_SECRET_FILE=/dev/null
OAUTH2_PROXY_REDIRECT_URL=${DASHBOARD_REDIRECT_URL}
OAUTH2_PROXY_COOKIE_SECRET=${DASHBOARD_COOKIE_SECRET}
OAUTH2_PROXY_PASS_ACCESS_TOKEN=true
OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256
OAUTH2_PROXY_EMAIL_DOMAINS=*
OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true
OAUTH2_PROXY_COOKIE_SECURE=true
OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY=${DASHBOARD_INSECURE_SKIP_TLS:-false}
# oauth2-proxy rejects the id_token by default if the OIDC provider's
# email_verified claim is false — true for real SSO-federated Keycloak
# accounts.
OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL=true
# Enable cookie refresh so oauth2-proxy renews tokens via the refresh token
# Keycloak issues by default.
OAUTH2_PROXY_SCOPE=openid email profile
OAUTH2_PROXY_COOKIE_REFRESH=60s
ENVEOF
chmod 600 "${HOME}/.config/openshell/dashboard.env" "${HOME}/.config/openshell/dashboard-proxy.env"

cat > "${HOME}/.config/systemd/user/openshell-dashboard.service" <<UNITEOF
[Unit]
Description=OpenShell Dashboard (BFF + UI)

[Service]
Type=simple
ExecStartPre=-/usr/bin/${RUNTIME} rm -f openshell-dashboard
ExecStart=/usr/bin/${RUNTIME} run --rm --name openshell-dashboard --network host --env-file=%h/.config/openshell/dashboard.env -v %h/.config/openshell/dashboard-gateway-ca.crt:/tls/ca.crt:ro,Z ${DASHBOARD_IMAGE}
ExecStop=/usr/bin/${RUNTIME} stop -t 5 openshell-dashboard
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
UNITEOF

cat > "${HOME}/.config/systemd/user/openshell-dashboard-proxy.service" <<UNITEOF
[Unit]
Description=OpenShell Dashboard Auth Proxy (oauth2-proxy)

[Service]
Type=simple
ExecStartPre=-/usr/bin/${RUNTIME} rm -f openshell-dashboard-proxy
ExecStart=/usr/bin/${RUNTIME} run --rm --name openshell-dashboard-proxy --network host --env-file=%h/.config/openshell/dashboard-proxy.env ${DASHBOARD_PROXY_IMAGE}
ExecStop=/usr/bin/${RUNTIME} stop -t 5 openshell-dashboard-proxy
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
UNITEOF

systemctl --user daemon-reload
# `enable --now` is a no-op on an already-running unit, so it silently keeps
# a stale container alive (with a stale env-file, e.g. an old OIDC issuer)
# across re-runs of this script — confirmed live: after fixing oidc.issuerUrl
# and re-running setup, the on-disk dashboard-proxy.env had the corrected
# issuer but the *running* oauth2-proxy container was untouched and kept
# redirecting logins to the old issuer until explicitly restarted. Always
# restart explicitly so config changes take effect on every run, not just
# the first.
systemctl --user enable openshell-dashboard.service openshell-dashboard-proxy.service
systemctl --user restart openshell-dashboard.service openshell-dashboard-proxy.service

echo "Waiting for dashboard to become ready..."
ok=0
for i in $(seq 1 15); do
  sleep 2
  if curl -sf --max-time 2 http://127.0.0.1:8090/api/v1/healthz >/dev/null 2>&1; then
    ok=1
    break
  fi
  echo "  waiting for dashboard... (attempt $i)"
done
if [[ "${ok}" -ne 1 ]]; then
  echo "WARN: dashboard health check timed out"
  ${RUNTIME} logs openshell-dashboard 2>&1 | tail -10 || true
  ${RUNTIME} logs openshell-dashboard-proxy 2>&1 | tail -10 || true
else
  echo "dashboard ready"
fi

echo "setup-dashboard OK"
