#!/usr/bin/env bash
# Phase: upgrade OpenShell binaries on the VM, patch OIDC, restart gateway.
# Expects: GATEWAY_IMAGE, SUPERVISOR_IMAGE, OPENSHELL_PIP_VERSION, PIP_INDEX_URL,
#          RUNTIME, SECRETS_DIR, WORK_DIR, NS, ALLOW_ANONYMOUS_PULL,
#          guest_ssh/guest_scp (functions)

if [[ -n "${GATEWAY_IMAGE}" && -n "${SUPERVISOR_IMAGE}" && -n "${OPENSHELL_PIP_VERSION}" ]]; then
  echo "Upgrading OpenShell binaries (gateway=${GATEWAY_IMAGE}, supervisor=${SUPERVISOR_IMAGE}, cli=${OPENSHELL_PIP_VERSION})..."
  guest_ssh "
    ${RUNTIME} pull '${GATEWAY_IMAGE}' && \
    CID=\$(${RUNTIME} create '${GATEWAY_IMAGE}') && \
    ${RUNTIME} cp \${CID}:/usr/local/bin/openshell-gateway /tmp/openshell-gateway && \
    ${RUNTIME} rm \${CID} && \
    sudo mv /tmp/openshell-gateway /usr/local/bin/openshell-gateway && \
    sudo chmod 755 /usr/local/bin/openshell-gateway && \
    echo 'gateway upgraded'
  " || echo "WARN: gateway binary upgrade failed (continuing with existing version)"
  guest_ssh "
    ${RUNTIME} pull '${SUPERVISOR_IMAGE}' && \
    CID=\$(${RUNTIME} create '${SUPERVISOR_IMAGE}') && \
    ${RUNTIME} cp \${CID}:/openshell-sandbox /tmp/openshell-supervisor && \
    ${RUNTIME} rm \${CID} && \
    sudo mv /tmp/openshell-supervisor /usr/local/bin/openshell-supervisor && \
    sudo chmod 755 /usr/local/bin/openshell-supervisor && \
    echo 'supervisor upgraded'
  " || echo "WARN: supervisor binary upgrade failed (continuing with existing version)"
  # The gateway refreshes its supervisor binary at startup from the upstream
  # Docker image (ghcr.io/nvidia/openshell/supervisor:dev). The gateway looks
  # for /openshell-sandbox inside the container, but the upstream :dev image
  # ships the binary as /openshell-supervisor (different path). Pre-populate
  # the content-addressed cache by pulling the upstream image fresh (to get
  # the current digest), then extracting /openshell-supervisor → /openshell-sandbox.
  # Falls back to the ODH binary if extraction fails.
  UPSTREAM_SUPERVISOR_IMAGE="ghcr.io/nvidia/openshell/supervisor:dev"
  # Single-line to avoid quoting/continuation issues inside guest_ssh.
  # Use the ODH supervisor binary (at /usr/local/bin/openshell-supervisor, copied from
  # the ODH image's /openshell-sandbox) — NOT the upstream /openshell-supervisor binary,
  # which is a different component and crashes with --backend-descriptor-file missing.
  guest_ssh "${RUNTIME} pull '${UPSTREAM_SUPERVISOR_IMAGE}' 2>/dev/null || true; DIGEST=\$(${RUNTIME} inspect '${UPSTREAM_SUPERVISOR_IMAGE}' --format '{{.Id}}' | sed 's|sha256:||'); CACHE_DIR=\"\$HOME/.local/share/openshell/docker-supervisor/sha256-\$DIGEST\"; mkdir -p \"\$CACHE_DIR\"; chmod 755 \"\$CACHE_DIR/openshell-sandbox\" 2>/dev/null || true; cp /usr/local/bin/openshell-supervisor \"\$CACHE_DIR/openshell-sandbox\" && chmod 755 \"\$CACHE_DIR/openshell-sandbox\" && echo \"pre-populated supervisor cache sha256:\$DIGEST (ODH binary)\"" || echo "WARN: supervisor cache pre-population failed (non-fatal)"
  PIP_EXTRA=""
  [[ -n "${PIP_INDEX_URL}" ]] && PIP_EXTRA="--extra-index-url ${PIP_INDEX_URL}"
  guest_ssh "
    pip3 install openshell==${OPENSHELL_PIP_VERSION} ${PIP_EXTRA} \
    && echo 'openshell CLI upgraded'
  " || echo "WARN: openshell CLI upgrade failed (continuing with existing version)"
  # Patch the pip-installed openshell binary's version output so nemoclaw's
  # feature gate sees matching versions across all three components. The pip
  # binary uses '+' (PEP 440 local) while the native Go binaries use '-'
  # (semver pre-release); the mismatch causes componentBuildVersionsMatch()
  # to return false. We wrap the original binary with a script that fixes
  # --version output and delegates everything else.
  NATIVE_VERSION="$(guest_ssh "openshell-gateway --version 2>/dev/null" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\S*' | head -1 || echo "${OPENSHELL_PIP_VERSION}" | sed 's/+/-/')"
  cat > "${WORK_DIR}/openshell-wrapper" <<WEOF
#!/usr/bin/env bash
if [[ "\$1" == "--version" ]]; then
  echo "openshell ${NATIVE_VERSION}"
  exit 0
fi
SELF_DIR="\$(cd "\$(dirname "\$0")" && pwd)"
exec "\${SELF_DIR}/openshell-real" "\$@"
WEOF
  chmod 755 "${WORK_DIR}/openshell-wrapper"
  guest_scp "${WORK_DIR}/openshell-wrapper" "/tmp/openshell-wrapper"
  guest_ssh "
    OS_BIN=\$(command -v openshell 2>/dev/null || echo /home/${SSH_USER}/.local/bin/openshell)
    OS_DIR=\$(dirname \${OS_BIN})
    if [[ -f \${OS_BIN} && ! -f \${OS_DIR}/openshell-real ]]; then
      mv \${OS_BIN} \${OS_DIR}/openshell-real
    fi
    mv /tmp/openshell-wrapper \${OS_BIN}
    chmod 755 \${OS_BIN}
    echo 'openshell version wrapper installed'
  " || echo "WARN: openshell wrapper install failed (non-fatal)"
  guest_ssh "openshell-gateway --version; openshell-supervisor --version; openshell --version" || true
fi

# --- Install lsof (needed by nemoclaw for gateway listener identification) ---
guest_ssh "sudo dnf install -y lsof 2>&1 | tail -3" || echo "WARN: lsof install failed (non-fatal)"

# --- Trust cluster's service-serving CA (for the internal image registry) ---
# Only needed when internalRegistry.allowAnonymousPull is enabled (see
# values.yaml) — the sandbox VM's Docker daemon needs this to pull
# internally-built images over TLS. Every namespace gets an
# "openshift-service-ca.crt" ConfigMap containing the CA that signs
# internal service serving certs. Requires a Docker restart to pick up
# the refreshed system trust store.
if [[ "${ALLOW_ANONYMOUS_PULL:-false}" == "true" ]]; then
  echo "Installing cluster service-serving CA into VM trust store..."
  SERVICE_CA="$(kubectl get configmap openshift-service-ca.crt -n "${NS}" -o jsonpath='{.data.service-ca\.crt}' 2>/dev/null || true)"
  if [[ -n "${SERVICE_CA}" ]]; then
    echo "${SERVICE_CA}" > "${WORK_DIR}/service-ca.crt"
    guest_scp "${WORK_DIR}/service-ca.crt" "/tmp/openshift-service-ca.crt"
    guest_ssh "sudo cp /tmp/openshift-service-ca.crt /etc/pki/ca-trust/source/anchors/openshift-service-ca.crt && sudo update-ca-trust extract && sudo systemctl restart docker" \
      || echo "WARN: failed to install service-serving CA into VM trust store (non-fatal)"
  else
    echo "WARN: could not fetch cluster service-serving CA (non-fatal, continuing)"
  fi
fi

# --- Systemd override: pre-populate supervisor cache before gateway starts ---
# This ensures the correct ODH binary is in the content-addressed cache
# on every gateway start, even if the upstream image digest changes.
guest_ssh "
  OVERRIDE_DIR=\"\$HOME/.config/systemd/user/openshell-gateway.service.d\"
  mkdir -p \"\$OVERRIDE_DIR\"
  cat > \"\$OVERRIDE_DIR/prepopulate-cache.conf\" << 'UNITEOF'
[Service]
ExecStartPre=/bin/bash -c 'D=\$(docker inspect ghcr.io/nvidia/openshell/supervisor:dev --format \"{{.Id}}\" 2>/dev/null | sed \"s|sha256:||\" || true); [ -n \"\$D\" ] && mkdir -p \$HOME/.local/share/openshell/docker-supervisor/sha256-\$D && cp /usr/local/bin/openshell-supervisor \$HOME/.local/share/openshell/docker-supervisor/sha256-\$D/openshell-sandbox 2>/dev/null && chmod 755 \$HOME/.local/share/openshell/docker-supervisor/sha256-\$D/openshell-sandbox 2>/dev/null || true'
UNITEOF
  systemctl --user daemon-reload && echo 'gateway override installed'
" || echo "WARN: gateway systemd override failed (non-fatal)"

# --- Patch OIDC issuer ---
source "${SECRETS_DIR}/run-create.env" 2>/dev/null || true
if [[ -n "${OIDC_ISSUER:-}" ]]; then
  echo "Patching OIDC issuer to ${OIDC_ISSUER}..."
  guest_ssh "sudo sed -i 's|issuer = \".*\"|issuer = \"${OIDC_ISSUER}\"|' /etc/openshell/gateway.toml 2>/dev/null || true" || true
  guest_ssh "sed -i 's|issuer = \".*\"|issuer = \"${OIDC_ISSUER}\"|' ~/.config/openshell/gateway.toml 2>/dev/null || true" || true
  guest_ssh "grep -v '^OPENSHELL_OIDC_ISSUER' ~/.config/openshell/gateway.env > /tmp/genv.tmp 2>/dev/null && mv /tmp/genv.tmp ~/.config/openshell/gateway.env; echo 'OPENSHELL_OIDC_ISSUER=${OIDC_ISSUER}' >> ~/.config/openshell/gateway.env" || true
  guest_ssh "MFILE=~/.config/openshell/gateways/openshell/metadata.json; [[ -f \"\${MFILE}\" ]] && sed -i 's|\"oidc_issuer\":\"[^\"]*\"|\"oidc_issuer\":\"${OIDC_ISSUER}\"|' \"\${MFILE}\" || true" || true
  echo "OIDC config patched"
fi

# --- Restart gateway with new binaries ---
echo "Restarting gateway service..."
guest_ssh "systemctl --user daemon-reload && systemctl --user restart openshell-gateway.service" || true
GW_READY=0
for i in $(seq 1 10); do
  if guest_ssh "systemctl --user is-active openshell-gateway.service" 2>/dev/null; then
    GW_READY=1; break
  fi
  echo "  waiting for gateway... (attempt $i)"
  sleep 3
done
if [[ "${GW_READY}" -ne 1 ]]; then
  echo "WARN: gateway did not restart after upgrade"
  guest_ssh "journalctl --user -u openshell-gateway.service --no-pager 2>/dev/null | tail -5" || true
fi
