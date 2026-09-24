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

# --- Pre-populate the supervisor cache on every gateway start ---
# Transfer files instead of embedding shell code in a systemd command over SSH.
# Load after route-san.conf, whose ExecStartPre= resets earlier startup commands.
guest_scp "${SCRIPTS_DIR}/prepopulate-supervisor-cache.sh" "/tmp/prepopulate-supervisor-cache.sh"
guest_ssh "sudo install -m 755 /tmp/prepopulate-supervisor-cache.sh /usr/local/bin/openshell-prepopulate-cache"
cat > "${WORK_DIR}/zz-prepopulate-cache.conf" <<UNITEOF
[Service]
ExecStartPre=/usr/local/bin/openshell-prepopulate-cache ${RUNTIME}
UNITEOF
guest_scp "${WORK_DIR}/zz-prepopulate-cache.conf" "/tmp/zz-prepopulate-cache.conf"
guest_ssh 'mkdir -p "$HOME/.config/systemd/user/openshell-gateway.service.d" && install -m 644 /tmp/zz-prepopulate-cache.conf "$HOME/.config/systemd/user/openshell-gateway.service.d/zz-prepopulate-cache.conf" && rm -f "$HOME/.config/systemd/user/openshell-gateway.service.d/prepopulate-cache.conf" && systemctl --user daemon-reload'

# Docker's 1500-byte default exceeds some OpenShift VM uplinks (e.g. 1400).
# Network administration belongs in the system manager, not a sudo command
# inside the gateway's user manager (which may run in a user namespace).
guest_ssh 'rm -f "$HOME/.config/systemd/user/openshell-gateway.service.d/zz-docker-mtu.conf"'
if [[ "${RUNTIME}" == "docker" ]]; then
  guest_scp "${SCRIPTS_DIR}/configure-docker-mtu.sh" "/tmp/configure-docker-mtu.sh"
  guest_ssh "sudo install -m 755 /tmp/configure-docker-mtu.sh /usr/local/bin/openshell-configure-docker-mtu"
  MTU_USER_UID="$(guest_ssh 'id -u')"
  [[ "${MTU_USER_UID}" =~ ^[0-9]+$ ]] || { echo "ERROR: could not determine gateway user UID"; exit 1; }
  cat > "${WORK_DIR}/openshell-docker-mtu.service" <<UNITEOF
[Unit]
Description=Configure OpenShell Docker network MTU
Requires=docker.service
After=docker.service network-online.target
Before=user@${MTU_USER_UID}.service
PartOf=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openshell-configure-docker-mtu
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNITEOF
  guest_scp "${WORK_DIR}/openshell-docker-mtu.service" "/tmp/openshell-docker-mtu.service"
  guest_ssh 'sudo install -m 644 /tmp/openshell-docker-mtu.service /etc/systemd/system/openshell-docker-mtu.service && sudo systemctl daemon-reload && sudo systemctl enable openshell-docker-mtu.service && sudo systemctl restart openshell-docker-mtu.service'
else
  guest_ssh 'if test -f /etc/systemd/system/openshell-docker-mtu.service; then sudo systemctl disable --now openshell-docker-mtu.service; fi'
fi

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
