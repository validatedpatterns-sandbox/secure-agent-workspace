#!/usr/bin/env bash
# Phase: extract BOM profiles from ConfigMap, resolve credentials, apply via apply_bom.py.
# Expects: NS, SSH_USER, SECRETS_DIR, WORK_DIR, OIDC_ISSUER_URL, OWNER,
#          KEYCLOAK_NAME, KEYCLOAK_NS, NEMOCLAW_CLI_IMAGE, VM_NAME,
#          guest_ssh, guest_scp (functions)

BOM_CM="saw-bom-profiles"
BOM_MOUNT="/tmp/bom-profiles"
if ! kubectl get configmap "${BOM_CM}" -n "${NS}" >/dev/null 2>&1; then
  echo "WARNING: No BOM profiles ConfigMap (${BOM_CM}) found — no workspaces or sandboxes will be provisioned."
  echo "WARNING: Deploy the saw-bom chart to configure workspaces and providers."
  echo "WARNING: The VM is running but has no agent sandboxes configured."
  return 0 2>/dev/null || true
fi

echo "BOM profiles detected (ConfigMap ${BOM_CM}) — applying profiles"

mkdir -p "${BOM_MOUNT}"

# Extract ConfigMap data to files
for key in $(kubectl get configmap "${BOM_CM}" -n "${NS}" -o json | jq -r '.data | keys[]'); do
  kubectl get configmap "${BOM_CM}" -n "${NS}" -o json | jq -r --arg k "${key}" '.data[$k]' > "${BOM_MOUNT}/${key}"
done

cp "${SECRETS_DIR}/run-create.env" "${WORK_DIR}/run-create.env"
source "${WORK_DIR}/run-create.env" 2>/dev/null || true

# Transfer BOM app + profiles to VM
BOM_DIR="/home/${SSH_USER}/bom-profiles"
guest_ssh "mkdir -p ${BOM_DIR}"
for file in ${BOM_MOUNT}/*; do
  key="$(basename "$file")"
  if [[ "${key}" == "apply_bom.py" ]]; then
    guest_scp "$file" "/home/${SSH_USER}/apply_bom.py"
    continue
  fi
  IFS_OLD="${IFS}"; IFS='|'
  read -ra parts <<< "$(echo "${key}" | sed 's/__/|/g')"
  IFS="${IFS_OLD}"
  if [[ ${#parts[@]} -ge 4 ]]; then
    profile="${parts[1]}"
    ws="${parts[2]}"
    ws_file="${parts[3]}"
    guest_ssh "mkdir -p ${BOM_DIR}/${profile}/${ws}"
    guest_scp "$file" "${BOM_DIR}/${profile}/${ws}/${ws_file}"
  fi
done

# Resolve credentials from mounted secrets
BOM_ENV="${WORK_DIR}/bom.env"
for file in ${BOM_MOUNT}/*; do
  key="$(basename "$file")"
  IFS_OLD="${IFS}"; IFS='|'
  read -ra p <<< "$(echo "${key}" | sed 's/__/|/g')"
  IFS="${IFS_OLD}"
  if [[ ${#p[@]} -ge 4 && "${p[3]}" == "providers.yaml" ]]; then
    _flush_prov() {
      if [[ -n "${cur_name:-}" && -n "${cur_secret:-}" ]]; then
        skey="${cur_key:-api_key}"
        # Every credentialSecret a BOM profile declares is mounted dynamically
        # at /ws-secrets/<name> (see job-setup.yaml's additionalProviderSecrets
        # loop) — this used to also fall back to a hardcoded /search-secret
        # path regardless of the declared name, which silently broke if a
        # tenant renamed their secret; that path is gone now, the declared
        # name is what actually controls resolution.
        spath="/ws-secrets/${cur_secret}/${skey}"
        if [[ -f "${spath}" ]]; then
          env_var="$(echo "PROV_${cur_name}_KEY" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
          echo "${env_var}=$(cat "${spath}")" >> "${BOM_ENV}"
          echo "  Resolved: ${cur_name}"
          # Also surface the secret's own "provider" field (e.g. "gemini",
          # "build") if present, so apply_bom.py can validate it against
          # the BOM profile's declared type before creating the provider.
          ppath="/ws-secrets/${cur_secret}/provider"
          if [[ -f "${ppath}" ]]; then
            type_env_var="$(echo "PROV_${cur_name}_TYPE" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
            echo "${type_env_var}=$(cat "${ppath}")" >> "${BOM_ENV}"
          fi
        else
          echo "  WARNING: credential for provider '${cur_name}' not found at ${spath} — is '${cur_secret}' listed in additionalProviderSecrets (openshell-saw values) or is it the primary inference.secretName?"
        fi
      fi
    }
    cur_name="" ; cur_secret="" ; cur_key=""
    while IFS= read -r line; do
      if echo "${line}" | grep -q '^\s*- name:'; then
        _flush_prov
        cur_name="$(echo "${line}" | sed 's/.*name: *//' | tr -d '"' | tr -d "'")"
        cur_secret="" ; cur_key=""
      elif echo "${line}" | grep -q 'credentialSecretKey:'; then
        cur_key="$(echo "${line}" | sed 's/.*credentialSecretKey: *//' | tr -d '"' | tr -d "'")"
      elif echo "${line}" | grep -q 'credentialSecret:'; then
        cur_secret="$(echo "${line}" | sed 's/.*credentialSecret: *//' | tr -d '"' | tr -d "'")"
      fi
    done < "$file"
    _flush_prov
  fi
done

# Fetch OIDC token from Keycloak
if [[ -z "${OIDC_TOKEN:-}" ]]; then
  if [[ -n "${OIDC_ISSUER_URL}" && -n "${OWNER}" ]]; then
    KEYCLOAK_SECRET="$(kubectl get secret ${KEYCLOAK_NAME}-initial-admin \
      -n ${KEYCLOAK_NS} \
      -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)"
    if [[ -n "${KEYCLOAK_SECRET}" ]]; then
      TOKEN_RESPONSE=$(curl -sk -X POST \
        "${OIDC_ISSUER_URL}/protocol/openid-connect/token" \
        -d "grant_type=password" \
        -d "client_id=openshell-cli" \
        -d "username=${OWNER}" \
        -d "password=${OWNER}" \
        -d "scope=openid" 2>/dev/null || true)
      OIDC_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.access_token // empty')
      if [[ -n "${OIDC_TOKEN}" ]]; then
        echo "OIDC token obtained for ${OWNER}"
      else
        echo "WARNING: OIDC token fetch failed for '${OWNER}': $(echo "${TOKEN_RESPONSE}" | jq -r '.error_description // .error // "no response / unparseable response"')"
      fi
    else
      echo "WARNING: could not read secret ${KEYCLOAK_NAME}-initial-admin in namespace ${KEYCLOAK_NS} — skipping OIDC token fetch. Check dashboard.keycloakNamespace if Keycloak isn't co-located with this sandbox."
    fi
  fi
fi
[[ -n "${OIDC_TOKEN:-}" ]] && echo "OIDC_TOKEN=${OIDC_TOKEN}" >> "${BOM_ENV}"
echo "OIDC_ISSUER=${OIDC_ISSUER_URL}" >> "${BOM_ENV}"
echo "OIDC_CLIENT_ID=${OIDC_CLIENT_ID:-openshell-cli}" >> "${BOM_ENV}"
echo "OPENSHELL_GATEWAY=${OPENSHELL_GATEWAY:-openshell}" >> "${BOM_ENV}"

# Nemoclaw CLI image
if [[ -n "${NEMOCLAW_CLI_IMAGE}" ]]; then
  echo "NEMOCLAW_CLI_IMAGE=${NEMOCLAW_CLI_IMAGE}" >> "${BOM_ENV}"
fi

guest_scp "${BOM_ENV}" "/home/${SSH_USER}/bom.env"

# Compute dashboard route for openclaw gateway inside sandboxes
DASHBOARD_ROUTE_HOST="$(kubectl get route "${VM_NAME}-dashboard" -n "${NS}" -o jsonpath='{.spec.host}' 2>/dev/null || true)"

# Run apply_bom.py on the VM
echo "Running BOM setup on vm/${VM_NAME}..."
guest_ssh "
  set -a; source /home/${SSH_USER}/bom.env 2>/dev/null; set +a
  python3 /home/${SSH_USER}/apply_bom.py \
    --profiles-dir ${BOM_DIR} \
    --oidc-gateway \${OPENSHELL_GATEWAY:-openshell} \
    --mtls-gateway openshell-local \
    --nemoclaw-cli-image \"\${NEMOCLAW_CLI_IMAGE:-}\" \
    --dashboard-route '${DASHBOARD_ROUTE_HOST}'
" 2>&1

echo "BOM profiles applied."

# --- Extract Codex shared secret (if codex sandbox was created) ---
CODEX_SECRET="$(guest_ssh 'cat /home/cloud-user/.codex-secrets/codex/ws-secret 2>/dev/null' 2>/dev/null || true)"
if [[ -n "${CODEX_SECRET}" ]]; then
  kubectl create secret generic "${VM_NAME}-codex-secret" \
    --from-literal=ws-secret="${CODEX_SECRET}" \
    --from-literal=issuer=saw-codex \
    --from-literal=audience=codex-session \
    -n "${NS}" --dry-run=client -o yaml | kubectl apply -f -
  echo "Codex shared secret stored as ${VM_NAME}-codex-secret"
fi
