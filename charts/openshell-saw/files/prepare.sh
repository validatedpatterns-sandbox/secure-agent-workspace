#!/usr/bin/env bash
# Prepare Job entrypoint: cluster-side work only. It never connects to the
# VM; the VM installs itself (see files/installer/apply_bom.py).
# Chart values are resolved by Helm tpl() at render time.
set -euo pipefail

VM_NAME="{{ include "openshell-sandbox.fullname" . }}"
NS="{{ .Release.Namespace }}"
GOLDEN_DS="{{ include "openshell-sandbox.dataSourceName" . }}"
GOLDEN_NS="{{ include "openshell-sandbox.goldenNamespace" . }}"
GOLDEN_DISK_SIZE="{{ .Values.vm.diskSize }}"
GOLDEN_IMAGE_URL="{{ .Values.source.goldenImageURL }}"
PULL_METHOD="{{ .Values.source.pullMethod | default "node" }}"
DASHBOARD_ENABLED="{{ and .Values.dashboard.enabled .Values.route.webui }}"
DASHBOARD_CLIENT_ID="{{ .Values.dashboard.clientId }}"
OIDC_ISSUER_URL="{{ include "openshell-sandbox.oidcIssuerUrl" . }}"
OIDC_KEYCLOAK_NAME="{{ .Values.oidc.keycloakName }}"
OIDC_REALM="{{ .Values.oidc.realm }}"
KEYCLOAK_NS="{{ include "openshell-sandbox.keycloakNamespace" . }}"
UI_ROUTE_HOSTS="{{ range $e := include "openshell-sandbox.sandboxUi" . | fromJsonArray }}{{ $e.host }} {{ end }}"
SCRIPTS_DIR="/scripts"

# --- Phase 1: tools ---
source "${SCRIPTS_DIR}/install-deps.sh"

# --- Phase 2: golden image DataSource (only for the DataSource disk source) ---
{{- if not (or .Values.source.registryURL .Values.source.httpURL) }}
source "${SCRIPTS_DIR}/bootstrap-golden-image.sh"
{{- else }}
echo "Disk source is a registry/HTTP import; no golden image bootstrap needed."
{{- end }}

# --- Phase 3: dashboard redirect URI in Keycloak ---
if [[ ( "${DASHBOARD_ENABLED}" == "true" || -n "${UI_ROUTE_HOSTS// /}" ) && -n "${OIDC_ISSUER_URL}" ]]; then
  source "${SCRIPTS_DIR}/register-keycloak-redirect.sh"
else
  echo "Dashboard or OIDC issuer not configured; skipping Keycloak redirect registration."
fi

echo "Prepare complete for vm/${VM_NAME}. The VM installs itself; follow its console log:"
echo "  oc logs -f -n ${NS} \$(oc get pod -n ${NS} -l vm.kubevirt.io/name=${VM_NAME} -o name) -c guest-console-log"
