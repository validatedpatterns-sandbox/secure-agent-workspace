#!/usr/bin/env bash
# Quickstart: run APF as the governance interceptor in NS (no Argo CD, no Vault).
#
#   GHCR_USER=<github user> GHCR_TOKEN=<PAT with read:packages> make governance-apf
#
# 1. the ghcr-pull and governance-apf-signing Secrets, from GHCR_* and APF_SEED
# 2. release governance-apf-inputs: charts/governance-interceptor with engine=apf
#    (the signed bundle and trust root ConfigMaps, the NetworkPolicy)
# 3. release governance-interceptor: the APF chart, with the values the pattern's
#    Argo CD Application uses (rendered from the same chart, so they match)
#
# SAWs then need GOVERNANCE_ENGINE=apf on make openshell-saw-create.
set -euo pipefail

NS="${NS:-openshell-agents}"
APF_SEED="${APF_SEED:-$HOME/.apf-keys/apf.seed}"
GHCR_USER="${GHCR_USER:-}"
GHCR_TOKEN="${GHCR_TOKEN:-}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CHART="${REPO_DIR}/charts/governance-interceptor"
PYTHON="${PYTHON:-python3}"

die() { echo "Error: $*" >&2; exit 1; }

[[ -n "${GHCR_USER}" && -n "${GHCR_TOKEN}" ]] || \
  die "set GHCR_USER and GHCR_TOKEN (a GitHub token with read:packages that can read ghcr.io/mkhaas/apf)"
[[ -f "${APF_SEED}" ]] || die "no signing seed at ${APF_SEED} (make apf-keys, or set APF_SEED)"
[[ -f "${CHART}/files/apf/bundle.tar.gz" ]] || die "no signed bundle in the chart (make apf-bundle)"
"${PYTHON}" "${REPO_DIR}/scripts/apf-bundle.py" verify

# The APF chart takes over the release name the interceptor chart uses.
if helm status governance-interceptor -n "${NS}" >/dev/null 2>&1; then
  chart=$(helm list -n "${NS}" --filter '^governance-interceptor$' -o json | "${PYTHON}" -c \
    'import json,sys; r=json.load(sys.stdin); print(r[0]["chart"] if r else "")')
  if [[ "${chart}" == governance-interceptor-* ]]; then
    die "release governance-interceptor is the OpenShell interceptor; remove it first: helm uninstall governance-interceptor -n ${NS}"
  fi
fi

oc get namespace "${NS}" >/dev/null 2>&1 || oc create namespace "${NS}"

echo "Creating Secrets ghcr-pull and governance-apf-signing in ${NS}..."
oc -n "${NS}" create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username="${GHCR_USER}" --docker-password="${GHCR_TOKEN}" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
oc -n "${NS}" create secret generic governance-apf-signing \
  --from-file=apf-dev.seed="${APF_SEED}" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null

echo "Installing the APF inputs (release governance-apf-inputs)..."
helm upgrade --install governance-apf-inputs "${CHART}" -n "${NS}" \
  --set engine=apf --set apf.application.enabled=false --set apf.externalSecrets.enabled=false

VALUES="$(mktemp)"
trap 'rm -f "${VALUES}"' EXIT
helm template governance-interceptor "${CHART}" -n "${NS}" --set engine=apf \
  --show-only templates/apf-application.yaml | "${PYTHON}" -c '
import sys, yaml
app = yaml.safe_load(sys.stdin)
src = app["spec"]["source"]
print("#", src["repoURL"], src["chart"], src["targetRevision"])
print(yaml.safe_dump(src["helm"]["valuesObject"], sort_keys=False))' > "${VALUES}"
read -r _ REPO CHART_NAME VERSION < "${VALUES}"

echo "Installing APF ${VERSION} (release governance-interceptor)..."
printf '%s' "${GHCR_TOKEN}" | helm registry login ghcr.io -u "${GHCR_USER}" --password-stdin >/dev/null
helm upgrade --install governance-interceptor "oci://${REPO}/${CHART_NAME}" --version "${VERSION}" \
  -n "${NS}" -f "${VALUES}"

oc -n "${NS}" rollout status deployment/governance-interceptor --timeout=180s
echo "APF is serving governance-interceptor.${NS}.svc:18081."
echo "Create SAWs with GOVERNANCE_ENGINE=apf; restart existing ones (make openshell-saw-restart) after recreating them with it."
