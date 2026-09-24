#!/usr/bin/env bash
# Read-only, sectioned checks for the SAW tenant flows.
set -euo pipefail

errors=0
warnings=0
require_argo="${SAW_REQUIRE_ARGO:-0}"
require_keycloak="${SAW_REQUIRE_KEYCLOAK:-0}"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
cyan() { printf '\033[36m%s\033[0m\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok() { green "  ✓ $*"; }
fail() { red "  ✗ $1"; [[ -n "${2:-}" ]] && printf '    → %s\n' "$2"; errors=$((errors + 1)); }
warn() { yellow "  ⚠ $1"; [[ -n "${2:-}" ]] && printf '    → %s\n' "$2"; warnings=$((warnings + 1)); }
info() { cyan "  ℹ $*"; }
section() { echo; bold "$1"; }

check_api() {
  local group="$1" resource="$2" label="$3" hint="$4"
  if oc api-resources --api-group="$group" -o name 2>/dev/null | grep -Fqx "$resource" \
      || oc get crd "$resource" >/dev/null 2>&1; then
    ok "$label"
  else
    fail "$label API missing (group: $group, resource: $resource)" "$hint"
  fi
}

check_optional_api() {
  local group="$1" resource="$2" label="$3" required="$4" hint="$5"
  if oc api-resources --api-group="$group" -o name 2>/dev/null | grep -Fqx "$resource" \
      || oc get crd "$resource" >/dev/null 2>&1; then
    ok "$label"
  elif [[ "$required" == "1" ]]; then
    fail "$label API missing (required by explicit configuration)" "$hint"
  else
    info "$label is not installed; external OIDC is allowed"
  fi
}

section "SAW platform preflight"
if ! oc whoami >/dev/null 2>&1; then
  fail "Not logged in to OpenShift" "Run: oc login <cluster-api>"
  red "  Cannot continue without a cluster connection."
  exit 2
fi
ok "OpenShift connection: $(oc whoami 2>/dev/null)"

section "1. Required platform APIs"
check_api kubevirt.io virtualmachines.kubevirt.io OpenShift-Virtualization \
  "Install OpenShift Virtualization, then rerun this check"
check_api cdi.kubevirt.io datavolumes.cdi.kubevirt.io CDI \
  "Wait for the kubevirt-hyperconverged CSV/CDI rollout (oc get csv -n openshift-cnv); if it is absent, run: make saw-platform-operators"
check_api external-secrets.io externalsecrets.external-secrets.io External-Secrets-Operator \
  "Run: make saw-platform-operators, then wait for the operator CSV"
check_api external-secrets.io secretstores.external-secrets.io External-Secrets-Operator-SecretStore \
  "Run: make saw-platform-operators, then wait for the SecretStore CRD"

section "2. Optional identity and GitOps APIs"
check_optional_api k8s.keycloak.org keycloaks.k8s.keycloak.org \
  "Bundled Red Hat Build of Keycloak" "$require_keycloak" \
  "Run: make saw-keycloak-operator, then set SAW_REQUIRE_KEYCLOAK=1"
check_optional_api argoproj.io applications.argoproj.io "Argo CD" "$require_argo" \
  "Install Argo CD or use standalone Helm"
check_optional_api argoproj.io applicationsets.argoproj.io "Argo CD ApplicationSet" "$require_argo" \
  "Install ApplicationSet or use standalone Helm"

section "3. Controller readiness"
if oc get deployment -A -l app.kubernetes.io/name=argocd-application-controller --no-headers 2>/dev/null | grep -q .; then
  ok "Argo CD application controller deployment"
else
  info "Argo CD application controller not found; this is valid for standalone Helm"
fi

section "4. Result"
if (( errors )); then
  red "SAW platform preflight failed: ${errors} error(s), ${warnings} warning(s)."
  echo "  GitOps bootstrap: ./pattern.sh make install"
  echo "  Standalone bootstrap: make saw-platform-operators"
  exit 1
fi
if (( warnings )); then
  yellow "SAW platform preflight passed with ${warnings} warning(s)."
else
  green "SAW platform preflight passed."
fi
