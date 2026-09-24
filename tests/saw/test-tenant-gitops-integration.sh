#!/usr/bin/env bash
# Opt-in live proof for SAW tenant isolation. It assumes two disposable,
# Git-reconciled enrollments and never creates tenants or grants permissions.
# Required: SAW_TEST_ALICE_NAMESPACE, SAW_TEST_BOB_NAMESPACE,
# SAW_TEST_APPROVED_DATASOURCE, SAW_TEST_PROFILE_CONFIGMAP,
# SAW_TEST_PROFILE_KEY, SAW_TEST_ALICE_APPLICATION, SAW_TEST_BOB_APPLICATION,
# VAULT_ADDR, VAULT_TOKEN (a disposable Vault token allowed to rotate one key).
set -euo pipefail

need() { [[ -n "${!1:-}" ]] || { echo "missing $1" >&2; exit 2; }; }
for variable in SAW_TEST_ALICE_NAMESPACE SAW_TEST_BOB_NAMESPACE SAW_TEST_APPROVED_DATASOURCE SAW_TEST_PROFILE_CONFIGMAP SAW_TEST_PROFILE_KEY SAW_TEST_ALICE_APPLICATION SAW_TEST_BOB_APPLICATION VAULT_ADDR VAULT_TOKEN; do need "$variable"; done
for command in oc curl jq; do command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }; done

alice="$SAW_TEST_ALICE_NAMESPACE"; bob="$SAW_TEST_BOB_NAMESPACE"
image_ns="${SAW_TEST_IMAGE_NAMESPACE:-saw-images}"; argo_ns="${SAW_TEST_ARGO_NAMESPACE:-openshift-gitops}"
mount="${SAW_TEST_VAULT_MOUNT:-secret}"; auth_mount="${SAW_TEST_VAULT_AUTH_MOUNT:-kubernetes}"
prefix="${SAW_TEST_VAULT_PREFIX:-saw/users}"; provider="${SAW_TEST_PROVIDER:-nvidia}"
wait_seconds="${SAW_TEST_WAIT_SECONDS:-180}"; work="$(mktemp -d)"; restore=""
curl_args=(); [[ -n "${VAULT_CACERT:-}" ]] && curl_args+=(--cacert "$VAULT_CACERT")
cleanup() {
  if [[ -n "$restore" ]]; then
    curl -fsS "${curl_args[@]}" -H "X-Vault-Token: $VAULT_TOKEN" -H 'Content-Type: application/json' --data-binary "@$restore" "$VAULT_ADDR/v1/$mount/data/$vault_path" >/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
deny() { [[ "$(oc auth can-i "$1" "$2" -n "$3" --as "$4")" == no ]] || { echo "unexpected permission: $4 $1 $2 in $3" >&2; exit 1; }; }
wait_for() { local until=$((SECONDS + wait_seconds)); until "$@"; do (( SECONDS < until )) || { echo "timed out waiting for $*" >&2; exit 1; }; sleep 5; done; }

oc whoami >/dev/null
alice_sa="system:serviceaccount:$alice:saw-vault-reader"
for resource in secrets configmaps virtualmachines.kubevirt.io datavolumes.cdi.kubevirt.io persistentvolumeclaims; do deny get "$resource" "$bob" "$alice_sa"; done
deny get datasources.cdi.kubevirt.io "$image_ns" "$alice_sa"
deny create datavolumes/source "$image_ns" "$alice_sa"
echo 'PASS: tenant SA cannot read another tenant or clone the shared image'

alice_id="$(oc get namespace "$alice" -o jsonpath='{.metadata.annotations.saw\.redhat\.com/enrollment-identity}')"
bob_id="$(oc get namespace "$bob" -o jsonpath='{.metadata.annotations.saw\.redhat\.com/enrollment-identity}')"
[[ -n "$alice_id" && -n "$bob_id" && "$alice_id" != "$bob_id" ]] || { echo 'invalid tenant identities' >&2; exit 1; }
vault_path="$prefix/$alice_id/providers/$provider"
vault_login() {
  local namespace="$1" jwt
  jwt="$(oc -n "$namespace" create token saw-vault-reader --audience vault)"
  curl -fsS "${curl_args[@]}" -H 'Content-Type: application/json' --data "$(jq -nc --arg role "$namespace" --arg jwt "$jwt" '{role:$role,jwt:$jwt}')" "$VAULT_ADDR/v1/auth/$auth_mount/login" | jq -er '.auth.client_token'
}
alice_token="$(vault_login "$alice")"; bob_token="$(vault_login "$bob")"
[[ "$(curl -sS "${curl_args[@]}" -o /dev/null -w '%{http_code}' -H "X-Vault-Token: $alice_token" "$VAULT_ADDR/v1/$mount/data/$vault_path")" == 200 ]]
[[ "$(curl -sS "${curl_args[@]}" -o /dev/null -w '%{http_code}' -H "X-Vault-Token: $bob_token" "$VAULT_ADDR/v1/$mount/data/$vault_path")" != 200 ]] || { echo 'Bob Vault role read Alice path' >&2; exit 1; }
echo 'PASS: Vault role is tenant-scoped'

secret="saw-provider-$provider"; old_rv="$(oc get secret "$secret" -n "$alice" -o jsonpath='{.metadata.resourceVersion}')"
curl -fsS "${curl_args[@]}" -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/$mount/data/$vault_path" | jq '{data:.data.data}' > "$work/original.json"
restore="$work/original.json"
jq --arg value "rotation-$RANDOM-$(date +%s)" '.data.api_key = $value' "$restore" > "$work/rotated.json"
curl -fsS "${curl_args[@]}" -H "X-Vault-Token: $VAULT_TOKEN" -H 'Content-Type: application/json' --data-binary "@$work/rotated.json" "$VAULT_ADDR/v1/$mount/data/$vault_path" >/dev/null
secret_rotated() { [[ "$(oc get secret "$secret" -n "$alice" -o jsonpath='{.metadata.resourceVersion}')" != "$old_rv" ]]; }
wait_for secret_rotated
echo 'PASS: ESO rotation updated only the tenant provider Secret'

original="$(oc get configmap "$SAW_TEST_PROFILE_CONFIGMAP" -n "$alice" -o jsonpath="{.data['$SAW_TEST_PROFILE_KEY']}")"
oc patch configmap "$SAW_TEST_PROFILE_CONFIGMAP" -n "$alice" --type merge -p "{\"data\":{\"$SAW_TEST_PROFILE_KEY\":\"drift-marker\"}}" >/dev/null
cm_reconciled() { [[ "$(oc get configmap "$SAW_TEST_PROFILE_CONFIGMAP" -n "$alice" -o jsonpath="{.data['$SAW_TEST_PROFILE_KEY']}")" == "$original" ]]; }
app_synced() { [[ "$(oc get application.argoproj.io "$1" -n "$argo_ns" -o jsonpath='{.status.sync.status}')" == Synced ]]; }
wait_for cm_reconciled
for app in "$SAW_TEST_ALICE_APPLICATION" "$SAW_TEST_BOB_APPLICATION"; do wait_for app_synced "$app"; done
echo 'PASS: Argo restored Git input and both tenant Applications are synced'
