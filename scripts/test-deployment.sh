#!/usr/bin/env bash
# Live OpenShift acceptance test. Run only on a dedicated test cluster.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo}"

: "${TEST_CLUSTER_CONTEXT:?Set TEST_CLUSTER_CONTEXT to the dedicated oc context}"
: "${TEST_SAW_NAME:?Set TEST_SAW_NAME to a new SAW name of at most 19 characters}"
: "${TEST_PATTERN_SAW_NAME:?Set TEST_PATTERN_SAW_NAME to a SAW installed by the pattern}"
: "${TEST_OWNER:?Set TEST_OWNER to the test owner name}"
: "${TEST_OWNER_SUBJECT:?Set TEST_OWNER_SUBJECT to the owner OIDC subject}"
: "${TEST_SECOND_TOKEN_DIR:?Set TEST_SECOND_TOKEN_DIR to the second user token directory}"
: "${PROVIDER:?Set PROVIDER for the manual quickstart}"
: "${MODEL:?Set MODEL for the manual quickstart}"
: "${API_KEY:?Set API_KEY in the environment; do not pass it on the command line}"
: "${WEB_SEARCH_API_KEY:?Set WEB_SEARCH_API_KEY for the data-science profile}"
: "${TARGET_BRANCH:?Set TARGET_BRANCH to the pushed branch with the tested commit}"
: "${TARGET_ORIGIN:?Set TARGET_ORIGIN to its remote name}"
: "${TEST_INFERENCE_CHECK:?Set TEST_INFERENCE_CHECK to an executable request check}"
: "${TEST_OWNER_ACCESS_CHECK:?Set TEST_OWNER_ACCESS_CHECK to an executable owner access check}"
: "${TEST_SECOND_USER_DENIED_CHECK:?Set TEST_SECOND_USER_DENIED_CHECK to an executable second-user denial check}"

for check in "${TEST_INFERENCE_CHECK}" "${TEST_OWNER_ACCESS_CHECK}" \
    "${TEST_SECOND_USER_DENIED_CHECK}"; do
  if [[ ! -f "${check}" || ! -x "${check}" ]]; then
    echo "Error: ${check} must be an executable test script." >&2
    exit 1
  fi
done

context="$(oc config current-context)"
if [[ "${context}" != "${TEST_CLUSTER_CONTEXT}" ]]; then
  echo "Error: current oc context does not match TEST_CLUSTER_CONTEXT." >&2
  exit 1
fi
if [[ "${OIDC_TOKEN_DIR:-${HOME}/.config/openshell/oidc}" == "${TEST_SECOND_TOKEN_DIR}" ]]; then
  echo "Error: the owner and second user need separate token directories." >&2
  exit 1
fi
if [[ ! -f "${TEST_SECOND_TOKEN_DIR}/token.json" ]]; then
  echo "Error: second user's token file is absent." >&2
  exit 1
fi

export OPENSHELL_SAW_NAME="${TEST_SAW_NAME}" OWNER="${TEST_OWNER}"
export OWNER_SUBJECT="${TEST_OWNER_SUBJECT}"
if [[ -n "${SAW_NS:-}" && "${SAW_NS}" != saw- && \
      "${SAW_NS}" != "saw-${TEST_SAW_NAME}" ]]; then
  echo "Error: SAW_NS must be saw-${TEST_SAW_NAME} for this test." >&2
  exit 1
fi
export SAW_NS="saw-${TEST_SAW_NAME}"
"${repo}/scripts/check-saw-name.sh"
OPENSHELL_SAW_NAME="${TEST_PATTERN_SAW_NAME}" "${repo}/scripts/check-saw-name.sh"

commit="$(git rev-parse HEAD)"
git diff --quiet
git diff --cached --quiet
remote_commit="$(git ls-remote --heads "${TARGET_ORIGIN}" "${TARGET_BRANCH}" | awk '{print $1}')"
if [[ -z "${remote_commit}" || "${remote_commit}" != "${commit}" ]]; then
  echo "Error: the pushed branch must point to the tested commit ${commit}." >&2
  exit 1
fi

namespace="${SAW_NS}"
pattern_namespace="saw-${TEST_PATTERN_SAW_NAME}"
namespaces="$(oc get namespaces -o json)"
keycloak_initial=false
if jq -e --arg name "${KEYCLOAK_NS:-saw-keycloak}" \
    '.items | any(.metadata.name == $name)' <<<"${namespaces}" >/dev/null; then
  keycloak_releases="$(helm list -n "${KEYCLOAK_NS:-saw-keycloak}" -o json)"
  if jq -e '. | any(.name == "openshell-keycloak")' \
      <<<"${keycloak_releases}" >/dev/null; then
    keycloak_initial=true
  fi
fi
governance_initial=false
if jq -e --arg name "${NS:-openshell-agents}" \
    '.items | any(.metadata.name == $name)' <<<"${namespaces}" >/dev/null; then
  governance_releases="$(helm list -n "${NS:-openshell-agents}" -o json)"
  if jq -e '. | any(.name == "governance-interceptor" or
                     .name == "governance-policy")' \
      <<<"${governance_releases}" >/dev/null; then
    if jq -e '. | any(.name == "governance-interceptor") and
                   any(.name == "governance-policy")' \
        <<<"${governance_releases}" >/dev/null; then
      governance_initial=true
    else
      echo "Error: one governance release exists without the other." >&2
      exit 1
    fi
  fi
fi
if "${repo}/scripts/pattern-exists.sh"; then
  echo "Error: this test requires a cluster without an existing pattern install." >&2
  exit 1
else
  rc=$?
  if (( rc != 1 )); then exit "${rc}"; fi
fi
if jq -e --arg manual "${namespace}" --arg pattern "${pattern_namespace}" \
    '.items | any(.metadata.name == $manual or .metadata.name == $pattern)' \
    <<<"${namespaces}" >/dev/null; then
  echo "Error: a test SAW namespace exists. Use fresh names to protect existing work." >&2
  exit 1
fi

evidence="${TEST_EVIDENCE_FILE:-${repo}/local-docs/test-deployment-$(date -u +%Y-%m-%dT%H:%M:%SZ).tsv}"
umask 077
mkdir -p "$(dirname "${evidence}")"
printf 'timestamp\tcommit\tcontext\tcheck\texit_code\tdetail\n' > "${evidence}"
status_file="$(mktemp)"
status_error_file="$(mktemp)"
check_file="$(mktemp)"
manual_started=false
pattern_started=false
keycloak_started=false
governance_started=false
test_complete=false

record() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${commit}" "${context}" "$1" "$2" "${3:-}" \
    >> "${evidence}"
}
run() {
  local label="$1" rc
  shift
  echo "=== ${label} ==="
  if "$@"; then rc=0; else rc=$?; fi
  record "${label}" "${rc}"
  if (( rc != 0 )); then
    echo "Error: ${label} failed with exit code ${rc}. Evidence: ${evidence}" >&2
    exit "${rc}"
  fi
}
run_check() {
  local label="$1" script="$2" active_name="$3" expected="$4" rc digest bytes status
  echo "=== ${label} ==="
  if TEST_ACTIVE_SAW_NAME="${active_name}" \
      TEST_ACTIVE_SAW_NS="saw-${active_name}" \
      "${script}" > "${check_file}"; then rc=0; else rc=$?; fi
  digest="$(openssl dgst -sha256 "${check_file}" | awk '{print $NF}')"
  bytes="$(wc -c < "${check_file}" | tr -d ' ')"
  if (( rc != 0 )); then
    record "${label}" "${rc}" "output_sha256=${digest};output_bytes=${bytes}"
    echo "Error: ${label} failed with exit code ${rc}. Check output stayed private." >&2
    exit "${rc}"
  fi
  if ! jq -e --arg expected "${expected}" \
      '.result == $expected and (.status_code | type == "number") and
       (if $expected == "denied" then .status_code == 403
        else .status_code >= 200 and .status_code < 300 end)' \
      "${check_file}" >/dev/null; then
    record "${label}" 1 "invalid request result;output_sha256=${digest}"
    echo "Error: ${label} did not report the required request result." >&2
    exit 1
  fi
  status="$(jq -r '.status_code' "${check_file}")"
  record "${label}" 0 "result=${expected};status_code=${status};output_sha256=${digest}"
}
cleanup_on_exit() {
  local rc=$?
  trap - EXIT
  rm -f "${status_file}" "${status_error_file}" "${check_file}"
  if [[ "${test_complete}" != true ]]; then
    echo "A test stopped. Cleaning up resources owned by this test." >&2
    if [[ "${pattern_started}" == true ]]; then
      if ./pattern.sh make uninstall; then
        record failure.pattern-uninstall 0
      else
        record failure.pattern-uninstall "$?"
      fi
      if delete_pattern_namespace; then
        record failure.pattern-namespace 0
      else
        record failure.pattern-namespace "$?"
      fi
    fi
    if [[ "${manual_started}" == true ]]; then
      if make saw-delete; then record failure.saw-delete 0; else record failure.saw-delete "$?"; fi
    fi
    if [[ "${governance_started}" == true && "${governance_initial}" == false ]]; then
      if make governance-delete; then record failure.governance-delete 0; else record failure.governance-delete "$?"; fi
    fi
    if [[ "${keycloak_started}" == true && "${keycloak_initial}" == false ]]; then
      if make keycloak-delete; then record failure.keycloak-delete 0; else record failure.keycloak-delete "$?"; fi
    fi
    echo "Review ${evidence} and any reported cleanup failure." >&2
  fi
  exit "${rc}"
}
trap cleanup_on_exit EXIT
confirm() {
  local label="$1" answer
  echo "Complete ${label} in a separate terminal. Enter yes only after it passes."
  if ! read -r answer; then answer=""; fi
  if [[ "${answer}" == yes ]]; then
    record "${label}" 0
  else
    record "${label}" 1
    echo "Error: ${label} was not verified. Evidence: ${evidence}" >&2
    exit 1
  fi
}
wait_for_installer() {
  local label="$1" name="$2" deadline phase
  deadline=$((SECONDS + 2400))
  while (( SECONDS < deadline )); do
    if OPENSHELL_SAW_NAME="${name}" SAW_NS="saw-${name}" \
        make saw-status > "${status_file}" 2> "${status_error_file}"; then
      if ! jq -e 'type == "object"' "${status_file}" >/dev/null; then
        record "${label}" 1 "status output was not JSON"
        echo "Error: saw-status did not return JSON." >&2
        return 1
      fi
      if jq -e '.install.phase == "Done" and .apply.phase == "Done"' \
          "${status_file}" >/dev/null; then
        record "${label}" 0
        echo "Both installer phases are Done for ${name}."
        return 0
      fi
      phase="$(jq -r '[.install.phase // "Pending", .apply.phase // "Pending"] | join("/")' \
        "${status_file}")"
      if [[ "${phase}" == *Failed* ]]; then
        echo "Error: installer phase is ${phase}." >&2
        record "${label}" 1
        return 1
      fi
      echo "Installer phases for ${name}: ${phase}."
    else
      cat "${status_error_file}" >&2
      if grep -Eiq 'Forbidden|Unauthorized|permission denied|secrets?.*not found' \
          "${status_error_file}"; then
        record "${label}" 1 "status access failed"
        echo "Error: saw-status failed due to access or missing Secret." >&2
        return 1
      fi
      echo "VM status is not ready yet; retrying."
    fi
    sleep 15
  done
  record "${label}" 1
  echo "Error: installer did not finish within 2400 seconds." >&2
  return 1
}
check_argo_revision() {
  local label="$1" applications
  applications="$(oc get applications.argoproj.io -n "${ARGOCD_NS:-vp-gitops}" \
    -l "openshell.pattern/owner=${TEST_PATTERN_SAW_NAME}" -o json)"
  if jq -e --arg commit "${commit}" \
      '.items | length >= 3 and all(.[];
        .status.sync.revision == $commit and .status.sync.status == "Synced" and
        .status.health.status == "Healthy")' <<<"${applications}" >/dev/null; then
    record "${label}" 0 "all owner applications synced and healthy at ${commit}"
  else
    record "${label}" 1 "Argo CD revision or health differs from ${commit}"
    echo "Error: Argo CD did not deploy the tested commit for the pattern SAW." >&2
    return 1
  fi
}
delete_pattern_namespace() {
  local namespaces owned
  namespaces="$(oc get namespaces -o json)"
  owned="$(jq -r --arg name "${pattern_namespace}" \
    --arg owner "${TEST_PATTERN_SAW_NAME}" --arg argo "${ARGOCD_NS:-vp-gitops}" \
    '.items[] | select(.metadata.name == $name) |
      select(.metadata.labels["openshell.pattern/saw"] == "true" and
             .metadata.labels["openshell.pattern/owner"] == $owner and
             .metadata.labels["argocd.argoproj.io/managed-by"] == $argo) |
      .metadata.name' <<<"${namespaces}")"
  if [[ -z "${owned}" ]]; then
    if jq -e --arg name "${pattern_namespace}" \
        '.items | any(.metadata.name == $name)' <<<"${namespaces}" >/dev/null; then
      echo "Error: ${pattern_namespace} remains without expected ownership labels." >&2
      return 1
    fi
    return 0
  fi
  if jq -e '.items | length > 0' \
      <<<"$(oc get vm -n "${pattern_namespace}" -o json)" >/dev/null; then
    echo "Error: pattern VM remains in ${pattern_namespace}." >&2
    return 1
  fi
  oc delete namespace "${pattern_namespace}" --wait=false
  wait_for_namespace_absent pattern.namespace-removed "${pattern_namespace}"
}
wait_for_namespace_absent() {
  local label="$1" target="$2" deadline namespaces
  deadline=$((SECONDS + 600))
  while (( SECONDS < deadline )); do
    namespaces="$(oc get namespaces -o json)"
    if ! jq -e --arg ns "${target}" '.items | any(.metadata.name == $ns)' \
        <<<"${namespaces}" >/dev/null; then
      record "${label}" 0
      return 0
    fi
    sleep 10
  done
  record "${label}" 1
  echo "Error: namespace ${target} remains after cleanup." >&2
  return 1
}
secret_hash() {
  local name="$1" target="$2"
  oc get secret "${name}" -n "${target}" -o json |
    jq -eSc '.data | select(type == "object" and length > 0)' |
    openssl dgst -sha256 | awk '{print $NF}'
}
check_repeat_state() {
  local label="$1" before="$2" after="$3"
  if [[ "${before}" == "${after}" ]]; then
    record "${label}" 0
  else
    record "${label}" 1
    echo "Error: ${label} changed credentials during repeat setup." >&2
    exit 1
  fi
}

echo "Testing commit ${commit} on context ${context}. Evidence: ${evidence}"
record version.oc-client 0 "$(oc version --client | sed -n '1p')"
record version.helm 0 "$(helm version --short)"
record version.gateway-image 0 "${OPENSHELL_VERSION:-0.0.116}"
record version.interceptor 0 "${OPENSHELL_INTERCEPTOR_REF:-v0.1.2}"
record version.bom-gateway 0 "$(awk '/^      gateway:/{getline; print $2; exit}' charts/openshell-saw/values.yaml)"
record initial.saw-namespaces 0 "$(jq -r '[.items[].metadata.name |
  select(startswith("saw-"))] | join(",")' <<<"${namespaces}")"
record initial.virtual-machines 0 "$(oc get vm -A -o json | jq -r \
  '[.items[] | "\(.metadata.namespace)/\(.metadata.name)"] | join(",")')"
record initial.operators 0 "$(oc get csv -A -o json | jq -r \
  '[.items[] | "\(.metadata.namespace)/\(.metadata.name)"] | join(",")')"
run manual.prereqs make quickstart-prereqs-check
confirm 'initial.capacity: confirm a virtualization node has at least 4 vCPU, 8 GiB memory, and 40 GiB suitable storage'
run manual.keys make ssh-key-generate
run manual.images make images-mirror
keycloak_started=true
run manual.keycloak make keycloak-deploy
run manual.keycloak-check make keycloak-check
governance_started=true
run manual.governance make governance-deploy
run manual.login make login
run manual.whoami make whoami
manual_started=true
run manual.saw-create make saw-create
run manual.saw-list make saw-list
wait_for_installer manual.installer "${TEST_SAW_NAME}"
keycloak_hash="$(secret_hash openshell-keycloak-user-passwords "${KEYCLOAK_NS:-saw-keycloak}")"
inference_hash="$(secret_hash inference "${namespace}")"
run manual.saw-configure make saw-configure
run manual.vm-ssh make saw-vm-ssh CMD=true
run manual.alias make openshell-saw-list

confirm 'manual.saw-logs: make saw-logs FOLLOW=false'
confirm 'manual.saw-ssh: make saw-ssh and exit the shell'
confirm 'manual.saw-tui: make saw-tui and exit the TUI'
confirm 'manual.saw-gui: make saw-gui and stop the forward'
run_check manual.inference "${TEST_INFERENCE_CHECK}" "${TEST_SAW_NAME}" accepted
run_check manual.owner-access "${TEST_OWNER_ACCESS_CHECK}" "${TEST_SAW_NAME}" allowed
run_check manual.second-user-denied "${TEST_SECOND_USER_DENIED_CHECK}" "${TEST_SAW_NAME}" denied

run repeat.keys make ssh-key-generate
run repeat.keycloak make keycloak-deploy
run repeat.saw-create make saw-create
wait_for_installer repeat.installer "${TEST_SAW_NAME}"
check_repeat_state repeat.keycloak-credentials "${keycloak_hash}" \
  "$(secret_hash openshell-keycloak-user-passwords "${KEYCLOAK_NS:-saw-keycloak}")"
check_repeat_state repeat.inference-credentials "${inference_hash}" \
  "$(secret_hash inference "${namespace}")"
releases="$(helm list -n "${namespace}" -o json)"
if [[ "$(jq -r --arg name "${TEST_SAW_NAME}" \
    '[.[] | select(.name == $name)] | length' <<<"${releases}")" != 1 ]]; then
  record repeat.single-release 1
  echo "Error: repeat setup left a missing or duplicate SAW release." >&2
  exit 1
fi
record repeat.single-release 0
run manual.saw-delete make saw-delete
manual_started=false
wait_for_namespace_absent manual.cleanup "${namespace}"
run manual.saw-delete-again make saw-delete
if [[ "${governance_initial}" == false ]]; then
  run manual.governance-delete make governance-delete
fi
governance_started=false
if [[ "${keycloak_initial}" == false ]]; then
  run manual.keycloak-delete make keycloak-delete
fi
keycloak_started=false

pattern_started=true
run pattern.install ./pattern.sh make install
run pattern.health ./pattern.sh make argo-healthcheck
check_argo_revision pattern.revision
wait_for_installer pattern.installer "${TEST_PATTERN_SAW_NAME}"
pattern_inference_hash="$(secret_hash inference "${pattern_namespace}")"
pattern_search_hash="$(secret_hash web-search "${pattern_namespace}")"
record pattern.secret-delivery 0 "inference and web-search Secrets exist"
run_check pattern.owner-access "${TEST_OWNER_ACCESS_CHECK}" "${TEST_PATTERN_SAW_NAME}" allowed
run_check pattern.second-user-denied "${TEST_SECOND_USER_DENIED_CHECK}" "${TEST_PATTERN_SAW_NAME}" denied
run pattern.uninstall ./pattern.sh make uninstall
run pattern.namespace-delete delete_pattern_namespace
run pattern.uninstall-again ./pattern.sh make uninstall
run pattern.remirror make images-mirror
run pattern.reinstall ./pattern.sh make install
run pattern.reinstall-health ./pattern.sh make argo-healthcheck
check_argo_revision pattern.reinstall-revision
wait_for_installer pattern.reinstall-installer "${TEST_PATTERN_SAW_NAME}"
check_repeat_state pattern.inference-credentials "${pattern_inference_hash}" \
  "$(secret_hash inference "${pattern_namespace}")"
check_repeat_state pattern.web-search-credentials "${pattern_search_hash}" \
  "$(secret_hash web-search "${pattern_namespace}")"
run pattern.final-uninstall ./pattern.sh make uninstall
run pattern.final-namespace-delete delete_pattern_namespace
pattern_started=false
test_complete=true
echo "Live deployment checks passed. Review evidence in ${evidence}."
