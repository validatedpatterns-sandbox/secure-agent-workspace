#!/usr/bin/env bash
# Live end-to-end check of one SAW user's workspace, for any deployment mode.
#
# Follows the README: a user added in overrides/saw-users.yaml, deployed by
# Argo CD. This script changes nothing on the cluster except one OpenClaw
# turn inside the user's own sandbox (which adds one tool-gate audit entry).
#
#   W1  Argo CD applications for the user are Synced and Healthy
#   W2  sandbox is running (container/kata: supervisor + workload Ready;
#       vm: VirtualMachineInstance Running and the gateway answers)
#   W3  kata only: workload and supervisor Pods both run in the Kata
#       RuntimeClass; each Kata Pod is its own VM, so that is two VMs
#   W4  OpenClaw answers a real turn through the user's inference profile
#       (a random nonce must come back, so a cached or canned reply fails;
#       the turn also asks for one tool call, which the gate may deny)
#   W5  container/kata: the tool gate recorded that turn's tool call
#       (local log by default; receipts mode is reported, not checked here)
#   W6  container/kata: a fresh OCSF body for this sandbox reached the collector
#
# Usage:
#   scripts/e2e-workspace.sh --mode container|kata|vm --user NAME
#                            [--sandbox notebook] [--workspace default]
#                            [--kata-class saw-kata] [--argo-namespace vp-gitops]
#   make e2e-workspace MODE=container SAW_USER=alice
#
# Needs: oc logged in with exec rights in the user's runtime namespace.
# vm mode also needs the openshell CLI with a gateway named after the user
# (README: "Connect with the OpenShell CLI").

set -euo pipefail

MODE="" USER_NAME="" SANDBOX="${SANDBOX:-notebook}" WORKSPACE="${WORKSPACE:-default}"
KATA_CLASS="${KATA_CLASS:-saw-kata}" ARGO_NS="${ARGO_NAMESPACE:-vp-gitops}"
COLLECTOR_NS="${COLLECTOR_NS:-openshell-agents}"
COLLECTOR_SELECTOR="${COLLECTOR_SELECTOR:-app.kubernetes.io/name=saw-ocsf-collector}"
TURN_TIMEOUT="${TURN_TIMEOUT:-180}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --sandbox) SANDBOX="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --kata-class) KATA_CLASS="$2"; shift 2 ;;
    --argo-namespace) ARGO_NS="$2"; shift 2 ;;
    -h|--help) sed -n '/^# Usage:/,/^$/p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done
case "${MODE}" in container|kata|vm) ;; *) echo "Error: --mode container|kata|vm" >&2; exit 2 ;; esac
[[ "${USER_NAME}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || { echo "Error: --user NAME" >&2; exit 2; }

NS="saw-${USER_NAME}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
FAILED=0
step() { echo -e "\n${CYAN}=== $1 ===${NC}"; }
pass() { echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAILED=1; }
note() { echo -e "  ${YELLOW}NOTE${NC} $1"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }
# macOS has no timeout(1); use coreutils' gtimeout when present, else none.
limit() {
  if command -v timeout >/dev/null; then timeout "${TURN_TIMEOUT}" "$@"
  elif command -v gtimeout >/dev/null; then gtimeout "${TURN_TIMEOUT}" "$@"
  else "$@"; fi
}

command -v oc >/dev/null || { echo "Error: oc is required" >&2; exit 2; }
oc get namespace "${NS}" >/dev/null 2>&1 || { echo "Error: namespace ${NS} not found; is ${USER_NAME} deployed?" >&2; exit 1; }
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

step "W1 Argo CD applications"
REG="$(oc get namespace "${NS}" -o jsonpath='{.metadata.labels.saw\.redhat\.com/registration}')"
apps="$(oc get applications.argoproj.io -n "${ARGO_NS}" -o json | json "
user, reg = '${USER_NAME}', '${REG}'
for a in d['items']:
    n = a['metadata']['name']
    if n in ('saw-'+user, 'saw-'+user+'-bom') or (reg and n.startswith('saw-c-'+reg+'-')) or n.endswith('-'+user) and n.startswith('saw-projector-'):
        s = a.get('status', {})
        print(n, s.get('sync', {}).get('status'), s.get('health', {}).get('status'))")"
if [[ -z "${apps}" ]]; then
  fail "no Argo CD applications found for ${USER_NAME} in ${ARGO_NS}"
else
  while read -r name sync health; do
    if [[ "${sync}" == Synced && "${health}" == Healthy ]]; then pass "${name}"; else fail "${name}: ${sync}/${health}"; fi
  done <<< "${apps}"
fi

# In-sandbox turn. Arguments: config path, OpenClaw home, nonce.
read -r -d '' TURN <<'SH' || true
set -eu
cfg="$1"; home="$2"; nonce="$3"
export HOME="$home" OPENCLAW_HOME="$home" OPENCLAW_CONFIG_PATH="$cfg"
export TMPDIR="$(dirname "$cfg")/state" SQLITE_TMPDIR="$(dirname "$cfg")/state"
[ -f "$cfg" ] || { echo "no OpenClaw config at $cfg"; exit 3; }
mode=$(node -e 'process.stdout.write(String(require(process.argv[1]).gateway.auth.mode||""))' "$cfg")
secret=$(node -e 'const a=require(process.argv[1]).gateway.auth;process.stdout.write(a.password||a.token||"")' "$cfg")
[ -n "$secret" ] || { echo "no gateway secret in $cfg"; exit 3; }
if [ "$mode" = token ]; then export OPENCLAW_GATEWAY_TOKEN="$secret"; else export OPENCLAW_GATEWAY_PASSWORD="$secret"; fi
unset secret
openclaw agent --agent main --message "Try to run the shell command date once; it may be denied, and that is fine. Whatever happens, finish your reply with this exact line: $nonce"
SH

NONCE="SAW_E2E_$(python3 -c 'import secrets; print(secrets.token_hex(4).upper())')"

if [[ "${MODE}" == vm ]]; then
  step "W2 VM and gateway"
  phase="$(oc get vmi -n "${NS}" -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)"
  [[ "${phase}" == Running ]] && pass "VirtualMachineInstance Running" || fail "VirtualMachineInstance phase: ${phase:-none}"
  command -v openshell >/dev/null || { fail "openshell CLI not installed"; exit 1; }
  sandboxes="$(openshell --gateway "${USER_NAME}" sandbox list --workspace "${WORKSPACE}" 2>/dev/null || true)"
  if grep -qw "${SANDBOX}" <<< "${sandboxes}"; then
    pass "gateway ${USER_NAME} lists sandbox ${SANDBOX}"
  else
    fail "gateway ${USER_NAME} does not list sandbox ${SANDBOX} (is the CLI logged in?)"
  fi
  run_turn() {
    limit openshell --gateway "${USER_NAME}" sandbox exec -n "${SANDBOX}" \
      --workspace "${WORKSPACE}" --no-tty -- bash -c "${TURN}" turn \
      /sandbox/.openclaw/openclaw.json /sandbox "${NONCE}"
  }
else
  step "W2 sandbox Pods"
  SANDBOX_ID="$(oc get sandboxes.agents.x-k8s.io -n "${NS}" "${WORKSPACE}--${SANDBOX}" \
    -o jsonpath='{.metadata.labels.openshell\.ai/sandbox-id}' 2>/dev/null || true)"
  [[ -n "${SANDBOX_ID}" ]] || { fail "no sandbox identity for ${WORKSPACE}/${SANDBOX}"; exit 1; }
  pod_of() { oc get pods -n "${NS}" -l "openshell.ai/boundary-role=$1,openshell.ai/boundary-pair=${SANDBOX_ID}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true; }
  WORKLOAD="$(pod_of workload)" SUPERVISOR="$(pod_of supervisor)"
  for pod in "${SUPERVISOR}" "${WORKLOAD}"; do
    if [[ -z "${pod}" ]]; then fail "missing supervisor or workload Pod in ${NS}"; continue; fi
    ready="$(oc get pod -n "${NS}" "${pod}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
    [[ "${ready}" == True ]] && pass "${pod} Ready" || fail "${pod} not Ready"
  done
  [[ -n "${WORKLOAD}" ]] || { echo; echo "No workload Pod; stopping."; exit 1; }

  if [[ "${MODE}" == kata ]]; then
    step "W3 Kata runtime"
    rc="$(oc get pod -n "${NS}" "${WORKLOAD}" -o jsonpath='{.spec.runtimeClassName}')"
    [[ "${rc}" == "${KATA_CLASS}" ]] && pass "workload runs in ${KATA_CLASS}" || fail "workload runtimeClassName: ${rc:-none}"
    rc="$(oc get pod -n "${NS}" "${SUPERVISOR}" -o jsonpath='{.spec.runtimeClassName}' 2>/dev/null || true)"
    [[ "${rc}" == "${KATA_CLASS}" ]] && pass "supervisor runs in its own ${KATA_CLASS} VM" || fail "supervisor runtimeClassName: ${rc:-none}"
  fi

  AUDIT=/sandbox/.saw/audit/tool-actions.jsonl
  before="$(oc exec -n "${NS}" "${WORKLOAD}" -c agent -- sh -c "wc -l < ${AUDIT} 2>/dev/null || echo missing" | tr -d ' ')"
  run_turn() {
    limit oc exec -n "${NS}" "${WORKLOAD}" -c agent -- bash -c "${TURN}" turn \
      /sandbox/workspace/.openclaw/openclaw.json /sandbox/workspace "${NONCE}"
  }
fi

step "W4 OpenClaw inference turn"
if out="$(run_turn 2>&1)"; then status=0; else status=$?; fi
if grep -qF "${NONCE}" <<< "${out}"; then
  pass "model returned the nonce through the user's inference profile"
else
  fail "no nonce in the reply (exit ${status}):"; sed 's/^/    /' <<< "${out}" | tail -n 12
fi

if [[ "${MODE}" != vm ]]; then
  step "W5 tool-gate audit"
  if oc get namespace "saw-history-${REG}" >/dev/null 2>&1; then
    note "auditReceipts mode: receipts go to saw-history-${REG}; local log not checked"
  elif [[ "${before}" == missing ]]; then
    fail "${AUDIT} does not exist"
  else
    entry="$(oc exec -n "${NS}" "${WORKLOAD}" -c agent -- sh -c "tail -n +$((before + 1)) ${AUDIT}" 2>/dev/null || true)"
    if [[ -z "${entry}" ]]; then
      fail "no new entry in ${AUDIT} (the agent made no tool call?)"
    else
      summary="$(printf '%s\n' "${entry}" | tail -n 1 | json "print(d.get('tool'), d.get('decision'), d.get('user', {}).get('username'))" 2>/dev/null || echo unparsable)"
      read -r tool decision who <<< "${summary}"
      if [[ -n "${decision}" && "${decision}" != None && "${who}" == "${USER_NAME}" ]]; then
        pass "gate recorded ${tool}: ${decision} for ${who}"
      else
        fail "unexpected audit entry: ${summary}"
      fi
    fi
  fi

  step "W6 OCSF export"
  collector="$(oc get pods -n "${COLLECTOR_NS}" -l "${COLLECTOR_SELECTOR}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [[ -z "${collector}" ]]; then
    fail "no OCSF collector Pod in ${COLLECTOR_NS}"
  else
    found=0
    for attempt in 1 2 3 4 5 6; do
      if event="$(oc logs -n "${COLLECTOR_NS}" -l "${COLLECTOR_SELECTOR}" --tail=-1 --since-time="${START}" 2>/dev/null \
          | python3 "${SCRIPT_DIR}/check-ocsf-record.py" --sandbox-id "${SANDBOX_ID}" --since "${START}")"; then
        pass "collector preserved a fresh OCSF body: ${event}"
        found=1
        break
      fi
      (( attempt == 6 )) || sleep 5
    done
    (( found )) || fail "no fresh OCSF body for sandbox ${SANDBOX_ID}; W6 requires detailed collector log output"
  fi
fi

echo
if (( FAILED )); then echo -e "${RED}${MODE} workspace for ${USER_NAME}: FAILED${NC}"; exit 1; fi
echo -e "${GREEN}${MODE} workspace for ${USER_NAME}: all checks passed${NC}"
