#!/usr/bin/env bash
# NetworkPolicy isolation checks. Offline assertions always run; live probes
# need a logged-in oc context and the named test SAW(s).
#
#   SKIP_LIVE=1 ./tests/test-network-policy.sh
#   SAW_NS=saw-nptest-a VM_NAME=nptest-a PEER_NS=saw-nptest-b \
#     PEER_VM_NAME=nptest-b REQUIRE_PEER=1 ./tests/test-network-policy.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON="${PYTHON:-python3}"
SAW_NS="${SAW_NS:-saw-test}"
VM_NAME="${VM_NAME:-saw-test}"
PEER_NS="${PEER_NS:-}"
PEER_VM_NAME="${PEER_VM_NAME:-}"
KEYCLOAK_NS="${KEYCLOAK_NS:-saw-keycloak}"
CURL_TIMEOUT="${CURL_TIMEOUT:-8}"
PASS=0
FAIL=0
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }
finish() { echo; echo "${PASS} passed, ${FAIL} failed"; [[ "${FAIL}" -eq 0 ]]; }

echo "== offline chart checks =="
for tool in helm "${PYTHON}"; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "${tool} is required" >&2
    exit 1
  fi
done

if helm template saw-test "${ROOT}/charts/openshell-saw" -n "${SAW_NS}" \
    -f "${ROOT}/tests/fixtures/saw-network-topology.yaml" \
    --set sandboxName=saw-test >"${tmpdir}/rendered.yaml"; then
  pass "chart renders with NetworkPolicies enabled"
else
  fail "chart renders with NetworkPolicies enabled"
  finish
  exit $?
fi

if "${PYTHON}" - "${tmpdir}/rendered.yaml" <<'PY'
import sys
import yaml

docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
policies = {d['metadata']['name']: d for d in docs if d['kind'] == 'NetworkPolicy'}
assert set(policies) == {'saw-default-deny', 'saw-vm', 'saw-cdi-import', 'saw-cleanup-hook'}, policies.keys()
deny = policies['saw-default-deny']['spec']
assert deny == {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']}, deny
vm = policies['saw-vm']['spec']
assert vm['podSelector']['matchLabels'] == {'openshell.pattern/role': 'gateway'}
assert policies['saw-cdi-import']['spec']['podSelector']['matchLabels'] == {'app': 'containerized-data-importer'}
assert policies['saw-cleanup-hook']['spec']['podSelector']['matchLabels'] == {'openshell.pattern/role': 'cleanup'}
assert policies['saw-cleanup-hook']['spec']['egress'] == [
    {'to': [{'ipBlock': {'cidr': '172.30.0.1/32'}}], 'ports': [{'protocol': 'TCP', 'port': 443}]},
    {'to': [{'ipBlock': {'cidr': '192.0.2.10/32'}}], 'ports': [{'protocol': 'TCP', 'port': 6443}]},
]
assert next(d for d in docs if d['kind'] == 'Pod' and d['metadata']['name'] == 'saw-test-cleanup')['metadata']['labels']['openshell.pattern/role'] == 'cleanup'
for name in ('saw-vm', 'saw-cdi-import'):
    spec = policies[name]['spec']
    for direction, key in [('ingress', 'from'), ('egress', 'to')]:
        for rule in spec.get(direction) or []:
            assert rule.get(key), (name, direction, rule)
            assert all(rule[key]), (name, direction, rule)
            assert all(port['port'] != 6443 for port in rule.get('ports', []))
            for peer in rule[key]:
                assert peer.get('namespaceSelector') != {}
                if 'ipBlock' in peer:
                    block = peer['ipBlock']
                    assert block['cidr'] == '0.0.0.0/0' and block['except']
                    assert {'10.128.0.0/14', '172.30.0.0/16', '169.254.0.0/16', '192.0.2.10/32'} <= set(block['except'])
dns = next(r for r in vm['egress'] if {'protocol': 'UDP', 'port': 5353} in r.get('ports', []))
assert {'protocol': 'TCP', 'port': 5353} in dns['ports']
assert dns['to'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'] == 'openshift-dns'
router = next(r for r in vm['ingress'] if r['from'][0]['namespaceSelector']['matchLabels'].get('policy-group.network.openshift.io/ingress') == '')
assert router['from'][0]['podSelector'] == {}
assert {p['port'] for p in router['ports']} == {17670, 18789, 8080}
ssh = next(r for r in vm['ingress'] if {'protocol': 'TCP', 'port': 22} in r.get('ports', []))
assert ssh['from'] == [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'openshift-cnv'}}, 'podSelector': {'matchLabels': {'kubevirt.io': 'virt-api'}}}]
assert ssh['ports'] == [{'protocol': 'TCP', 'port': 22}]
firewall = next(d for d in docs if d['kind'] == 'EgressFirewall')['spec']['egress']
api_rules = [r for r in firewall if r.get('to', {}).get('cidrSelector') == '192.0.2.10/32']
assert api_rules == [{'type': 'Allow', 'to': {'cidrSelector': '192.0.2.10/32'}, 'ports': [{'protocol': 'TCP', 'port': 6443}]}]
firewall_ports = {p['port'] for r in firewall if r['type'] == 'Allow' and r not in api_rules for p in r['ports']}
outside = next(r for r in vm['egress'] if 'ipBlock' in r['to'][0])
assert firewall_ports <= {p['port'] for p in outside['ports']}
assert 6443 not in {p['port'] for p in outside['ports']}
PY
then
  pass "default-deny, scoped peers, ingress, CIDRs and firewall port parity"
else
  fail "default-deny, scoped peers, ingress, CIDRs and firewall port parity"
fi

if helm template saw-test "${ROOT}/charts/openshell-saw" -n "${SAW_NS}" \
    -f "${ROOT}/tests/fixtures/saw-network-topology.yaml" \
    --set sandboxName=saw-test --set networkPolicy.enabled=false 2>/dev/null \
    | grep -q 'kind: NetworkPolicy'; then
  fail "networkPolicy.enabled=false removes the policies"
else
  pass "networkPolicy.enabled=false removes the policies"
fi

echo
echo "== live cluster checks =="
if [[ "${SKIP_LIVE:-}" == "1" ]]; then
  echo "  SKIP  live checks (SKIP_LIVE=1)"
  finish
  exit $?
fi
if ! command -v oc >/dev/null 2>&1; then
  fail "oc is installed"
  finish
  exit $?
fi
if [[ -n "${EXPECTED_CONTEXT:-}" && "$(oc config current-context)" != "${EXPECTED_CONTEXT}" ]]; then
  fail "oc context matches EXPECTED_CONTEXT"
  finish
  exit $?
fi
if ! oc get namespace "${SAW_NS}" >/dev/null 2>&1; then
  fail "${SAW_NS} exists"
  finish
  exit $?
fi
if ! oc get vm "${VM_NAME}" -n "${SAW_NS}" >/dev/null 2>&1; then
  fail "${SAW_NS}/${VM_NAME} VM exists"
  finish
  exit $?
fi
if ! oc get networkpolicy -n "${SAW_NS}" -o json >"${tmpdir}/policies.json"; then
  fail "read live NetworkPolicies"
  finish
  exit $?
fi
if "${PYTHON}" - "${tmpdir}/policies.json" <<'PY'
import json, sys
items = json.load(open(sys.argv[1]))['items']
names = {i['metadata']['name'] for i in items}
assert {'saw-default-deny', 'saw-vm', 'saw-cdi-import', 'saw-cleanup-hook'} <= names, names
for item in items:
    spec = item['spec']
    if item['metadata']['name'] == 'saw-default-deny':
        assert not spec.get('ingress') and not spec.get('egress')
    for direction, key in (('ingress', 'from'), ('egress', 'to')):
        for rule in spec.get(direction) or []:
            assert rule.get(key) and all(rule[key]), (item['metadata']['name'], rule)
            for peer in rule[key]:
                assert peer.get('namespaceSelector') != {}
                if 'ipBlock' in peer and item['metadata']['name'] != 'saw-cleanup-hook':
                    assert peer['ipBlock'].get('except')
                if item['metadata']['name'] == 'saw-cleanup-hook':
                    assert peer.get('ipBlock', {}).get('cidr', '').endswith('/32')
                    assert rule.get('ports')
PY
then
  pass "live policies exist and have no allow-all rule"
else
  fail "live policies exist and have no allow-all rule"
fi

if oc get network.config cluster -o json >"${tmpdir}/network.json" && \
    "${PYTHON}" - "${tmpdir}/network.json" "${tmpdir}/policies.json" <<'PY'
import ipaddress, json, sys
network = json.load(open(sys.argv[1]))['status']
policies = {i['metadata']['name']: i for i in json.load(open(sys.argv[2]))['items']}
for name in ('saw-vm', 'saw-cdi-import'):
    rules = policies[name]['spec']['egress']
    blocks = [peer['ipBlock'] for r in rules for peer in r['to'] if 'ipBlock' in peer]
    if not blocks:
        if name == 'saw-cdi-import':
            continue
        raise AssertionError(f'{name}: missing outside rule')
    block = blocks[0]
    excluded = [ipaddress.ip_network(c) for c in block['except']]
    for field in ('clusterNetwork', 'serviceNetwork'):
        for entry in network[field]:
            value = entry['cidr'] if isinstance(entry, dict) else entry
            actual = ipaddress.ip_network(value)
            assert any(actual.subnet_of(e) for e in excluded), f'{name}: {value} is not excluded'
    assert any(ipaddress.ip_network('169.254.0.0/16').subnet_of(e) for e in excluded)
PY
then
  pass "outside rules exclude every live pod/service CIDR and link-local"
else
  fail "outside rules exclude every live pod/service CIDR and link-local"
fi

vm_cmd() {
  SAW_NS="$1" VM_NAME="$2" "${ROOT}/scripts/openshell-saw-vm-ssh.sh" "$3"
}

if vm_cmd "${SAW_NS}" "${VM_NAME}" true >/dev/null 2>&1; then
  pass "VM SSH probe path works"
else
  fail "VM SSH probe path works"
  finish
  exit $?
fi

http_probe() {
  local ns="$1" vm="$2" url="$3" output
  output="$(vm_cmd "${ns}" "${vm}" "curl -k -m ${CURL_TIMEOUT} -sS -o /dev/null -w '%{http_code}' '${url}'; printf ' rc=%s' \$?" 2>/dev/null)" || return 1
  printf '%s\n' "${output##*$'\n'}"
}
expect_blocked_http() {
  local desc="$1" ns="$2" vm="$3" url="$4" result
  if result="$(http_probe "${ns}" "${vm}" "${url}")" && [[ "${result}" == 000\ rc=* ]]; then
    pass "${desc} (${result})"
  else
    fail "${desc} (got ${result:-no response})"
  fi
}
expect_reachable_http() {
  local desc="$1" ns="$2" vm="$3" url="$4" result code
  result="$(http_probe "${ns}" "${vm}" "${url}")" || result=""
  code="${result%% *}"
  if [[ "${code}" =~ ^[1-5][0-9][0-9]$ ]]; then
    pass "${desc} (${result})"
  else
    fail "${desc} (got ${result:-no response})"
  fi
}
tcp_probe() {
  local ns="$1" vm="$2" host="$3" port="$4" output
  output="$(vm_cmd "${ns}" "${vm}" \
    "if timeout 8 bash -c 'exec 3<>/dev/tcp/${host}/${port}' >/dev/null 2>&1; then echo NP_TCP_CONNECTED; else echo NP_TCP_BLOCKED; fi" \
    2>/dev/null)" || return 2
  case "${output##*$'\n'}" in
    NP_TCP_CONNECTED) return 0 ;;
    NP_TCP_BLOCKED) return 1 ;;
    *) return 2 ;;
  esac
}
expect_tcp() {
  local desc="$1" sense="$2" ns="$3" vm="$4" host="$5" port="$6" rc
  if tcp_probe "${ns}" "${vm}" "${host}" "${port}"; then
    if [[ "${sense}" == allowed ]]; then pass "${desc}"; else fail "${desc} (connected)"; fi
  else
    rc=$?
    if [[ "${rc}" -eq 1 && "${sense}" == blocked ]]; then
      pass "${desc} (connection failed)"
    elif [[ "${rc}" -eq 2 ]]; then
      fail "${desc} (VM SSH probe failed)"
    else
      fail "${desc} (connection failed)"
    fi
  fi
}

expect_blocked_http "Kubernetes API service name is blocked" "${SAW_NS}" "${VM_NAME}" \
  "https://kubernetes.default.svc/"
expect_blocked_http "Kubernetes API full service name is blocked" "${SAW_NS}" "${VM_NAME}" \
  "https://kubernetes.default.svc.cluster.local/"
service_ip="$(oc get service kubernetes -n default -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
if [[ -n "${service_ip}" ]]; then
  expect_blocked_http "Kubernetes API ClusterIP is blocked" "${SAW_NS}" "${VM_NAME}" \
    "https://${service_ip}/"
else
  fail "Kubernetes API ClusterIP exists"
fi
expect_blocked_http "metadata endpoint is blocked" "${SAW_NS}" "${VM_NAME}" \
  "http://169.254.169.254/"
if oc get endpointslice -n default -l kubernetes.io/service-name=kubernetes -o json >"${tmpdir}/api-endpoints.json"; then
  while read -r ip port; do
    [[ -z "${ip}" ]] && continue
    expect_tcp "Kubernetes API endpoint ${ip}:${port} TCP is blocked" blocked \
      "${SAW_NS}" "${VM_NAME}" "${ip}" "${port}"
    expect_blocked_http "Kubernetes API endpoint ${ip}:${port} HTTPS is blocked" "${SAW_NS}" "${VM_NAME}" \
      "https://${ip}:${port}/"
  done < <("${PYTHON}" - "${tmpdir}/api-endpoints.json" <<'PY'
import json, sys
for item in json.load(open(sys.argv[1])).get('items') or []:
    if item.get('addressType') != 'IPv4':
        continue
    for endpoint in item.get('endpoints') or []:
        if (endpoint.get('conditions') or {}).get('ready') is False:
            continue
        for ip in endpoint.get('addresses') or []:
            for port in item.get('ports') or []:
                if port.get('protocol', 'TCP') == 'TCP':
                    print(ip, port['port'])
PY
)
else
  fail "read Kubernetes API endpoints"
fi

if vm_cmd "${SAW_NS}" "${VM_NAME}" "getent ahostsv4 integrate.api.nvidia.com" >/dev/null 2>&1; then
  pass "VM DNS lookup succeeds"
else
  fail "VM DNS lookup succeeds"
fi
expect_tcp "governance interceptor TCP 18081 is reachable" allowed "${SAW_NS}" "${VM_NAME}" \
  governance-interceptor.openshell-agents.svc.cluster.local 18081
expect_tcp "internal registry TCP 5000 is reachable" allowed "${SAW_NS}" "${VM_NAME}" \
  image-registry.openshift-image-registry.svc.cluster.local 5000
expect_reachable_http "allowed external host answers" "${SAW_NS}" "${VM_NAME}" \
  https://integrate.api.nvidia.com/

issuer_host="$(oc get route -n "${KEYCLOAK_NS}" -o jsonpath='{.items[0].spec.host}' 2>/dev/null || true)"
if [[ -n "${issuer_host}" ]]; then
  expect_reachable_http "Keycloak discovery answers" "${SAW_NS}" "${VM_NAME}" \
    "https://${issuer_host}/realms/openshell/.well-known/openid-configuration"
else
  fail "Keycloak route exists"
fi

route_control() {
  local ns="$1" vm="$2" host code
  host="$(oc get route "${vm}-webui" -n "${ns}" -o jsonpath='{.spec.host}' 2>/dev/null)" || return 1
  [[ -n "${host}" ]] || return 1
  code="$(curl -k -m "${CURL_TIMEOUT}" -sS -o /dev/null -w '%{http_code}' "https://${host}/" 2>/dev/null)" || return 1
  [[ "${code}" =~ ^[1-5][0-9][0-9]$ ]]
}
if route_control "${SAW_NS}" "${VM_NAME}"; then
  pass "VM webui Route answers from outside the cluster"
else
  fail "VM webui Route answers from outside the cluster"
fi

if [[ -n "${PEER_NS}" && -n "${PEER_VM_NAME}" ]] && \
    oc get vm "${PEER_VM_NAME}" -n "${PEER_NS}" >/dev/null 2>&1; then
  peer_ready=true
else
  peer_ready=false
fi
if [[ "${peer_ready}" == false ]]; then
  if [[ "${REQUIRE_PEER:-0}" == "1" ]]; then
    fail "required peer VM exists"
  else
    echo "  SKIP  peer checks (PEER_NS/PEER_VM_NAME missing or VM absent)"
  fi
else
  if route_control "${PEER_NS}" "${PEER_VM_NAME}"; then
    pass "peer webui Route answers from outside the cluster"
  else
    fail "peer webui Route answers from outside the cluster"
  fi
  for pair in "${SAW_NS}:${VM_NAME}:${PEER_NS}:${PEER_VM_NAME}" \
              "${PEER_NS}:${PEER_VM_NAME}:${SAW_NS}:${VM_NAME}"; do
    IFS=: read -r from_ns from_vm to_ns to_vm <<<"${pair}"
    pod_ip="$(oc get pod -n "${to_ns}" -l "vm.kubevirt.io/name=${to_vm}" \
      -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)"
    service_ip="$(oc get service "${to_vm}-gateway" -n "${to_ns}" \
      -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
    if [[ -z "${pod_ip}" || -z "${service_ip}" ]]; then
      fail "${to_ns} peer pod and Service addresses exist"
      continue
    fi
    for port in 17670 8080 18789; do
      expect_tcp "${from_ns} to ${to_ns} pod:${port} is blocked" blocked \
        "${from_ns}" "${from_vm}" "${pod_ip}" "${port}"
      expect_tcp "${from_ns} to ${to_ns} Service:${port} is blocked" blocked \
        "${from_ns}" "${from_vm}" "${service_ip}" "${port}"
    done
  done
fi

finish
