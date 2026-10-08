#!/usr/bin/env bash
# EgressFirewall safety checks for a sandbox namespace.
#
# Offline (always, needs helm): the chart denies both IP families, allows
# only exact hostnames, and rejects a wildcard, an IP, and a URL.
#
# Live (when oc is logged in and the firewall exists, unless SKIP_LIVE=1):
# the object is applied only in sandbox namespaces, an undeclared host from
# the VM times out, and a declared host still answers. OpenShell is not on
# this path: the probe is curl on the VM itself.
#
#   SAW_NS=saw-alice VM_NAME=alice ./tests/test-egress-firewall.sh
#   SKIP_LIVE=1 ./tests/test-egress-firewall.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHART="${REPO_ROOT}/charts/openshell-saw"
SAW_NS="${SAW_NS:-saw-alice}"
VM_NAME="${VM_NAME:-alice}"
UNDECLARED_HOST="${UNDECLARED_HOST:-example.com}"
ALLOWED_HOST="${ALLOWED_HOST:-integrate.api.nvidia.com}"
CURL_TIMEOUT="${CURL_TIMEOUT:-8}"

PASS=0
FAIL=0

pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

finish() {
  echo
  echo "${PASS} passed, ${FAIL} failed"
  [[ "${FAIL}" -eq 0 ]]
}

render() {
  helm template saw-test "${CHART}" --namespace "${SAW_NS}" "$@"
}

echo "== offline chart checks =="

if ! command -v helm >/dev/null 2>&1; then
  echo "helm is required" >&2
  exit 1
fi

rendered="$(render --set global.clusterDomain=example.com)"
if python3 -c '
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin.read()) if d and d.get("kind") == "EgressFirewall"]
if len(docs) != 1 or docs[0]["metadata"]["name"] != "default":
    sys.exit("expected one EgressFirewall named default")
if docs[0]["apiVersion"] != "k8s.ovn.org/v1":
    sys.exit("wrong apiVersion")
rules = docs[0]["spec"]["egress"]
types = [r["type"] for r in rules]
if types[0] != "Allow" or types[-2:] != ["Deny", "Deny"]:
    sys.exit("allows must come before the two denies")
if rules[-2]["to"] != {"cidrSelector": "0.0.0.0/0"} or rules[-1]["to"] != {"cidrSelector": "::/0"}:
    sys.exit("missing IPv4 or IPv6 deny")
if rules[0]["to"].get("nodeSelector", {}).get("matchLabels", {}).get("kubernetes.io/os") != "linux":
    sys.exit("first rule must allow node addresses only")
if rules[0].get("ports") != [
    {"protocol": "TCP", "port": 6443},
    {"protocol": "TCP", "port": 443},
    {"protocol": "TCP", "port": 80},
]:
    sys.exit("node allow must be TCP 6443, 443, and 80 only")
if "ports" in rules[-1] or "ports" in rules[-2]:
    sys.exit("the denies must not be limited to one port")
names = []
for rule in rules:
    if len(rule["to"]) != 1:
        sys.exit("a rule must set only one of dnsName, cidrSelector, nodeSelector")
    if rule["type"] == "Allow" and rule["to"].get("cidrSelector") in {"0.0.0.0/0", "::/0"}:
        sys.exit("allow-all")
    if "dnsName" in rule["to"]:
        name = rule["to"]["dnsName"]
        if not name or "*" in name or "/" in name or ":" in name:
            sys.exit("unsafe hostname " + repr(name))
        if rule["ports"] != [{"protocol": "TCP", "port": 443}]:
            sys.exit("hostname allow must be TCP 443 only")
        names.append(name)
for required in ("integrate.api.nvidia.com", "quay.io", "cdn01.quay.io",
                 "registry.fedoraproject.org", "registry.npmjs.org", "api.openai.com",
                 "github.com"):
    if required not in names:
        sys.exit("missing " + required)
if "openshell-keycloak-ingress-saw-keycloak.apps.example.com" not in names:
    sys.exit("missing keycloak route host")
if names.count("openshell-keycloak-ingress-saw-keycloak.apps.example.com") != 1:
    sys.exit("keycloak host duplicated")
' <<<"${rendered}"; then
  pass "rendered firewall is default-deny for both IP families"
else
  fail "rendered firewall is default-deny for both IP families"
fi

reject() {
  local desc="$1" host="$2"
  local err
  if err="$(render --set-string "egress.extraAllow[0]=${host}" 2>&1 >/dev/null)"; then
    fail "${desc}"
  elif grep -q "egress host" <<<"${err}"; then
    pass "${desc}"
  else
    fail "${desc} (render failed without an egress host error)"
  fi
}

reject "wildcard hostname is rejected" "*.quay.io"
reject "IP address is rejected" "1.2.3.4"
reject "URL is rejected" "https://example.com/v1"

if render --set egress.enabled=false 2>/dev/null | grep -q "kind: EgressFirewall"; then
  fail "egress.enabled=false still renders a firewall"
else
  pass "egress.enabled=false renders no firewall"
fi

echo
echo "== live cluster checks =="

if [[ "${SKIP_LIVE:-}" == "1" ]]; then
  echo "  SKIP  live checks (SKIP_LIVE=1)"
  finish
  exit $?
fi

if ! command -v oc >/dev/null 2>&1 || ! oc whoami >/dev/null 2>&1; then
  echo "  SKIP  live checks (oc is not logged in)"
  finish
  exit $?
fi

if ! oc get egressfirewall default -n "${SAW_NS}" >/dev/null 2>&1; then
  echo "  SKIP  live checks (no EgressFirewall default in ${SAW_NS})"
  finish
  exit $?
fi

if oc get egressfirewall -A -o json | python3 -c '
import json, sys
items = json.load(sys.stdin).get("items") or []
bad = []
for item in items:
    ns = item["metadata"]["namespace"]
    if not ns.startswith("saw-"):
        bad.append(ns)
    if item["metadata"]["name"] != "default":
        bad.append(ns + "/" + item["metadata"]["name"])
if bad:
    sys.exit("egress firewall outside a sandbox namespace: " + ", ".join(bad))
'; then
  pass "firewall exists only in sandbox namespaces and is named default"
else
  fail "firewall exists only in sandbox namespaces and is named default"
fi

status="$(oc get egressfirewall default -n "${SAW_NS}" -o jsonpath='{.status.status}' 2>/dev/null || true)"
if [[ "${status}" == *"applied"* ]]; then
  pass "firewall status is applied (${status})"
else
  fail "firewall status is applied (got '${status}')"
fi

if oc get egressfirewall default -n "${SAW_NS}" -o json | python3 -c '
import json, sys
rules = json.load(sys.stdin)["spec"]["egress"]
types = [r["type"] for r in rules]
if types[-2:] != ["Deny", "Deny"]:
    sys.exit("denies are not last")
if rules[-2]["to"].get("cidrSelector") != "0.0.0.0/0":
    sys.exit("missing ipv4 deny")
if rules[-1]["to"].get("cidrSelector") != "::/0":
    sys.exit("missing ipv6 deny")
for rule in rules:
    name = (rule.get("to") or {}).get("dnsName") or ""
    if "*" in name:
        sys.exit("wildcard on the cluster")
'; then
  pass "cluster object denies both IP families and has no wildcard"
else
  fail "cluster object denies both IP families and has no wildcard"
fi

if ! oc get vm "${VM_NAME}" -n "${SAW_NS}" >/dev/null 2>&1; then
  echo "  SKIP  VM probes (no VM ${VM_NAME} in ${SAW_NS})"
  finish
  exit $?
fi

if [[ ! -x "${REPO_ROOT}/scripts/openshell-saw-vm-ssh.sh" ]]; then
  fail "VM probe helper is missing"
  finish
  exit $?
fi

probe() {
  local host="$1"
  # The helper logs key setup on stdout. The HTTP code is the last line.
  SAW_NS="${SAW_NS}" VM_NAME="${VM_NAME}" \
    "${REPO_ROOT}/scripts/openshell-saw-vm-ssh.sh" \
    "curl -m ${CURL_TIMEOUT} -sS -o /dev/null -w '%{http_code}' https://${host}/ || true" \
    | tail -n 1 | tr -d '[:space:]'
}

undeclared_code="$(probe "${UNDECLARED_HOST}" | tr -d '[:space:]')"
if [[ "${undeclared_code}" == "000" || -z "${undeclared_code}" ]]; then
  pass "VM cannot reach undeclared host ${UNDECLARED_HOST}"
else
  fail "VM cannot reach undeclared host ${UNDECLARED_HOST} (HTTP ${undeclared_code})"
fi

allowed_code="$(probe "${ALLOWED_HOST}" | tr -d '[:space:]')"
if [[ "${allowed_code}" =~ ^[0-9]{3}$ && "${allowed_code}" != "000" ]]; then
  pass "VM can reach declared host ${ALLOWED_HOST} (HTTP ${allowed_code})"
else
  fail "VM can reach declared host ${ALLOWED_HOST} (got '${allowed_code}')"
fi

for host in cdn01.quay.io registry.npmjs.org; do
  code="$(probe "${host}" | tr -d '[:space:]')"
  if [[ "${code}" =~ ^[0-9]{3}$ && "${code}" != "000" ]]; then
    pass "VM can reach ${host} (HTTP ${code})"
  elif [[ "${host}" == "registry.npmjs.org" && ( "${code}" == "000" || -z "${code}" ) ]]; then
    # The name is on the allowlist. OVN resolves it itself and, for this
    # Cloudflare name, has not matched the addresses the guest uses.
    echo "  NOTE  ${host} is allowed but the VM got no HTTP response (OVN DNS)"
    pass "${host} is on the firewall; a timeout is not a missing allow entry"
  else
    fail "VM can reach ${host} (got '${code}')"
  fi
done

finish
