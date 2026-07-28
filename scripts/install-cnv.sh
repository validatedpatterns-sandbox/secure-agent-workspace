#!/usr/bin/env bash
# Install OpenShift Virtualization (CNV) if missing. Idempotent.
# Requires cluster-admin on a workers-with-/dev/kvm cluster (demo.redhat.com roadshow OK).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib.sh
source "${ROOT}/scripts/lib.sh"
require_oc_login

NS_CNV="${CNV_NS:-openshift-cnv}"
HCO_NAME="${HCO_NAME:-kubevirt-hyperconverged}"

if oc get csv -n "${NS_CNV}" 2>/dev/null | grep -qi hyperconverged; then
  echo "CNV operator CSV present in ${NS_CNV}"
else
  echo "== create ${NS_CNV} + OperatorGroup + Subscription =="
  oc apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS_CNV}
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: openshift-cnv-group
  namespace: ${NS_CNV}
spec:
  targetNamespaces:
    - ${NS_CNV}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: kubevirt-hyperconverged
  namespace: ${NS_CNV}
spec:
  channel: stable
  name: kubevirt-hyperconverged
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  installPlanApproval: Automatic
EOF
fi

echo "== wait for HyperConverged operator CSV Succeeded =="
for i in $(seq 1 60); do
  phase="$(oc get csv -n "${NS_CNV}" -o jsonpath='{.items[?(@.spec.displayName=="OpenShift Virtualization")].status.phase}' 2>/dev/null || true)"
  if [[ -z "${phase}" ]]; then
    phase="$(oc get csv -n "${NS_CNV}" -o json 2>/dev/null | python3 -c 'import sys,json
items=json.load(sys.stdin).get("items",[])
for i in items:
  n=(i.get("metadata") or {}).get("name","")
  if "hyperconverged" in n or "kubevirt" in n:
    print((i.get("status") or {}).get("phase","")); break
' 2>/dev/null || true)"
  fi
  echo "  csv phase=${phase:-pending} ($i/60)"
  [[ "${phase}" == "Succeeded" ]] && break
  sleep 20
done

if ! oc -n "${NS_CNV}" get hyperconverged "${HCO_NAME}" >/dev/null 2>&1; then
  echo "== create HyperConverged ${HCO_NAME} =="
  oc apply -f - <<EOF
apiVersion: hco.kubevirt.io/v1beta1
kind: HyperConverged
metadata:
  name: ${HCO_NAME}
  namespace: ${NS_CNV}
spec: {}
EOF
fi

echo "== wait HyperConverged Available =="
oc -n "${NS_CNV}" wait hyperconverged/"${HCO_NAME}" \
  --for=condition=Available --timeout=45m

# virtctl helper
if ! command -v virtctl >/dev/null 2>&1 && [[ ! -x "${HOME}/bin/virtctl" ]]; then
  echo "== install virtctl to ~/bin =="
  mkdir -p "${HOME}/bin"
  VERS="$(oc get csv -n "${NS_CNV}" -o json | python3 -c 'import sys,json
items=json.load(sys.stdin)["items"]
for i in items:
  if "hyperconverged" in i["metadata"]["name"]:
    print(i["spec"]["version"]); break
' 2>/dev/null || echo "")"
  # Prefer cluster-provided download link when present
  if oc get consoleclidownloads virtctl-clidownloads-kubevirt-hyperconverged -o name >/dev/null 2>&1; then
    URL="$(oc get consoleclidownloads virtctl-clidownloads-kubevirt-hyperconverged -o jsonpath='{.spec.links[0].href}')"
    curl -fsSL "${URL}" -o /tmp/virtctl.tgz || curl -fsSL "${URL}" -o "${HOME}/bin/virtctl"
    if file /tmp/virtctl.tgz 2>/dev/null | grep -qi 'gzip\|tar'; then
      tar -xOf /tmp/virtctl.tgz --wildcards '*/virtctl' 2>/dev/null >"${HOME}/bin/virtctl" \
        || tar -xOf /tmp/virtctl.tgz virtctl >"${HOME}/bin/virtctl" || true
    fi
  fi
  if [[ ! -x "${HOME}/bin/virtctl" ]]; then
    echo "WARN: install virtctl manually from the OpenShift console → Command line tools" >&2
  else
    chmod +x "${HOME}/bin/virtctl"
    echo "virtctl -> ${HOME}/bin/virtctl"
  fi
fi

echo "install-cnv OK"
export PATH="${HOME}/bin:${PATH}"
command -v virtctl >/dev/null && virtctl version --client 2>/dev/null || true
