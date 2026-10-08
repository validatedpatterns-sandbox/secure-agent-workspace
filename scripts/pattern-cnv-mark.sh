#!/usr/bin/env bash
# Preserve CNV namespace ownership on its cluster-scoped CRD before uninstall.
set -euo pipefail

namespace="$(oc get namespace openshift-cnv -o json --ignore-not-found)"
if [[ -z "${namespace}" ]]; then
  echo "OpenShift Virtualization namespace is already absent."
  exit 0
fi
if ! jq -e '.metadata.annotations["argocd.argoproj.io/tracking-id"] ==
    "secure-agent-workspace-prod:/Namespace:patterns-operator/openshift-cnv"' \
    <<<"${namespace}" >/dev/null; then
  echo "Keeping the HyperConverged CRD: the CNV namespace has no pattern ownership."
  exit 0
fi

crd="$(oc get crd hyperconvergeds.hco.kubevirt.io -o json --ignore-not-found)"
if [[ -z "${crd}" ]]; then
  echo "HyperConverged CRD is already absent."
  exit 0
fi
if ! jq -e '.metadata.labels["olm.managed"] == "true" and
  (.metadata.labels | has("operators.coreos.com/kubevirt-hyperconverged.openshift-cnv"))' \
  <<<"${crd}" >/dev/null; then
  echo "Keeping the HyperConverged CRD: it is not from the CNV operator."
  exit 0
fi

oc annotate crd hyperconvergeds.hco.kubevirt.io \
  openshell.pattern/cleanup-on-uninstall=secure-agent-workspace-prod --overwrite
