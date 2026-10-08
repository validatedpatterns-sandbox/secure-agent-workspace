#!/usr/bin/env bash
# Run only after the framework removes the Argo CD applications.
set -euo pipefail

namespaces="$(oc get namespaces -o json)"
pattern_namespace="$(jq -r '.items[] |
  select(.metadata.name == "openshift-cnv") |
  .metadata.annotations["argocd.argoproj.io/tracking-id"] // ""' \
  <<<"${namespaces}")"
namespace_present=false
if jq -e '.items | any(.metadata.name == "openshift-cnv")' \
  <<<"${namespaces}" >/dev/null; then
  namespace_present=true
else
  echo "OpenShift Virtualization namespace is already absent."
fi

if [[ "${namespace_present}" == true ]]; then
  resources="$(oc api-resources -o name)"
  for kind in hyperconvergeds.hco.kubevirt.io \
      subscriptions.operators.coreos.com \
      clusterserviceversions.operators.coreos.com \
      installplans.operators.coreos.com; do
    if ! grep -qx "${kind}" <<<"${resources}"; then continue; fi
    objects="$(oc get "${kind}" -n openshift-cnv -o json)"
    owned_names="$(jq -r '.items[] |
      select(.metadata.labels["argocd.argoproj.io/instance"] == "openshift-cnv" or
        ((.metadata.annotations["argocd.argoproj.io/tracking-id"] // "") |
         startswith("openshift-cnv:"))) | .metadata.name' <<<"${objects}")"
    total="$(jq -r '.items | length' <<<"${objects}")"
    owned_count="$(jq -r '.items | [ .[] |
      select(.metadata.labels["argocd.argoproj.io/instance"] == "openshift-cnv" or
        ((.metadata.annotations["argocd.argoproj.io/tracking-id"] // "") |
         startswith("openshift-cnv:"))) ] | length' <<<"${objects}")"
    if (( total > owned_count )); then
      echo "Keeping $((total - owned_count)) ${kind} objects without pattern ownership."
    fi
    while IFS= read -r name; do
      [[ -n "${name}" ]] || continue
      echo "Deleting pattern-owned ${kind}/${name} in openshift-cnv."
      oc delete "${kind}" "${name}" -n openshift-cnv \
        --wait=false --ignore-not-found=true
    done <<<"${owned_names}"
  done
fi

# OLM leaves this cluster-scoped CRD after removing the operator namespace.
# Its conversion webhook then points at a service that no longer exists.
# A later install can create a HyperConverged object against the stale schema.
if [[ "${namespace_present}" == true && \
      "${pattern_namespace}" != "secure-agent-workspace-prod:/Namespace:patterns-operator/openshift-cnv" ]]; then
  echo "Keeping the HyperConverged CRD: the CNV namespace has no pattern ownership."
  exit 0
fi

if [[ "${namespace_present}" == true ]]; then
  oc wait --for=delete namespace/openshift-cnv --timeout=180s
fi
crd="$(oc get crd hyperconvergeds.hco.kubevirt.io -o json --ignore-not-found)"
if [[ -z "${crd}" ]]; then
  echo "HyperConverged CRD is already absent."
  exit 0
fi
if ! jq -e '.metadata.annotations["openshell.pattern/cleanup-on-uninstall"] ==
    "secure-agent-workspace-prod" and
  .metadata.labels["olm.managed"] == "true" and
  (.metadata.labels | has("operators.coreos.com/kubevirt-hyperconverged.openshift-cnv"))' \
  <<<"${crd}" >/dev/null; then
  echo "Keeping the HyperConverged CRD: no matching pre-uninstall ownership marker."
  exit 0
fi

hyperconvergeds="$(oc get hyperconvergeds.hco.kubevirt.io -A -o json)"
subscriptions="$(oc get subscriptions.operators.coreos.com -A -o json)"
if jq -e '.items | length > 0' <<<"${hyperconvergeds}" >/dev/null ||
   jq -e '.items | any(.spec.name == "kubevirt-hyperconverged")' \
     <<<"${subscriptions}" >/dev/null; then
  echo "Keeping the HyperConverged CRD: another resource uses the CNV operator."
  exit 0
fi
echo "Deleting the orphaned HyperConverged CRD after pattern-owned CNV teardown."
oc delete crd hyperconvergeds.hco.kubevirt.io --wait=true
