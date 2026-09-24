#!/usr/bin/env bash
# Discover the ServiceAccount used by an Argo CD application controller.
set -euo pipefail

namespace="${SAW_ARGO_NAMESPACE:-}"
deployment="${SAW_ARGO_DEPLOYMENT:-}"
if ! oc whoami >/dev/null 2>&1; then
  echo 'Not logged in to OpenShift. Run: oc login <cluster-api>' >&2
  exit 2
fi

if [[ -n "$namespace" && -n "$deployment" ]]; then
  sa="$(oc -n "$namespace" get deployment "$deployment" -o jsonpath='{.spec.template.spec.serviceAccountName}')"
  test -n "$sa" || { echo "Deployment $namespace/$deployment has no serviceAccountName" >&2; exit 1; }
  printf 'deployerServiceAccount:\n  name: %s\n  namespace: %s\n' "$sa" "$namespace"
  exit 0
fi

matches="$(oc get deployment -A -o jsonpath='{range .items[?(@.spec.template.spec.serviceAccountName)]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.template.spec.serviceAccountName}{"\n"}{end}' | grep 'application-controller' || true)"
if [[ -z "$matches" ]]; then
  echo 'No application-controller Deployment found. Set SAW_ARGO_NAMESPACE and SAW_ARGO_DEPLOYMENT explicitly.' >&2
  exit 1
fi
echo 'Candidate controller deployments (namespace, deployment, ServiceAccount):'
echo "$matches"
echo
echo 'Select the controller that manages this cluster, then run:'
echo '  SAW_ARGO_NAMESPACE=<namespace> SAW_ARGO_DEPLOYMENT=<deployment> make saw-argo-discover'
