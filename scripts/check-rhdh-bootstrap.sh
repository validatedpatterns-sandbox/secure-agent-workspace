#!/usr/bin/env bash
# Acceptance check around a real clean Pattern installation.
set -euo pipefail
namespace=${RHDH_NAMESPACE:-rhdh}
argo=${ARGOCD_NS:-vp-gitops}
portal=backstage-${RHDH_NAME:-developer-hub}
case "${1:-}" in
  before)
    existing=$(oc get secret rhdh-oidc -n "${namespace}" --ignore-not-found -o name)
    if [[ -n "${existing}" ]]; then
      echo "Clean bootstrap requires an installation without ${namespace}/rhdh-oidc." >&2
      exit 1
    fi
    echo "Verified clean bootstrap input: ${namespace}/rhdh-oidc is absent."
    ;;
  after)
    # ExternalSecret, hook and Application controllers reconcile asynchronously.
    # The caller invokes this after the Pattern install returns.
    oc wait --for=create crd/externalsecrets.external-secrets.io --timeout=15m
    oc wait --for=condition=Established crd/externalsecrets.external-secrets.io --timeout=15m
    for obj in externalsecret/rhdh-oidc secret/rhdh-oidc job/saw-rhdh-keycloak-client; do
      oc wait --for=create "${obj}" -n "${namespace}" --timeout=15m
    done
    oc wait --for=condition=Ready externalsecret/rhdh-oidc -n "${namespace}" --timeout=15m
    oc wait --for=condition=Complete job/saw-rhdh-keycloak-client -n "${namespace}" --timeout=15m
    oc wait --for=jsonpath='{.status.sync.status}'=Synced applications.argoproj.io/openshell-rhdh -n "${argo}" --timeout=15m
    oc wait --for=jsonpath='{.status.health.status}'=Healthy applications.argoproj.io/openshell-rhdh -n "${argo}" --timeout=15m
    oc get applications.argoproj.io/openshell-rhdh -n "${argo}" -o json |
      jq -e '.status.sync.status == "Synced" and .status.health.status == "Healthy"' >/dev/null
    # The operator creates this Deployment asynchronously from the Backstage
    # CR. Argo can already report Healthy while dynamic plugins are installing.
    oc wait --for=create "deployment/${portal}" -n "${namespace}" --timeout=15m
    oc wait --for=condition=Available "deployment/${portal}" -n "${namespace}" --timeout=30m
    oc rollout status "deployment/${portal}" -n "${namespace}" --timeout=30m
    oc get "deployment/${portal}" -n "${namespace}" -o json |
      jq -e '.spec.replicas > 0 and .status.observedGeneration == .metadata.generation and
             .status.updatedReplicas == .spec.replicas and .status.availableReplicas == .spec.replicas' >/dev/null
    echo "Verified ESO Ready, Secret present, hook Complete, RHDH Synced/Healthy, and portal Deployment available."
    ;;
  *) echo "Usage: $0 before|after" >&2; exit 2 ;;
esac
