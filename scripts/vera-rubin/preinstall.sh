#!/usr/bin/env bash
# =============================================================================
# SAW on OpenShift 5.0 rc5 / arm64 (Vera Rubin / verac2) — PRE-INSTALL
# -----------------------------------------------------------------------------
# Run once, logged in as cluster-admin, BEFORE applying the Pattern CR.
# Installs the pieces the rc5 operator catalog cannot provide on arm64:
#   1. the RHDH community operator CatalogSource (arm64)
#   2. the patterns-operator built for arm64 (quay.io/sauagarw), out-of-catalog,
#      with its service-CA webhook serving cert.
# Everything else (keycloak community operator, RHDH community subscription,
# chart fixes) is already in the openshift-vera-rubin branch.
# See docs/vera-rubin-ocp.md.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; MAN="$HERE/manifests"
oc whoami >/dev/null || { echo "ERROR: not logged in (oc login)"; exit 1; }

echo "== [1/2] RHDH community operator catalog (arm64) =="
oc apply -f "$MAN/rhdh-community-catalog.yaml"
echo "   waiting for the catalog to report READY..."
for i in $(seq 1 30); do
  st=$(oc get catalogsource rhdh-community-catalog -n openshift-marketplace -o jsonpath='{.status.connectionState.lastObservedState}' 2>/dev/null || true)
  [ "$st" = "READY" ] && { echo "   READY"; break; }
  sleep 5
done

echo "== [2/2] patterns-operator (arm64, quay.io/sauagarw), out-of-catalog =="
oc apply -f "$MAN/patterns-crd.yaml"
oc apply -f "$MAN/patterns-operator-arm64.yaml"
echo "   image: $(grep -m1 'quay.io/sauagarw/patterns-operator' "$MAN/patterns-operator-arm64.yaml" | awk '{print $NF}')"
echo "   (the webhook serving cert is issued by service-CA from the baked-in annotations)"
echo "   waiting for the operator rollout..."
oc rollout status deploy/patterns-operator-controller-manager -n patterns-operator --timeout=300s || {
  echo "   NOTE: if it is stuck on the webhook cert, confirm the service-CA operator is running:"
  echo "         oc get pods -n openshift-service-ca"; }

cat <<'NEXT'

== pre-install done ==
Next:
  1) Apply the Pattern CR (points at sauagarwa/secure-agent-workspace @ openshift-vera-rubin):
       oc apply -f scripts/vera-rubin/manifests/pattern-cr.yaml
  2) Once the operators begin installing, run the post-install fixes:
       bash scripts/vera-rubin/postinstall.sh
NEXT
