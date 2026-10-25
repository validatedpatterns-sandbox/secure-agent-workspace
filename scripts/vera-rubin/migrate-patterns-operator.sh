#!/usr/bin/env bash
# =============================================================================
# Vera Rubin / verac2: replace the out-of-catalog arm64 patterns-operator with
# the released one from the community-operators catalog.
# -----------------------------------------------------------------------------
# Early rc5 clusters got patterns-operator as raw manifests in the
# `patterns-operator` namespace (quay.io/sauagarw/patterns-operator:0.0.4-arm64)
# because the catalog had no arm64 build. The released operator is in the
# catalog now, so this script:
#   1. removes the raw install (Deployments, webhook, RBAC) — the Pattern CRD and
#      the Pattern CR stay, so the GitOps apps keep running;
#   2. subscribes to patterns-operator from community-operators in
#      openshift-operators, where `./pattern.sh make install` puts it;
#   3. waits for the CSV and checks the Pattern CR is reconciled again.
# Safe to re-run. Logged in as cluster-admin.
# =============================================================================
set -euo pipefail
oc whoami >/dev/null || { echo "ERROR: not logged in (oc login)"; exit 1; }
RAW_NS=patterns-operator
SUB_NS=openshift-operators
SOURCE=${SOURCE:-community-operators}
CHANNEL=${CHANNEL:-fast}

echo "== [0/3] catalog check =="
if ! oc get packagemanifests -n openshift-marketplace patterns-operator >/dev/null 2>&1; then
  echo "ERROR: no packagemanifest 'patterns-operator' in openshift-marketplace; nothing to migrate to."
  echo "       oc get catalogsource -n openshift-marketplace"
  exit 1
fi
oc get packagemanifests -n openshift-marketplace patterns-operator \
  -o jsonpath='   catalog: {.status.catalogSource}  channels: {.status.channels[*].name}  default: {.status.defaultChannel}{"\n"}'
CHANNEL=$(oc get packagemanifests -n openshift-marketplace patterns-operator -o jsonpath='{.status.defaultChannel}')
SOURCE=$(oc get packagemanifests -n openshift-marketplace patterns-operator -o jsonpath='{.status.catalogSource}')

echo "== [1/3] remove the out-of-catalog install in namespace $RAW_NS =="
# Cluster-scoped first so nothing re-admits through the old webhook.
oc delete validatingwebhookconfiguration patterns-operator-validating-webhook-configuration --ignore-not-found
oc delete clusterrolebinding patterns-operator-manager-rolebinding patterns-operator-secret-injector-rolebinding --ignore-not-found
oc delete clusterrole patterns-operator-manager-role patterns-operator-secret-injector-role --ignore-not-found
if oc get ns "$RAW_NS" >/dev/null 2>&1; then
  oc delete deployment -n "$RAW_NS" patterns-operator-controller-manager patterns-operator-pattern-ui-catalog --ignore-not-found
  oc delete service -n "$RAW_NS" patterns-operator-webhook-service patterns-operator-pattern-ui-catalog --ignore-not-found
  oc delete configmap -n "$RAW_NS" patterns-operator-config patterns-operator-manager-config patterns-operator-pattern-ui-catalog --ignore-not-found
  oc delete rolebinding -n "$RAW_NS" patterns-operator-leader-election-rolebinding patterns-operator-manager-rolebinding --ignore-not-found
  oc delete role -n "$RAW_NS" patterns-operator-leader-election-role --ignore-not-found
  oc delete serviceaccount -n "$RAW_NS" patterns-operator-controller-manager patterns-operator-secret-injector --ignore-not-found
  echo "   left in place: namespace/$RAW_NS (empty), the Pattern CRD, and every Pattern CR"
fi

echo "== [2/3] subscribe to patterns-operator ($SOURCE / $CHANNEL) in $SUB_NS =="
oc apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: patterns-operator
  namespace: $SUB_NS
spec:
  channel: $CHANNEL
  installPlanApproval: Automatic
  name: patterns-operator
  source: $SOURCE
  sourceNamespace: openshift-marketplace
EOF
echo "   waiting for the CSV..."
csv=""
for i in $(seq 1 60); do
  csv=$(oc get subscription patterns-operator -n "$SUB_NS" -o jsonpath='{.status.installedCSV}' 2>/dev/null || true)
  if [ -n "$csv" ]; then
    phase=$(oc get csv "$csv" -n "$SUB_NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [ "$phase" = "Succeeded" ] && break
  fi
  sleep 5
done
if [ -z "$csv" ] || [ "$(oc get csv "$csv" -n "$SUB_NS" -o jsonpath='{.status.phase}' 2>/dev/null)" != "Succeeded" ]; then
  echo "   NOT READY yet. Check:"
  echo "     oc get subscription patterns-operator -n $SUB_NS -o yaml | sed -n '/^status:/,\$p'"
  echo "     oc get installplan,csv -n $SUB_NS"
  exit 1
fi
echo "   $csv Succeeded; image: $(oc get deploy -n "$SUB_NS" patterns-operator-controller-manager -o jsonpath='{.spec.template.spec.containers[?(@.name=="manager")].image}' 2>/dev/null)"

echo "== [3/3] the Pattern CR under the new operator =="
oc get pattern -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,REPO:.spec.gitSpec.targetRepo,REV:.spec.gitSpec.targetRevision,VERSION:.status.version 2>&1
echo "   (status.version / conditions update once the new controller reconciles; the"
echo "    app-of-apps in openshift-gitops is untouched by the switch)"
oc get application -n openshift-gitops -o custom-columns=NAME:.metadata.name,SYNC:.status.sync.status,HEALTH:.status.health.status 2>/dev/null | head -5 || true
