#!/usr/bin/env bash
# =============================================================================
# SAW on OpenShift 5.0 rc5 / arm64 (Vera Rubin / verac2) — PRE-INSTALL
# -----------------------------------------------------------------------------
# Run once, logged in as cluster-admin, BEFORE `./pattern.sh make install`.
# Installs the one piece the rc5 operator catalog cannot provide on arm64:
#   1. the RHDH community operator CatalogSource (arm64)
# The patterns-operator itself now comes from community-operators like on any
# other cluster (`./pattern.sh make install` subscribes to it); the out-of-catalog
# arm64 build this script used to apply is gone. A cluster that still runs that
# build: see migrate-patterns-operator.sh.
# Everything else (keycloak community operator, RHDH community subscription,
# chart fixes) is already in the branch. See docs/vera-rubin-ocp.md.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; MAN="$HERE/manifests"
oc whoami >/dev/null || { echo "ERROR: not logged in (oc login)"; exit 1; }

echo "== [1/1] RHDH community operator catalog (arm64) =="
oc apply -f "$MAN/rhdh-community-catalog.yaml"
echo "   waiting for the catalog to report READY..."
for i in $(seq 1 30); do
  st=$(oc get catalogsource rhdh-community-catalog -n openshift-marketplace -o jsonpath='{.status.connectionState.lastObservedState}' 2>/dev/null || true)
  [ "$st" = "READY" ] && { echo "   READY"; break; }
  sleep 5
done

echo
echo "== patterns-operator in the cluster catalog =="
if oc get packagemanifests -n openshift-marketplace patterns-operator >/dev/null 2>&1; then
  oc get packagemanifests -n openshift-marketplace patterns-operator \
    -o jsonpath='   package: {.metadata.name}  catalog: {.status.catalogSource}  default channel: {.status.defaultChannel}{"\n"}'
else
  echo "   WARNING: no packagemanifest 'patterns-operator' in openshift-marketplace;"
  echo "   './pattern.sh make install' will not resolve its Subscription on this cluster."
fi

cat <<'NEXT'

== pre-install done ==
Next:
  1) Install the pattern the standard way (subscribes to patterns-operator from
     community-operators and creates the Pattern CR from values-global.yaml and
     this checkout's remote/branch):
       ./pattern.sh make install
  2) Once the operators begin installing, run the post-install fixes:
       bash scripts/vera-rubin/postinstall.sh
NEXT
