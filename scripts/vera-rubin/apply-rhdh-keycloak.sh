#!/usr/bin/env bash
# Enable the Keycloak catalog module (OCI) so users/groups import and RBAC
# grants saw-user -> templates become visible.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "repo: $(pwd)   branch: $(git branch --show-current)"
git add charts/openshell-rhdh/values.yaml
git commit -m "fix(ocp5-rc5): load Keycloak catalog module as OCI plugin on community RHDH

The SAW chart points keycloakCatalogPlugin at a local dynamic-plugins path
that exists only in the productized RHDH 1.10 image. On the community
rhdh:next (2.x) arm64 image that path is absent, so no Keycloak users/groups
import and RBAC leaves every user without the saw-user role (all templates
hidden). Repoint it at the OCI digest the community image already ships
(disabled by default) to re-enable it.

Assisted-By: Claude" || echo "(nothing new to commit)"
git push
oc annotate application openshell-rhdh -n vp-gitops argocd.argoproj.io/refresh=hard --overwrite
oc patch application openshell-rhdh -n vp-gitops --type merge \
  -p '{"operation":{"sync":{"revision":"openshift-vera-rubin"}}}'
echo "waiting ~20s for the dynamic-plugins ConfigMap to sync..."
sleep 20
echo "restarting backend so install-dynamic-plugins re-runs..."
oc rollout restart deployment backstage-developer-hub -n rhdh
oc rollout status deployment backstage-developer-hub -n rhdh --timeout=360s
POD=$(oc get pods -n rhdh -o name | grep backstage-developer-hub | grep -v psql | tail -1)
echo "=== did the keycloak OCI plugin install (no 'not found')? ==="
oc logs -n rhdh "$POD" -c install-dynamic-plugins 2>&1 | grep -i "keycloak" | tail -8
echo "=== keycloak provider activity (imported users/groups)? ==="
sleep 20
oc logs -n rhdh "$POD" -c backstage-backend 2>&1 | grep -i "keycloak" | tail -10 || echo "(none yet - provider runs on a schedule, initialDelay 15s)"
