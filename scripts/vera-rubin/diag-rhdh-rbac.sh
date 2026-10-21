#!/usr/bin/env bash
set -uo pipefail
POD=$(oc get pods -n rhdh -o name | grep backstage-developer-hub | grep -v psql | tail -1)
echo "backend pod: $POD"
echo
echo "=== are the template files mounted? ==="
oc exec -n rhdh "$POD" -c backstage-backend -- ls -la /opt/app-root/src/saw/ 2>&1 | grep -i "workspace\|rbac\|token" || echo "(mount missing)"
echo
echo "=== did the catalog register the Template entities? ==="
oc logs -n rhdh "$POD" -c backstage-backend 2>&1 | grep -iE "create-workspace|delete-workspace|template" | grep -iv "fetch failed" | tail -10 || echo "(none)"
echo
echo "=== is the Keycloak catalog backend plugin loaded? ==="
oc logs -n rhdh "$POD" -c install-dynamic-plugins 2>&1 | grep -i "keycloak" | tail -6 || echo "(NOT loaded — no keycloak plugin)"
echo "--- keycloak provider activity in backend log ---"
oc logs -n rhdh "$POD" -c backstage-backend 2>&1 | grep -i "keycloak" | tail -8 || echo "(no keycloak provider activity)"
echo
echo "=== RBAC: who are the configured admins? (from values) ==="
grep -rn "rbac:" -A8 charts/openshell-rhdh/values.yaml values-prod.yaml 2>/dev/null | grep -iA8 "rbac" | head -30
echo
echo "=== RBAC policy csv (roles -> permissions) ==="
oc exec -n rhdh "$POD" -c backstage-backend -- cat /opt/app-root/src/saw/rbac-policy.csv 2>&1 | head -40 || echo "(no csv)"
