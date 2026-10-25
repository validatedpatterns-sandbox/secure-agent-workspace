#!/usr/bin/env bash
# Ship the generator-egress NetworkPolicy and verify the backend can reach it.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "repo: $(pwd)   branch: $(git branch --show-current)"
git add charts/openshell-rhdh/templates/portal-generator.yaml
git commit -m "fix(ocp5-rc5): allow RHDH backend egress to the workspace generator

The community RHDH 2.x operator's default-deny egress netpol blocks the
backend from reaching saw-workspaces-generator:4355, so the catalog can't
read its catalog.yaml and http:backstage:request can't call it. Add an
additive egress NetworkPolicy. (Not needed on the older operator.)

Assisted-By: Claude" || echo "(nothing new to commit)"
git push
oc annotate application openshell-rhdh -n vp-gitops argocd.argoproj.io/refresh=hard --overwrite
oc patch application openshell-rhdh -n vp-gitops --type merge \
  -p '{"operation":{"sync":{"revision":"ocp-5.0"}}}'
echo "waiting for the netpol to exist..."
until oc get networkpolicy saw-rhdh-allow-generator-egress -n rhdh >/dev/null 2>&1; do sleep 5; done
echo "netpol present. testing reachability from the backend (give it ~15s)..."
sleep 15
POD=$(oc get pods -n rhdh -o name | grep backstage-developer-hub | grep -v psql | tail -1)
oc exec -n rhdh "$POD" -c backstage-backend -- \
  curl -s -o /dev/null -w "generator catalog.yaml -> http_code=%{http_code}\n" \
  http://saw-workspaces-generator.saw-portal.svc:4355/catalog.yaml || echo "(curl not available in backend; check the catalog log instead)"
echo "=== recent generator fetch log lines (should stop failing) ==="
oc logs -n rhdh "$POD" -c backstage-backend --since=30s 2>&1 | grep -i "saw-workspaces-generator" | tail -5 || echo "(no recent generator errors — good)"
