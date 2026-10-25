#!/usr/bin/env bash
# Ship the http:backstage:request dynamic-plugin change on ocp-5.0
# and roll the RHDH backend. Run from anywhere: it cd's to the repo root.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "repo: $(pwd)   branch: $(git branch --show-current)"

git add charts/openshell-rhdh/templates/rhdh-dynamic-plugins.yaml
git commit -m "fix(ocp5-rc5): add http:backstage:request action as OCI dynamic plugin (arm64)

The community rhdh hub does not bundle the roadiehq http-request scaffolder
module, so the workspace templates' http:backstage:request step has no action.
Pull it as an OCI dynamic plugin, pinned by amd64 digest (arch-neutral JS runs
on arm64).

Assisted-By: Claude" || echo "(nothing new to commit)"
git push

oc annotate application openshell-rhdh -n vp-gitops argocd.argoproj.io/refresh=hard --overwrite
oc patch application openshell-rhdh -n vp-gitops --type merge \
  -p '{"operation":{"sync":{"revision":"ocp-5.0"}}}'

echo "waiting for the http-request digest to land in the configmap..."
until oc get cm saw-rhdh-dynamic-plugins -n rhdh -o jsonpath='{.data.dynamic-plugins\.yaml}' | grep -q b7e9e36a; do sleep 5; done
echo "configmap updated -> restarting backend"
oc rollout restart deployment backstage-developer-hub -n rhdh
oc rollout status deployment backstage-developer-hub -n rhdh --timeout=360s || true

echo "=== scaffolder actions (expect http:backstage:request) ==="
POD=$(oc get pods -n rhdh -o name | grep backstage-developer-hub | grep -v psql | tail -1)
oc logs -n rhdh "$POD" -c backstage-backend 2>&1 | grep -i "Starting scaffolder with the following actions" | tail -1
echo "=== pods ==="
oc get pods -n rhdh
