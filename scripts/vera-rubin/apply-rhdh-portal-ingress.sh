#!/usr/bin/env bash
# Allow saw-portal (generator + pipelines) to reach the RHDH backend :7007.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "repo: $(pwd)   branch: $(git branch --show-current)"
git add charts/openshell-rhdh/templates/portal-generator.yaml
git commit -m "fix(ocp5-rc5): allow saw-portal ingress to the RHDH backend :7007

The community RHDH 2.x operator's default-deny ingress netpol lets only the
router reach the backend, but the generator's /status token check and the
portal pipelines call it from saw-portal via RHDH_INTERNAL_URL. Without this
the JWKS fetch times out (/status 504) and the register pipeline task fails.
Add an ingress allow from the portal namespace on 7007.

Assisted-By: Claude" || echo "(nothing new to commit)"
git push
oc annotate application openshell-rhdh -n vp-gitops argocd.argoproj.io/refresh=hard --overwrite
oc patch application openshell-rhdh -n vp-gitops --type merge \
  -p '{"operation":{"sync":{"revision":"openshift-vera-rubin"}}}'
echo "waiting for the ingress netpol to exist..."
until oc get networkpolicy saw-rhdh-allow-portal-ingress -n rhdh >/dev/null 2>&1; do sleep 5; done
echo "netpol present. testing generator -> backend JWKS (expect 80 OK now)..."
sleep 8
GPOD=$(oc get pods -n saw-portal -l app.kubernetes.io/name=saw-workspaces-generator -o name | tail -1)
oc exec -n saw-portal "$GPOD" -c generator -- python3 -c "
import urllib.request
u='http://backstage-developer-hub.rhdh.svc:80/api/auth/.well-known/jwks.json'
try:
    r=urllib.request.urlopen(u,timeout=8); print('JWKS :80 ->', r.status, '(reachable)')
except Exception as e: print('JWKS :80 -> FAIL', type(e).__name__, e)
" 2>&1
echo
echo ">>> If that says 'reachable', re-run the Create workspace template in the UI (the old run already failed)."
