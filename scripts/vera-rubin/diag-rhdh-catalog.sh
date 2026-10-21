#!/usr/bin/env bash
# Read-only: what is the generator serving, and did the http action load?
set -uo pipefail
POD=$(oc get pods -n rhdh -o name | grep backstage-developer-hub | grep -v psql | tail -1)
echo "backend pod: $POD"
echo
echo "=== generator catalog.yaml (first 80 lines) ==="
oc exec -n rhdh "$POD" -c backstage-backend -- \
  curl -s http://saw-workspaces-generator.saw-portal.svc:4355/catalog.yaml | head -80
echo
echo "=== how many entities did the generator emit? ==="
oc exec -n rhdh "$POD" -c backstage-backend -- \
  curl -s http://saw-workspaces-generator.saw-portal.svc:4355/catalog.yaml \
  | grep -c '^kind:' || true
echo
echo "=== is the catalog LOCATION for the generator registered? (backend log) ==="
oc logs -n rhdh "$POD" -c backstage-backend 2>&1 \
  | grep -i "saw-workspaces-generator\|catalog.yaml\|location" | tail -8 || echo "(none)"
echo
echo "=== did http:backstage:request register? (backend log) ==="
oc logs -n rhdh "$POD" -c backstage-backend 2>&1 \
  | grep -i "http:backstage:request\|module-http-request\|registered action" | tail -10 || echo "(none found — plugin may not be loaded)"
echo
echo "=== dynamic plugins actually loaded ==="
oc exec -n rhdh "$POD" -c install-dynamic-plugins -- ls /dynamic-plugins-root 2>/dev/null | grep -i "http-request\|oidc" || \
  oc logs -n rhdh "$POD" -c install-dynamic-plugins 2>&1 | grep -i "http-request\|oidc-provider" | tail -6 || echo "(couldn't read init container)"
