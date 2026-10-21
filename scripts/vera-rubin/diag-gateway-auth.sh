#!/usr/bin/env bash
# What is the in-VM gateway/oauth2-proxy actually doing for alice?
# The gateway + sandboxes run inside the VM; we reach their logs via the
# serial console the VM writes to the virt-launcher, plus the sandbox state
# the gateway exposes on its service.
set -uo pipefail
NS=saw-alice
echo "=== gateway service ports + endpoints (sandbox backends reachable?) ==="
oc get svc alice-gateway -n $NS -o jsonpath='{range .spec.ports[*]}{.name}={.port}->{.targetPort}  {end}{"\n"}' 2>&1
oc get endpoints alice-gateway -n $NS -o jsonpath='{.subsets[*].addresses[*].ip} ports={range .subsets[*].ports[*]}{.port} {end}{"\n"}' 2>&1
echo
echo "=== VM serial console log (gateway/oauth2-proxy/sandbox startup) — last 60 lines ==="
oc logs -n $NS virt-launcher-alice-64mzw -c compute 2>&1 | tail -3 || true
# the guest console is captured by virtctl; try the serial log file if exposed
POD=$(oc get pods -n $NS -o name | grep virt-launcher | head -1)
echo "(guest logs are inside the VM; checking what the launcher exposes)"
oc exec -n $NS "${POD#pod/}" -c compute -- ls /var/run/kubevirt-private 2>/dev/null | head || echo "(no direct guest log access from launcher)"
echo
echo "=== did the install finish? the generator reports per-sandbox status ==="
GPOD=$(oc get pods -n saw-portal -l app.kubernetes.io/name=saw-workspaces-generator -o name | tail -1)
oc exec -n saw-portal "$GPOD" -c generator -- curl -s http://localhost:4355/catalog.yaml 2>/dev/null \
  | grep -iE "openshell.pattern/status|description|installing|ready|sandbox|phase" | head -8 || echo "(catalog read failed)"
