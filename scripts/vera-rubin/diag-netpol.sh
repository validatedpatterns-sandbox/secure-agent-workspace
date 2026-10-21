#!/usr/bin/env bash
set -uo pipefail
echo "=== netpols in rhdh (ingress to backend) ==="
oc get netpol -n rhdh 2>&1
for np in $(oc get netpol -n rhdh -o name 2>/dev/null); do
  echo "------- $np -------"
  oc get $np -n rhdh -o jsonpath='podSelector={.spec.podSelector}
policyTypes={.spec.policyTypes}
ingress={.spec.ingress}
egress={.spec.egress}
' 2>&1
  echo
done
echo "=== backend pod labels (ingress target) ==="
oc get pod -n rhdh -l rhdh.redhat.com/app=backstage-developer-hub --show-labels 2>&1 | head -3
oc get pod -n rhdh -o name 2>/dev/null | grep backstage-developer-hub | grep -v psql | head -1 | xargs -I{} oc get {} -n rhdh --show-labels 2>&1 | head -3
echo
echo "=== netpols in saw-portal (generator/pipeline egress) ==="
oc get netpol -n saw-portal 2>&1
for np in $(oc get netpol -n saw-portal -o name 2>/dev/null); do
  echo "------- $np -------"
  oc get $np -n saw-portal -o jsonpath='podSelector={.spec.podSelector}
policyTypes={.spec.policyTypes}
egress={.spec.egress}
' 2>&1
  echo
done
echo "=== namespace labels (for namespaceSelector matching) ==="
oc get ns rhdh saw-portal -o jsonpath='{range .items[*]}{.metadata.name}: {.metadata.labels}{"\n"}{end}' 2>&1
