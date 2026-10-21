#!/usr/bin/env bash
set -uo pipefail
NS=saw-alice
POD=$(oc get pods -n $NS -o name | grep virt-launcher | sed 's|pod/||' | head -1)
echo "virt-launcher: $POD"
echo "containers: $(oc get pod $POD -n $NS -o jsonpath='{.spec.containers[*].name}' 2>/dev/null)"
echo
echo "=== guest console log: BOM install + sandbox/podman startup ==="
oc logs "$POD" -c guest-console-log -n $NS 2>&1 \
  | grep -iE "sandbox|notebook|cuda|apply_bom|bom|podman|pull|exec format|no such|error|fail|supervisor|started|oauth2|driver" \
  | tail -70 || echo "(no guest-console-log container / empty)"
echo
echo "=== the sandbox images the BOM pulls (arch check target) ==="
oc get configmap alice-installer -n $NS -o jsonpath='{.data.installer-bom\.yaml}' 2>/dev/null \
  | grep -iE "image:|sandbox_runtime|cuda|notebook" | sed 's/^/  /' | head -30
