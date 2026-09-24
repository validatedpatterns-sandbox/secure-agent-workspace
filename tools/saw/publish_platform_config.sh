#!/usr/bin/env bash
# Publish the reviewed, non-secret platform contract for manual user installs.
set -euo pipefail

values="${SAW_PLATFORM_VALUES:-config/saw-platform.yaml}"
namespace="${SAW_PLATFORM_NAMESPACE:-saw-system}"
name="${SAW_PLATFORM_CONFIGMAP:-saw-platform-config}"
test -f "$values" || { echo "Missing $values; run: make saw-platform-discover" >&2; exit 2; }
oc create namespace "$namespace" --dry-run=client -o yaml | oc apply -f - >/dev/null
oc create configmap "$name" -n "$namespace" --from-file=values.yaml="$values" --dry-run=client -o yaml | oc apply -f - >/dev/null
echo "Published $values as ConfigMap $name in namespace $namespace"
