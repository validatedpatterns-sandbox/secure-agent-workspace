#!/usr/bin/env bash
# Direct Helm installation from one user enrollment and shared platform defaults.
set -euo pipefail

mode="${SAW_TENANT_MANAGEMENT:-helm}"
platform_values="${SAW_PLATFORM_VALUES:-config/saw-platform.yaml}"
platform_namespace="${SAW_PLATFORM_NAMESPACE:-saw-system}"
platform_configmap="${SAW_PLATFORM_CONFIGMAP:-saw-platform-config}"
user_values="${SAW_USER_VALUES:?Set SAW_USER_VALUES to one sawUser YAML file}"
if [[ "$mode" != "helm" ]]; then
  echo "Refusing direct Helm installation with SAW_TENANT_MANAGEMENT=$mode." >&2
  echo 'For Argo management, add the enrollment to sawBlueprint and reconcile the parent ApplicationSet.' >&2
  exit 2
fi

tmp="$(mktemp)"
platform_tmp=""
trap 'rm -f "$tmp" "$platform_tmp"' EXIT
if command -v oc >/dev/null 2>&1 && oc get configmap "$platform_configmap" -n "$platform_namespace" >/dev/null 2>&1; then
  platform_tmp="$(mktemp)"
  oc get configmap "$platform_configmap" -n "$platform_namespace" -o jsonpath='{.data.values\.yaml}' > "$platform_tmp"
  platform_values="$platform_tmp"
fi
test -f "$platform_values" || { echo "Missing $platform_values and ConfigMap $platform_configmap; run: make saw-platform-discover && make saw-platform-configmap" >&2; exit 2; }
python3 tools/saw/render_user_values.py --platform-values "$platform_values" --user-values "$user_values" > "$tmp"
namespace="$(python3 - "$tmp" <<'PY'
import hashlib, json, sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))['openshellSaw']
raw = json.dumps([cfg['platform']['issuer'], cfg['tenant']['subject'], cfg['tenant']['name']], separators=(',', ':'), ensure_ascii=False)
raw = raw.replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
print(f"saw-{cfg['tenant']['name'][:33]}-{hashlib.sha256(raw.encode()).hexdigest()[:24]}")
PY
)"
name="$(python3 - "$tmp" <<'PY'
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))['openshellSaw']['tenant']['name'])
PY
)"
bash tools/saw/platform_preflight.sh
helm upgrade --install "saw-$name" charts/openshell-saw --namespace "$namespace" --create-namespace \
  --set openshellSaw.createNamespace=false -f "$tmp"
