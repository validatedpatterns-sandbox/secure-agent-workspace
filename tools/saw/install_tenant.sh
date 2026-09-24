#!/usr/bin/env bash
# Direct Helm installation only. Argo-managed tenants are created by ApplicationSet.
set -euo pipefail

mode="${SAW_TENANT_MANAGEMENT:-helm}"
tenant="${SAW_TENANT:?Set SAW_TENANT to the tenant.name to install}"
values="${SAW_VALUES:-overrides/saw-blueprint.yaml}"
if [[ "$mode" != "helm" ]]; then
  echo "Refusing direct Helm installation with SAW_TENANT_MANAGEMENT=$mode." >&2
  echo 'For Argo management, set sawBlueprint.applicationSet.enabled=true and reconcile the parent saw-blueprint Application.' >&2
  exit 2
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
python3 tools/saw/render_tenant_values.py --values "$values" --tenant "$tenant" > "$tmp"
namespace="$(python3 - "$tmp" <<'PY'
import hashlib, json, sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))['openshellSaw']
raw = json.dumps([cfg['platform']['issuer'], cfg['tenant']['subject'], cfg['tenant']['name']], separators=(',', ':'), ensure_ascii=False)
raw = raw.replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
print(f"saw-{cfg['tenant']['name'][:33]}-{hashlib.sha256(raw.encode()).hexdigest()[:24]}")
PY
)"
bash tools/saw/platform_preflight.sh
helm upgrade --install "saw-$tenant" charts/openshell-saw --namespace "$namespace" --create-namespace -f "$tmp"
