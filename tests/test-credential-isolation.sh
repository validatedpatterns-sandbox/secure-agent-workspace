#!/usr/bin/env bash
# Checks for a deployed SAW; set SKIP_APPLY=1 to skip the apply restart.
# SSH must already be authorized; this script does not add a VM access key.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SAW_NS="${SAW_NS:-}"
VM_NAME="${VM_NAME:-}"
render_ns="${SAW_NS:-saw-test}"
[[ "${render_ns}" == saw- ]] && render_ns=saw-test
PYTHON="${PYTHON:-python3}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

helm template saw-check "$ROOT/charts/openshell-saw" -n "$render_ns" \
  -f "$ROOT/tests/fixtures/saw-network-topology.yaml" \
  -f "$ROOT/tests/fixtures/credential-proxy-values.yaml" \
  --set sandboxName=saw-check > "$tmp/rendered.yaml"
"$PYTHON" - "$tmp/rendered.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
vm = next(d for d in docs if d['kind'] == 'VirtualMachine')
vols = vm['spec']['template']['spec']['volumes']
sources = {v.get('cloudInitNoCloud', {}).get('secretRef', {}).get('name') for v in vols}
sources.update(v.get('secret', {}).get('secretName') for v in vols)
assert 'inference' not in sources and 'web-search' not in sources
assert 'inference-meta' in sources and 'web-search-meta' in sources
assert any(v.get('configMap', {}).get('name') == 'saw-proxy-ca' for v in vols)
assert any(d['kind'] == 'Deployment' and d['metadata']['name'].endswith('-credential-proxy') for d in docs)
print('PASS offline: VM mounts metadata only and proxy resources render')
PY

if [[ "${SKIP_LIVE:-}" == 1 ]]; then
  echo 'SKIP live checks (SKIP_LIVE=1)'
  exit 0
fi
if [[ ! "$SAW_NS" =~ ^saw-[a-z0-9]([a-z0-9-]*[a-z0-9])?$ || ! "$VM_NAME" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
  echo 'SAW_NS=saw-<name> and VM_NAME=<name> are required for live checks' >&2
  exit 1
fi
for tool in oc virtctl openssl; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }; done
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.generated-ssh-keys/sandbox-ssh}"
[[ -f "$SSH_KEY_PATH" ]] || { echo "Existing SSH key required at $SSH_KEY_PATH" >&2; exit 1; }

oc get vm "$VM_NAME" -n "$SAW_NS" -o json > "$tmp/vm.json"
oc get cm "$VM_NAME-installer" -n "$SAW_NS" -o json > "$tmp/installer.json"
"$PYTHON" - "$tmp/vm.json" "$tmp/installer.json" <<'PY'
import json, sys
vm, cm = (json.load(open(p)) for p in sys.argv[1:])
cfg = json.loads(cm['data']['config.json'])
vols = vm['spec']['template']['spec']['volumes']
mounted = {v.get('secret', {}).get('secretName') for v in vols}
for b in cfg['credentialProxy']['secrets']:
    assert b['name'] not in mounted, f"VM attaches full provider Secret {b['name']}"
    assert b['name'] + '-meta' in mounted, f"VM lacks metadata Secret {b['name']}-meta"
assert any(v.get('configMap', {}).get('name') == 'saw-proxy-ca' for v in vols)
print('PASS live: no full provider Secret is attached to the VM')
PY

ssh_args=(-n "$SAW_NS" ssh "cloud-user@vm/$VM_NAME" --identity-file="$SSH_KEY_PATH"
  --local-ssh-opts=-oBatchMode=yes --local-ssh-opts=-oConnectTimeout=10
  --local-ssh-opts=-oGSSAPIAuthentication=no
  --local-ssh-opts=-oStrictHostKeyChecking=no
  --local-ssh-opts=-oUserKnownHostsFile=/dev/null)
vm_exec() { virtctl "${ssh_args[@]}" --command "$1"; }

guest_code="$(cat "$ROOT/scripts/scan-guest-credentials.py"; cat <<'PY'
import pathlib, subprocess, sys
hits = ca_key_files()
if hits:
    print('FAIL: gateway CA key found in guest files:', *hits, sep='\n', file=sys.stderr)
    raise SystemExit(1)
tls = pathlib.Path('/home/cloud-user/.local/state/openshell/tls')
assert (tls/'client-ca.pem').read_bytes() == (tls/'ca.crt').read_bytes(), 'stale admin CA in bundle'
for base in (pathlib.Path('/home/cloud-user/.config/openshell'), pathlib.Path('/home/cloud-user/.local/state')):
    for cert in list(base.rglob('*.crt')) + list(base.rglob('*.pem')):
        p = subprocess.run(['openssl','x509','-noout','-subject','-in',str(cert)], capture_output=True, text=True)
        assert not __import__('re').search(r'OU\s*=\s*openshell-admin', p.stdout), f'admin cert on disk: {cert}'
assert not pathlib.Path('/home/cloud-user/.local/state/saw-installer').exists()
assert not pathlib.Path('/home/cloud-user/.config/openshell/gateways/saw-installer').exists()
print('PASS guest: no CA key; client CA bundle and admin files are clean', file=sys.stderr)
import base64, gzip
print(base64.b64encode(gzip.compress(b"".join(sorted(token_digests())))).decode())
PY
)"
guest_b64="$(printf %s "$guest_code" | base64 -w0)"
remote="sudo python3 -c 'import base64; exec(base64.b64decode(\"$guest_b64\"))'"

"$PYTHON" - "$tmp/installer.json" <<'PY' > "$tmp/bindings.tsv"
import json, sys
cfg = json.load(open(sys.argv[1]))['data']['config.json']
for b in json.loads(cfg)['credentialProxy']['secrets']:
    keys = ['client_id', 'client_secret', 'refresh_token'] if b.get('refresh') else [b['key']]
    for key in keys:
        print(b['name'], key, sep='\t')
PY
vm_exec "$remote" </dev/null > "$tmp/guest-digests.b64"
while IFS=$'\t' read -r secret key; do
  oc get secret "$secret" -n "$SAW_NS" -o json | "$PYTHON" -c '
import base64, gzip, hashlib, json, re, sys
key = base64.b64decode(json.load(sys.stdin).get("data", {}).get(sys.argv[1], ""))
if not key:
    print(f"SKIP {sys.argv[2]}: empty key (keyless endpoint)"); raise SystemExit(0)
key = key.strip()  # Secret files can end in a newline; HTTP credentials cannot.
# Google material contains separators (dots and slashes). Check every long
# component with the same tokenizer used by the guest; values never go there.
parts = re.findall(rb"[A-Za-z0-9_-]{20,512}", key)
if not parts:
    raise SystemExit(f"FAIL {sys.argv[2]}: no checkable credential component")
blob = gzip.decompress(base64.b64decode(open(sys.argv[3], "rb").read()))
mine = {hashlib.sha256(part).digest()[:8] for part in parts}
if any(blob[i:i + 8] in mine for i in range(0, len(blob), 8)):
    raise SystemExit(f"FAIL {sys.argv[2]}: provider key found in guest files")
print(f"PASS {sys.argv[2]} absent from VM files")' "$key" "$secret/$key" "$tmp/guest-digests.b64"
done < "$tmp/bindings.tsv"

oc get deployment "$VM_NAME-credential-proxy" -n "$SAW_NS" -o jsonpath='{.status.readyReplicas}' | grep -qx 1
echo 'PASS credential proxy Deployment is ready'

if [[ -n "${OLD_ADMIN_CERT:-}" ]]; then
  [[ -f "$OLD_ADMIN_CERT" ]] || { echo "OLD_ADMIN_CERT file is missing" >&2; exit 1; }
  vm_exec 'cat /home/cloud-user/.local/state/openshell/tls/client-ca.pem' </dev/null > "$tmp/current-ca.pem"
  if openssl verify -CAfile "$tmp/current-ca.pem" "$OLD_ADMIN_CERT" >/dev/null 2>&1; then
    echo 'FAIL saved old admin certificate still chains to the active client CA' >&2
    exit 1
  fi
  echo 'PASS saved old admin certificate is not trusted by the current client CA'
fi

if [[ "${SKIP_APPLY:-}" != 1 ]]; then
  vm_exec 'sudo systemctl restart --no-block saw-apply.service' </dev/null >/dev/null
  saw_two=0
  finished=0
  for ((i=0; i<120; i++)); do
    count="$(vm_exec "sudo grep -c 'BEGIN CERTIFICATE' /home/cloud-user/.local/state/openshell/tls/client-ca.pem" </dev/null | tr -dc '0-9')"
    [[ "$count" == 2 ]] && saw_two=1
    if [[ "$saw_two" == 1 && "$count" == 1 ]] && \
       vm_exec "sudo python3 -c 'import json; print(json.load(open(\"/var/lib/saw/status.json\"))[\"apply\"][\"phase\"])'" </dev/null | grep -qx Done; then
      finished=1
      break
    fi
    sleep 1
  done
  [[ "$saw_two" == 1 && "$finished" == 1 ]] || {
    echo 'FAIL did not observe temporary two-CA bundle followed by successful apply' >&2; exit 1; }
  vm_exec "sudo bash -c 'test ! -e /home/cloud-user/.local/state/openshell/tls/ca.key && test -z \"\$(find /run/user -maxdepth 2 -name \"saw-admin.*\" -print -quit)\"'" </dev/null >/dev/null
  echo 'PASS apply temporarily trusted its admin CA, then removed it and the runtime directory'
fi
