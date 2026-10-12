"""Gateway configuration must retain the token obtained for that gateway."""
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('cached_issuer', ['https://old-cluster/realms/openshell', 'https://new-cluster/realms/openshell'])
def test_configure_keeps_gateway_login_token(tmp_path, cached_issuer):
    home = tmp_path / 'home'
    cached = home / '.config/openshell/oidc'
    cached.mkdir(parents=True)
    (cached / 'token.json').write_text(json.dumps({'issuer_url': cached_issuer, 'access_token': 'stale-token'}))
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    (scripts / 'saw-configure.sh').symlink_to(ROOT / 'scripts' / 'saw-configure.sh')
    (scripts / 'check-saw-name.sh').symlink_to(ROOT / 'scripts' / 'check-saw-name.sh')
    ca = scripts / 'extract-gateway-ca.sh'
    ca.write_text('#!/bin/sh\nmkdir -p "$(dirname "$OUT_FILE")"\nprintf ca > "$OUT_FILE"\n')
    ca.chmod(0o755)
    fakebin = tmp_path / 'bin'
    fakebin.mkdir()
    oc = fakebin / 'oc'
    oc.write_text('#!/bin/sh\nprintf new-gateway\n')
    oc.chmod(0o755)
    cli = fakebin / 'openshell'
    cli.write_text('''#!/bin/sh
if [ "$1 $2" = "gateway add" ]; then
  mkdir -p "$HOME/.config/openshell/gateways/test"
  printf '{"access_token":"fresh-token"}' > "$HOME/.config/openshell/gateways/test/oidc_token.json"
fi
''')
    cli.chmod(0o755)
    env = dict(os.environ, HOME=str(home), PATH=f'{fakebin}:{os.environ["PATH"]}')
    result = subprocess.run(['make', '-f', str(ROOT / 'Makefile-quickstart'),
                             'saw-configure', 'OPENSHELL_SAW_NAME=test',
                             'OIDC_ISSUER=https://new-cluster/realms/openshell',
                             f'OIDC_TOKEN_DIR={cached}', f'SCRIPTS_DIR={scripts}/'],
                            cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    saved = json.loads((home / '.config/openshell/gateways/test/oidc_token.json').read_text())
    assert saved['access_token'] == 'fresh-token'


def test_configure_without_oidc_does_not_pass_literal_none(tmp_path):
    home = tmp_path / 'home'
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    (scripts / 'saw-configure.sh').symlink_to(ROOT / 'scripts' / 'saw-configure.sh')
    ca = scripts / 'extract-gateway-ca.sh'
    ca.write_text('#!/bin/sh\nmkdir -p "$(dirname "$OUT_FILE")"\nprintf ca > "$OUT_FILE"\n')
    ca.chmod(0o755)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    oc = bindir / 'oc'
    oc.write_text('#!/bin/sh\nprintf gateway.example.test\n')
    oc.chmod(0o755)
    log = tmp_path / 'openshell-args'
    cli = bindir / 'openshell'
    cli.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CLI_LOG"\n')
    cli.chmod(0o755)
    env = dict(os.environ, HOME=str(home), PATH=f'{bindir}:{os.environ["PATH"]}',
               CLI_LOG=str(log), OPENSHELL_SAW_NAME='test', OIDC_ISSUER='none')
    result = subprocess.run(['bash', str(scripts / 'saw-configure.sh')],
                            cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    calls = log.read_text()
    assert 'gateway add https://gateway.example.test --name test' in calls
    assert '--oidc-issuer' not in calls and '--oidc-client-id' not in calls
