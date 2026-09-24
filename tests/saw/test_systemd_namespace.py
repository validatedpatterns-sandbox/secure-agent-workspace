"""Opt-in privileged Linux CI test of the real service mount namespace.

Never runs in the default unprivileged/offline gate. Uses only temporary marker
files, no credentials, user creation, Podman state, or Kubernetes access.
"""
import configparser
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('SAW_SYSTEMD_TEST') != '1',
    reason='requires an explicitly opted-in disposable Linux CI runner with systemd/root')


@pytest.mark.parametrize('unit', ['saw-guest.service', 'saw-openshell-gateway.service'])
def test_runtime_visible_readonly_but_home_hidden(unit):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read(ROOT / 'guest/systemd' / unit)
    service = parser['Service']
    with tempfile.TemporaryDirectory(prefix='saw-namespace-', dir='/run/user') as runtime:
        with tempfile.TemporaryDirectory(prefix='saw-namespace-', dir='/root') as home:
            runtime_file, home_file = Path(runtime) / 'marker', Path(home) / 'marker'
            runtime_file.write_text('public-test-marker')
            home_file.write_text('private-test-marker')
            command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                       '--unit=saw-namespace-' + uuid.uuid4().hex]
            for prop in ('ProtectHome', 'BindReadOnlyPaths', 'ProtectSystem', 'NoNewPrivileges', 'PrivateTmp'):
                command += ['--property=' + prop + '=' + service[prop]]
            command += ['/usr/bin/python3', '-I', '-c',
                'import errno, pathlib, sys\n'
                'runtime, home = map(pathlib.Path, sys.argv[1:])\n'
                'assert runtime.read_text() == "public-test-marker"\n'
                'assert not home.exists()\n'
                'try:\n'
                '    runtime.write_text("must-not-write")\n'
                'except OSError as error:\n'
                '    assert error.errno == errno.EROFS\n'
                'else:\n'
                '    raise AssertionError("runtime bind is writable")\n', str(runtime_file), str(home_file)]
            subprocess.run(command, check=True, capture_output=True, timeout=30)
            assert runtime_file.read_text() == 'public-test-marker'
