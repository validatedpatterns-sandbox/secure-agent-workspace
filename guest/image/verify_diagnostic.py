"""Opt-in smoke observer: runtime reads only, no repair or credential output."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path[:0] = ['/opt/saw/guest', '/var/lib/saw/releases/current']
import apply_bom  # noqa: E402
from saw_guest.health import ready  # noqa: E402
from saw_guest.inputs import MountedInputs  # noqa: E402
from saw_guest.errors import safe_reason  # noqa: E402


def rootless_client_probe():
    account = apply_bom.guest_runtime_account()
    runtime = f'/run/user/{account.pw_uid}'
    env = {'PATH': '/usr/local/bin:/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8', 'HOME': '/',
           'USER': 'cloud-user', 'LOGNAME': 'cloud-user', 'CONTAINERS_CONF': '/dev/null',
           'CONTAINERS_STORAGE_CONF': '/dev/null', 'XDG_RUNTIME_DIR': runtime,
           'DBUS_SESSION_BUS_ADDRESS': f'unix:path={runtime}/bus'}
    with tempfile.TemporaryDirectory(prefix='saw-client-probe-') as directory:
        os.chown(directory, account.pw_uid, account.pw_gid)
        private_runtime = Path(directory) / 'runtime'
        private_runtime.mkdir(mode=0o700)
        os.chown(private_runtime, account.pw_uid, account.pw_gid)
        for mode in ('image', 'private-client-home', 'private-client-home-default-storage',
                     'private-client-runtime', 'private-client-runtime-default-storage'):
            if mode != 'image':
                env.update(HOME=directory, XDG_CONFIG_HOME=directory + '/config',
                           XDG_DATA_HOME=directory + '/data', XDG_CACHE_HOME=directory + '/cache')
            env['XDG_RUNTIME_DIR'] = str(private_runtime) if 'client-runtime' in mode else runtime
            if 'default-storage' in mode:
                env.pop('CONTAINERS_STORAGE_CONF', None)
            else:
                env['CONTAINERS_STORAGE_CONF'] = '/dev/null'
            result = subprocess.run(['/usr/bin/podman', '--remote',
                f'--url=unix://{runtime}/podman/podman.sock', 'info', '--format=json'],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=20, cwd='/',
                user=account.pw_uid, group=account.pw_gid, extra_groups=[], env=env)
            error = result.stderr.decode(errors='replace').lower()
            categories = [word for word in ('permission denied', 'read-only', 'not permitted',
                '/.config', '/home', 'storage.conf', 'connection refused', 'cannot connect',
                'newuidmap', 'xdg_runtime_dir', 'no such file', 'getwd', '/run/user', '/var/',
                '/dev/null', '/tmp/', 'storage', 'rootless', 'mkdir', 'chmod', 'chown') if word in error]
            rootless = False
            if result.returncode == 0:
                rootless = json.loads(result.stdout).get('host', {}).get('security', {}).get('rootless') is True
            print('SAW remote-client diagnostic ' + json.dumps({'mode': mode, 'exit': result.returncode,
                  'rootless': rootless, 'errors': categories}), flush=True)


def verify():
    directory = Path('/var/lib/saw/reconciler')
    if not ready(directory):
        try:
            status = json.loads((directory / 'status.json').read_text())
            raw = apply_bom.guest_boot_command(['/usr/bin/systemctl', 'show',
                'saw-openshell-gateway.service', '--all',
                '--property=ActiveState,SubState,Result,ExecMainStatus,MainPID'], output=True)
            print('SAW runtime pending ' + json.dumps({'reason': safe_reason(status.get('reason')),
                  'gateway': raw.decode().replace('\n', '; ')}), flush=True)
            if status.get('reason') == 'RootlessCommandFailed':
                rootless_client_probe()
        except Exception:
            print('SAW runtime pending', flush=True)
        return
    settings = json.loads(Path('/etc/saw/guest.json').read_text())
    inputs = MountedInputs('/run/saw', settings)
    snapshot = inputs.capture()
    accepted = json.loads((directory / 'state.json').read_text())['accepted']
    if not accepted or accepted['snapshot'] != snapshot:
        return
    apply_bom.validate_guest_release(snapshot)
    apply_bom.prepare_guest_gateway(snapshot, 'verify')
    apply_bom.reconcile_guest_profiles(snapshot, 'verify')
    if inputs.capture() != snapshot or not ready(directory):
        return
    # Inspect the actual process, not just the User= declaration in the unit.
    raw = apply_bom.guest_boot_command(['/usr/bin/systemctl', 'show',
        'saw-openshell-gateway.service', '--property=MainPID', '--value'], output=True)
    pid = int(raw)
    if pid <= 0:
        return
    uid_line = next(line for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                    if line.startswith('Uid:'))
    uids = [int(value) for value in uid_line.split()[1:]]
    uid = apply_bom.guest_runtime_account().pw_uid
    if uids != [uid] * 4:
        return
    result = {'revision': accepted['id'], 'rootless': True, 'gatewayUID': uid,
              'workspaceCount': len(snapshot['workspaces']),
              'memberCount': sum(len(apply_bom.desired_guest_members(ws)) for ws in snapshot['workspaces']),
              'caSHA256': hashlib.sha256((apply_bom.GUEST_GATEWAY_ROOT / 'tls/ca.crt').read_bytes()).hexdigest(),
              'machineID': Path('/etc/machine-id').read_text().strip(),
              'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'selinuxEnforcing': Path('/sys/fs/selinux/enforce').read_text().strip() == '1'}
    print('SAW runtime verified ' + json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        verify()
    except Exception:
        print('SAW runtime verification unavailable', flush=True)
