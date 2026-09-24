"""Opt-in smoke-only read-only probe; never repairs state or invokes apply."""
import json
import subprocess
import sys
from pathlib import Path

sys.path[:0] = ['/opt/saw/guest', '/var/lib/saw/releases/current']
import apply_bom  # noqa: E402
from saw_guest.inputs import MountedInputs  # noqa: E402


def rootless_diagnostic():
    account = apply_bom.guest_runtime_account()
    runtime = f'/run/user/{account.pw_uid}'
    env = {'PATH': '/usr/local/bin:/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8',
           'HOME': account.pw_dir, 'USER': 'cloud-user', 'LOGNAME': 'cloud-user',
           'CONTAINERS_CONF': '/dev/null', 'XDG_RUNTIME_DIR': runtime,
           'DBUS_SESSION_BUS_ADDRESS': f'unix:path={runtime}/bus'}
    observed = {path: Path(path).exists() for path in
                ('/usr/lib/systemd/user/podman.socket', '/usr/lib/systemd/user/dbus.socket', f'{runtime}/bus')}
    result = subprocess.run(['/usr/bin/systemctl', '--user', 'show', 'podman.socket',
                             '--property=LoadState,ActiveState,FragmentPath', '--all'],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=20, cwd='/',
                            user=account.pw_uid, group=account.pw_gid, extra_groups=[], env=env)
    stderr = result.stderr.decode(errors='replace')
    categories = [word for word in ('Permission denied', 'No such file', 'not found',
                  'Failed to connect', 'Access denied', 'No medium found', 'Read-only') if word in stderr]
    print('SAW user-socket diagnostic ' + json.dumps({'pathsExist': observed, 'exit': result.returncode,
          'errors': categories, 'properties': result.stdout.decode(errors='replace')[:2048]}), flush=True)


def main():
    stage = 'inputs'
    try:
        settings = json.loads(Path('/etc/saw/guest.json').read_text())
        snapshot = MountedInputs('/run/saw', settings).capture()
        stage = 'release'
        apply_bom.validate_guest_release(snapshot)
        stage = 'machine-identity'
        apply_bom.guest_boot_identity(snapshot)
        stage = 'rootless-preflight'
        apply_bom.prepare_rootless_podman()
        stage = 'gateway-unit'
        # Unit metadata only, not environment, credentials or command arguments.
        raw = apply_bom.guest_boot_command(['/usr/bin/systemctl', 'show',
            'saw-openshell-gateway.service', '--all',
            '--property=LoadState,FragmentPath,DropInPaths,ActiveState,NeedDaemonReload'], output=True)
        print('SAW diagnostic unit metadata: ' + raw.decode().replace('\n', '; '), flush=True)
        apply_bom.guest_gateway_service()
        stage = 'gateway-preflight'
        apply_bom.prepare_guest_gateway(snapshot, 'validate')
        print('SAW diagnostic preflight passed', flush=True)
    except Exception as error:
        # Only a fixed vocabulary is logged, never stdout/stderr or exception text.
        reasons = {'UnqualifiedGatewayUnit', 'GatewayUnitMismatch', 'UnsafeGatewayState',
                   'GatewayBootstrapCommandFailed', 'RootlessCommandFailed', 'UnsafeRootlessSocket',
                   'RootlessEngineRequired', 'SandboxApplyNotImplemented', 'SoftwareReleaseMismatch', 'SoftwareUpgradeNotImplemented',
                   'UnsafeRootlessAccount', 'RootlessSubordinateIDsRequired', 'InvalidMachineIdentity'}
        code = str(error) if isinstance(error, apply_bom.InstallerError) and str(error) in reasons else 'Unavailable'
        category = next((name for cls, name in ((FileNotFoundError, 'FileNotFound'),
                          (PermissionError, 'PermissionDenied'), (KeyError, 'MissingField'),
                          (ValueError, 'InvalidValue')) if isinstance(error, cls)), 'Other')
        print(f'SAW diagnostic stage={stage} reason={code} category={category}', flush=True)
    try:
        rootless_diagnostic()
    except Exception:
        print('SAW user-socket diagnostic unavailable', flush=True)
    # Instrumentation cannot fix the reconciler or alter its readiness decision.


if __name__ == '__main__':
    main()
