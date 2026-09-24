"""Offline image build inputs: never build, push, or contact a cluster."""
import importlib.util
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def builder():
    spec = importlib.util.spec_from_file_location('saw_image_builder', ROOT / 'tools/saw/build_image_context.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_image_context_contains_only_release_inputs(builder, tmp_path):
    output = tmp_path / 'context'
    manifest = builder.create_context(output, ROOT / 'examples/saw/installer-bom.yaml')
    assert set(p.name for p in output.iterdir()) == {'Dockerfile', 'guest.tar.gz', 'customize.sh', 'build-inputs.json'}
    recipe = (output / 'Dockerfile').read_text()
    for item in manifest['installerBOM']['spec']['openshell'].values():
        assert item['image'] not in recipe
    assert 'payload' not in recipe
    assert 'force_tcg' in recipe  # Image build needs no privileged host KVM device.
    assert 'sha256sum --check' in recipe
    assert recipe.rstrip().endswith('/disk/disk.qcow2')
    with tarfile.open(output / 'guest.tar.gz') as archive:
        assert 'etc/saw/guest.json' not in archive.getnames()
        assert not any(p.startswith(('var/lib/', 'home/')) for p in archive.getnames())
    assert json.loads((output / 'build-inputs.json').read_text()) == manifest


def test_image_context_refuses_existing_directory(builder, tmp_path):
    with pytest.raises(FileExistsError):
        builder.create_context(tmp_path, ROOT / 'examples/saw/installer-bom.yaml')
    assert not list(tmp_path.iterdir())


def test_invalid_release_cannot_create_build_context(builder, tmp_path):
    bom = yaml.safe_load((ROOT / 'examples/saw/installer-bom.yaml').read_text())
    bom['spec']['openshell']['cli']['image'] = 'untrusted:latest\nRUN anything'
    release = tmp_path / 'bad.yaml'
    release.write_text(yaml.safe_dump(bom))
    with pytest.raises(ValueError):
        builder.create_context(tmp_path / 'context', release)
    assert not (tmp_path / 'context').exists()


def test_image_seals_identity_and_does_not_grant_runtime_sudo():
    script = ROOT / 'guest/image/customize.sh'
    subprocess.run(['bash', '-n', str(script)], check=True)
    content = script.read_text()
    assert 'install -m 0644 /etc/release-signing-public-key.pem /etc/saw/release-signing-public-key.pem' in content
    assert 'rm -f /etc/release-signing-public-key.pem' in content
    assert 'apply_bom.py' not in content
    assert "usermod --groups '' --lock cloud-user" in content
    assert "'sudo': []" in content
    assert 'clean --logs --seed --machine-id' in content
    assert content.index('install -m 0444 /dev/null /etc/machine-id') > content.index('cloud-init clean')
    assert 'systemctl disable podman.socket podman.service' in content
    assert 'saw-guest.service' in content


def test_guest_boot_target_does_not_cycle_with_cloud_final():
    # Fedora cloud-final is After=multi-user.target. A service waiting for it
    # cannot also be ordered before multi-user.target through WantedBy.
    for name in ('saw-guest.service', 'saw-guest-mounts.service'):
        unit = (ROOT / 'guest/systemd' / name).read_text()
        assert 'cloud-final.service' in unit
        assert 'WantedBy=cloud-init.target' in unit
        assert 'WantedBy=multi-user.target' not in unit


def test_image_context_cli_does_not_deploy(tmp_path):
    result = subprocess.run([sys.executable, str(ROOT / 'tools/saw/build_image_context.py'),
                             '--installer-bom', str(ROOT / 'examples/saw/installer-bom.yaml'),
                             '--output', str(tmp_path / 'context')], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'no image built or published' in result.stdout


def test_legacy_chart_copy_is_generated_from_installer():
    subprocess.run([sys.executable, str(ROOT / 'tools/saw/sync_installer_chart.py'), '--check'], check=True)
    assert not (ROOT / 'charts/saw-bom/scripts/apply_bom.py').exists()
    copy = (ROOT / 'charts/saw-bom/files/apply_bom.py').read_bytes()
    assert copy.split(b'\n', 1)[1] == (ROOT / 'installer/apply_bom.py').read_bytes()


def test_smoke_manifests_have_no_credentials_and_use_real_mounted_inputs(installer, tmp_path):
    from saw_guest.inputs import MountedInputs
    spec = importlib.util.spec_from_file_location('saw_boot_smoke', ROOT / 'tools/saw/render_boot_smoke.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bom = installer.load_installer_bom(ROOT / 'examples/saw/installer-bom.yaml')
    docs = module.resources(bom, 'registry.test/installer@sha256:' + 'a' * 64)
    vm = next(d for d in docs if d['kind'] == 'VirtualMachine')
    volumes = vm['spec']['template']['spec']['volumes']
    cloud = yaml.safe_load(next(v for v in volumes if v['name'] == 'cloudinit')['cloudInitNoCloud']['userData'])
    settings = json.loads(cloud['write_files'][0]['content'])
    locations = {'installer-smoke-intent': 'intent', 'installer-smoke-installer': 'installer',
                 'installer-smoke-profiles': 'profiles/installer-smoke-profiles'}
    for cm in (d for d in docs if d['kind'] == 'ConfigMap'):
        directory = tmp_path / locations[cm['metadata']['name']]
        directory.mkdir(parents=True)
        for key, value in cm['data'].items():
            (directory / key).write_text(value)
    snapshot = MountedInputs(tmp_path, settings).capture()
    assert installer.validate_guest_profiles(snapshot)[0]['name'] == 'smoke'
    assert snapshot['credentials'] == {}
    assert all(d['metadata']['namespace'] == module.NAMESPACE for d in docs)
    sa = next(d for d in docs if d['kind'] == 'ServiceAccount')
    assert sa['automountServiceAccountToken'] is False
    assert not any(d['kind'] == 'Secret' for d in docs)
    assert cloud['runcmd'][-1] == ['systemctl', '--no-block', 'start', 'saw-guest.service']
    with pytest.raises(ValueError):
        module.resources(bom, 'registry.test/installer:mutable')
    other = module.resources(bom, 'registry.test/installer@sha256:' + 'b' * 64, 'installer-smoke-4')
    assert {d['metadata']['name'] for d in docs}.isdisjoint(d['metadata']['name'] for d in other)
    other_vm = next(d for d in other if d['kind'] == 'VirtualMachine')
    assert other_vm['spec']['dataVolumeTemplates'][0]['metadata']['name'] == 'installer-smoke-4-root'
    for invalid in ('../unsafe', 'BAD', 'a' * 41, 'trailing-'):
        with pytest.raises(ValueError):
            module.resources(bom, 'registry.test/installer@sha256:' + 'b' * 64, invalid)
    diagnostic = module.resources(bom, 'registry.test/installer@sha256:' + 'b' * 64, diagnostics=True)
    user_data = next(d for d in diagnostic if d['kind'] == 'Secret')['stringData']['userdata']
    assert 'ExecStartPost=' in user_data
    assert 'StandardOutput=journal+console' in user_data
    assert 'saw-qualification.timer' in user_data
    observer = (ROOT / 'guest/image/verify_diagnostic.py').read_text()
    assert "prepare_guest_gateway(snapshot, 'verify')" in observer
    assert "reconcile_guest_profiles(snapshot, 'verify')" in observer
    assert "'apply'" not in observer
    diagnostic_vm = next(d for d in diagnostic if d['kind'] == 'VirtualMachine')
    volume = next(v for v in diagnostic_vm['spec']['template']['spec']['volumes'] if v['name'] == 'cloudinit')
    assert volume['cloudInitNoCloud'] == {'secretRef': {'name': 'installer-smoke-cloudinit'}}


@pytest.mark.parametrize('fault', [None, 'uid', 'changed-input', 'not-ready'])
def test_smoke_observer_only_reports_verified_nonsecret_evidence(installer, monkeypatch, tmp_path, capsys, fault):
    from types import SimpleNamespace
    monkeypatch.setitem(sys.modules, 'apply_bom', installer)
    spec = importlib.util.spec_from_file_location('saw_observer', ROOT / 'guest/image/verify_diagnostic.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshot = {'credentials': {'PRIVATE': 'PRIVATE-CREDENTIAL'}, 'workspaces': [{'name': 'smoke'}]}
    def disk(path):
        return tmp_path / str(path).lstrip('/')
    files = {'/etc/saw/guest.json': '{}',
             '/var/lib/saw/reconciler/status.json': json.dumps({'reason': 'PRIVATE-CREDENTIAL'}),
             '/var/lib/saw/reconciler/state.json': json.dumps({'accepted': {'id': 'revision1', 'snapshot': snapshot}}),
             '/proc/321/status': 'Uid:\t0\t0\t0\t0\n' if fault == 'uid' else 'Uid:\t1000\t1000\t1000\t1000\n',
             '/etc/machine-id': 'a' * 32, '/proc/sys/kernel/random/boot_id': 'boot-test',
             '/sys/fs/selinux/enforce': '1', '/var/lib/saw/gateway/tls/ca.crt': 'public-certificate'}
    for name, content in files.items():
        path = disk(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    monkeypatch.setattr(module, 'Path', disk)
    monkeypatch.setattr(module, 'ready', lambda _: fault != 'not-ready')
    calls = []
    captures = iter([snapshot, {} if fault == 'changed-input' else snapshot])
    monkeypatch.setattr(module, 'MountedInputs', lambda *args: SimpleNamespace(capture=lambda: next(captures)))
    monkeypatch.setattr(installer, 'validate_guest_release', lambda _: None)
    monkeypatch.setattr(installer, 'prepare_guest_gateway', lambda s, phase: calls.append(('gateway', phase)))
    monkeypatch.setattr(installer, 'reconcile_guest_profiles', lambda s, phase: calls.append(('profiles', phase)))
    monkeypatch.setattr(installer, 'guest_boot_command', lambda *args, **kwargs: b'321\n')
    monkeypatch.setattr(installer, 'guest_runtime_account', lambda: SimpleNamespace(pw_uid=1000))
    monkeypatch.setattr(installer, 'desired_guest_members', lambda _: {'smoke-owner': 'admin'})
    monkeypatch.setattr(installer, 'GUEST_GATEWAY_ROOT', disk('/var/lib/saw/gateway'))
    module.verify()
    output = capsys.readouterr().out
    assert 'PRIVATE' not in output and 'smoke-owner' not in output
    if fault == 'not-ready':
        assert calls == []
        assert 'SAW runtime pending' in output and 'InstallerFailed' in output
        return
    assert calls == [('gateway', 'verify'), ('profiles', 'verify')]
    if fault:
        assert output == ''
    else:
        result = json.loads(output.removeprefix('SAW runtime verified '))
        assert result['gatewayUID'] == 1000 and result['rootless'] and result['selinuxEnforcing']
        assert result['memberCount'] == result['workspaceCount'] == 1
