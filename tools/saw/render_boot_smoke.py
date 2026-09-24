#!/usr/bin/env python3
"""Render an isolated, credential-free boot smoke test; never deploy resources."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/saw'))
from build_guest_bundle import load_installer_bom  # noqa: E402
from openshell_saw.blueprints import name as validate_name, string  # noqa: E402

NAMESPACE = 'saw-installer-validation'


def resources(bom, image, name='installer-smoke', diagnostics=False, release=None,
              namespace=NAMESPACE):
    string(image, 'image', r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}', limit=512)
    string(name, 'name', r'[a-z][a-z0-9-]*[a-z0-9]', limit=40)
    validate_name(namespace, 'namespace')
    intent_name, installer_name, profiles_name = (f'{name}-{suffix}' for suffix in ('intent', 'installer', 'profiles'))
    def obj(kind, name, **kwargs):
        return {'apiVersion': 'v1', 'kind': kind,
                'metadata': {'name': name, 'namespace': namespace}, **kwargs}

    settings = {'namespace': namespace, 'instance': name, 'ownerSubject': 'smoke-owner',
                'enrollmentIdentity': hashlib.sha256(f'{namespace}/{name}'.encode()).hexdigest(),
                'profileConfigMaps': [profiles_name], 'providerSecrets': {}}
    instance = {'apiVersion': 'saw.redhat.com/v1alpha1', 'kind': 'SawInstance',
                'metadata': {'name': name},
                'spec': {'ownerSubject': 'smoke-owner', 'workspaces': [
                    {'profileRef': {'name': 'smoke', 'configMapRef': {'name': profiles_name}}}]}}
    profile = {'apiVersion': 'saw.redhat.com/v1alpha1', 'kind': 'Workspace',
               'metadata': {'name': 'smoke'},
               'spec': {'members': [{'subject': 'smoke-owner', 'role': 'admin'}]}}
    cloud = {'write_files': [{'path': '/etc/saw/guest.json', 'owner': 'root:root',
                              'permissions': '0600', 'content': json.dumps(settings)}],
             'runcmd': [['systemctl', 'enable', 'saw-guest.service'],
                        ['systemctl', '--no-block', 'start', 'saw-guest.service']]}
    if diagnostics:
        cloud['write_files'].extend([
            {'path': '/opt/saw/qualification/preflight.py', 'owner': 'root:root', 'permissions': '0600',
             'content': (ROOT / 'guest/image/preflight_diagnostic.py').read_text()},
            {'path': '/etc/systemd/system/saw-guest.service.d/qualification.conf',
             'owner': 'root:root', 'permissions': '0644',
             'content': '[Service]\nStandardOutput=journal+console\nStandardError=journal+console\n'
                        'ExecStartPost=/usr/bin/python3 -I /opt/saw/qualification/preflight.py\n'},
            {'path': '/opt/saw/qualification/verify.py', 'owner': 'root:root', 'permissions': '0600',
             'content': (ROOT / 'guest/image/verify_diagnostic.py').read_text()},
            {'path': '/etc/systemd/system/saw-qualification.service', 'owner': 'root:root', 'permissions': '0644',
             'content': '[Unit]\nAfter=saw-guest.service\n[Service]\nType=oneshot\nUser=root\n'
                        'ExecStart=/usr/bin/python3 -I /opt/saw/qualification/verify.py\n'
                        'Environment=PYTHONDONTWRITEBYTECODE=1\nUMask=0077\nNoNewPrivileges=true\n'
                        'ProtectSystem=strict\nProtectHome=tmpfs\nBindReadOnlyPaths=/run/user\nPrivateTmp=true\nLimitCORE=0\n'
                        'ReadWritePaths=/var/lib/saw\nStandardOutput=journal+console\nStandardError=journal+console\n'},
            {'path': '/etc/systemd/system/saw-qualification.timer', 'owner': 'root:root', 'permissions': '0644',
             'content': '[Timer]\nOnBootSec=45\nOnUnitInactiveSec=30\nAccuracySec=1\n'
                        '[Install]\nWantedBy=timers.target\n'}])
        cloud['runcmd'].insert(0, ['systemctl', 'daemon-reload'])
        cloud['runcmd'].append(['systemctl', 'enable', '--now', 'saw-qualification.timer'])
    installer_data = {'installer-bom.yaml': yaml.safe_dump(bom)}
    if release:
        installer_data['release.yaml'] = yaml.safe_dump(release)
    result = [obj('ServiceAccount', f'{name}-guest', automountServiceAccountToken=False),
              obj('ConfigMap', intent_name, data={'instance.yaml': yaml.safe_dump(instance)}),
              obj('ConfigMap', installer_name, data=installer_data),
              obj('ConfigMap', profiles_name, data={
                  'profiles__smoke__smoke__workspace.yaml': yaml.safe_dump(profile),
                  'profiles__smoke__smoke__providers.yaml': yaml.safe_dump({
                      'apiVersion': 'saw.redhat.com/v1alpha1', 'kind': 'Providers',
                      'metadata': {}, 'spec': {'providers': []}}),
                  'profiles__smoke__smoke__sandbox.yaml': yaml.safe_dump({
                      'apiVersion': 'saw.redhat.com/v1alpha1', 'kind': 'Sandboxes',
                      'metadata': {}, 'spec': {'sandboxes': []}})})]
    result.append({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                   'metadata': {'name': f'{name}-ingress', 'namespace': namespace},
                   'spec': {'podSelector': {'matchLabels': {'saw.redhat.com/instance': name}}, 'policyTypes': ['Ingress'],
                            'ingress': [{'from': [{'podSelector': {}}]}]}})
    vm = obj('VirtualMachine', name)
    vm['apiVersion'] = 'kubevirt.io/v1'
    vm['spec'] = {
        'runStrategy': 'Always',
        'dataVolumeTemplates': [{'metadata': {'name': f'{name}-root'}, 'spec': {
            'source': {'registry': {'url': f'docker://{image}', 'pullMethod': 'node'}},
            'storage': {'resources': {'requests': {'storage': '20Gi'}}}}}],
        'template': {'metadata': {'labels': {'saw.redhat.com/instance': name}}, 'spec': {
            'serviceAccountName': f'{name}-guest',
            'readinessProbe': {'httpGet': {'port': 9080, 'path': '/readyz'},
                               'initialDelaySeconds': 15, 'periodSeconds': 10},
            'domain': {'cpu': {'cores': 2}, 'resources': {'requests': {'memory': '6Gi'}},
                       'firmware': {'bootloader': {'efi': {'secureBoot': False}}},
                       'features': {'acpi': {}, 'smm': {}},
                       'devices': {'disks': [{'name': 'rootdisk', 'disk': {'bus': 'virtio'}},
                                              {'name': 'cloudinit', 'disk': {'bus': 'virtio'}}],
                                   'filesystems': [{'name': name, 'virtiofs': {}} for name in
                                                   ('saw-intent', 'saw-installer-bom', 'saw-profile-0')],
                                   'interfaces': [{'name': 'default', 'masquerade': {},
                                                   'ports': [{'name': 'guest-ready', 'port': 9080}]}]}},
            'networks': [{'name': 'default', 'pod': {}}],
            'volumes': [{'name': 'rootdisk', 'dataVolume': {'name': f'{name}-root'}},
                        {'name': 'cloudinit', 'cloudInitNoCloud': {'userData': '#cloud-config\n' + yaml.safe_dump(cloud)}},
                        {'name': 'saw-intent', 'configMap': {'name': intent_name}},
                        {'name': 'saw-installer-bom', 'configMap': {'name': installer_name}},
                        {'name': 'saw-profile-0', 'configMap': {'name': profiles_name}}]}}}
    cloud_volume = next(v for v in vm['spec']['template']['spec']['volumes'] if v['name'] == 'cloudinit')
    user_data = cloud_volume['cloudInitNoCloud']['userData']
    if len(user_data.encode()) > 2048:
        result.append(obj('Secret', f'{name}-cloudinit', type='Opaque', stringData={'userdata': user_data}))
        cloud_volume['cloudInitNoCloud'] = {'secretRef': {'name': f'{name}-cloudinit'}}
    result.append(vm)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installer-bom', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--name', default='installer-smoke', help='Unique name for a fresh VM, disk and configuration')
    parser.add_argument('--namespace', default=NAMESPACE)
    parser.add_argument('--diagnostics', action='store_true', help='Smoke-only safe console diagnostics; never repairs state')
    parser.add_argument('--bundle-ref', help='Signed release bundle reference, including its immutable digest')
    parser.add_argument('--bundle-digest', help='Signed release bundle digest')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    bom = load_installer_bom(args.installer_bom)
    if not args.bundle_ref or not args.bundle_digest:
        parser.error('--bundle-ref and --bundle-digest are required for a boot smoke')
    if (not args.bundle_digest.startswith('sha256:') or len(args.bundle_digest) != 71 or
            any(char not in '0123456789abcdef' for char in args.bundle_digest[7:])):
        parser.error('--bundle-digest must be sha256 followed by 64 lowercase hexadecimal characters')
    if '@' not in args.bundle_ref or args.bundle_ref.rsplit('@', 1)[-1] != args.bundle_digest:
        parser.error('--bundle-ref must be immutable and match --bundle-digest')
    release = {'name': bom['metadata']['name'], 'bundleRef': args.bundle_ref,
               'bundleDigest': args.bundle_digest, 'bom': bom}
    manifests = resources(bom, args.image, args.name, args.diagnostics, release, args.namespace)
    with args.output.open('x') as stream:
        yaml.safe_dump_all(manifests, stream, sort_keys=False)


if __name__ == '__main__':
    main()
