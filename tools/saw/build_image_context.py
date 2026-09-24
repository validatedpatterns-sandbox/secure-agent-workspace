#!/usr/bin/env python3
"""Generate an allowlisted binary build context. No build, push or deployment."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/saw'))
from build_guest_bundle import build, load_installer_bom  # noqa: E402


def create_context(output, installer_bom, release_public_key=None, enable_ssh=False):
    bom = load_installer_bom(installer_bom)
    recipe = (ROOT / 'guest/image/Containerfile.in').read_text()
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    (output / 'customize.sh').write_bytes((ROOT / 'guest/image/customize.sh').read_bytes())
    bundle_hash = build(output / 'guest.tar.gz', installer_bom)
    if enable_ssh:
        (output / 'enable-ssh.sh').write_text('''#!/bin/bash
set -euo pipefail
ssh-keygen -A
install -d -m 0755 /etc/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/sshd.service /etc/systemd/system/multi-user.target.wants/sshd.service
''')
        (output / 'enable-ssh.sh').chmod(0o700)
        recipe = recipe.replace(
            'COPY guest.tar.gz customize.sh /build/',
            'COPY guest.tar.gz customize.sh enable-ssh.sh /build/'
        )
        recipe = recipe.replace(
            'podman,shadow-utils,slirp4netns,passt,fuse-overlayfs,python3,python3-pyyaml,cloud-init,qemu-guest-agent,openssl',
            'podman,shadow-utils,slirp4netns,passt,fuse-overlayfs,python3,python3-pyyaml,cloud-init,qemu-guest-agent,openssl,openssh-server'
        )
        recipe = recipe.replace(
            '--run /build/customize.sh \\\n',
            '--run /build/customize.sh \\\n      --run /build/enable-ssh.sh \\\n'
        )
    if release_public_key:
        key = Path(release_public_key)
        (output / 'release-signing-public-key.pem').write_bytes(key.read_bytes())
        recipe = recipe.replace(
            'COPY guest.tar.gz customize.sh enable-ssh.sh /build/',
            'COPY guest.tar.gz customize.sh enable-ssh.sh release-signing-public-key.pem /build/'
        )
        recipe = recipe.replace(
            'COPY guest.tar.gz customize.sh /build/',
            'COPY guest.tar.gz customize.sh release-signing-public-key.pem /build/'
        )
    else:
        recipe = recipe.replace('      --copy-in /build/release-signing-public-key.pem:/etc/ \\\n', '')
    (output / 'Dockerfile').write_text(recipe)
    manifest = {'installerBOM': bom, 'bundleSHA256': bundle_hash,
                'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(output.iterdir())}}
    (output / 'build-inputs.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--installer-bom', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release-public-key', type=Path)
    parser.add_argument('--enable-ssh', action='store_true',
                        help='build a diagnostic-only image with sshd enabled')
    args = parser.parse_args()
    create_context(args.output, args.installer_bom, args.release_public_key, args.enable_ssh)
    print(f'Image build context: {args.output}; no image built or published')


if __name__ == '__main__':
    main()
