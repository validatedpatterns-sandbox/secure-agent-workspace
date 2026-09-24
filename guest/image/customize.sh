#!/bin/bash
# Runs only in a fresh Fedora cloud disk, offline through virt-customize.
set -euo pipefail
tar --extract --gzip --file=/opt/guest.tar.gz --directory=/ --no-same-owner
if ! id cloud-user >/dev/null 2>&1; then
    useradd --create-home --uid 1000 --user-group cloud-user
fi
usermod --groups '' --lock cloud-user
install -d -m 0755 /var/lib/saw /etc/saw
if [[ -f /etc/release-signing-public-key.pem ]]; then
    install -m 0644 /etc/release-signing-public-key.pem /etc/saw/release-signing-public-key.pem
    rm -f /etc/release-signing-public-key.pem
fi
install -d -m 0700 /var/lib/saw/reconciler
install -d -m 0755 /var/lib/systemd/linger
touch /var/lib/systemd/linger/cloud-user
# Only the enrolled guest starts the gateway; no rootful Podman socket at boot.
systemctl disable podman.socket podman.service || true
systemctl enable qemu-guest-agent.service saw-guest.service
python3 - <<'PY'
from pathlib import Path
import yaml
# Cloud-init must not turn the gateway runtime identity into a sudo administrator.
config = {'system_info': {'default_user': {'name': 'cloud-user', 'lock_passwd': True,
                                         'groups': [], 'sudo': [], 'shell': '/bin/bash'}}}
Path('/etc/cloud/cloud.cfg.d/99-saw-runtime-user.cfg').write_text(yaml.safe_dump(config))
for source in ('/etc/subuid', '/etc/subgid'):
    entries = [r.split(':') for r in Path(source).read_text().splitlines()]
    assert any(len(r) == 3 and r[0] == 'cloud-user' and int(r[2]) >= 65536 for r in entries)
assert not Path('/etc/saw/guest.json').exists()
assert not Path('/var/lib/saw/gateway').exists()
assert not Path('/var/lib/saw/openshell-client').exists()
PY
cloud-init clean --logs --seed --machine-id
# virt-customize is not booted under systemd. cloud-init may therefore remove
# machine-id instead of leaving a systemd first-boot sentinel. Keep an empty
# mount point: systemd must be able to bind its fresh ID before / is remounted RW.
install -m 0444 /dev/null /etc/machine-id
# Remove only fresh-image build inputs and generated SSH host identities.
rm -f /opt/guest.tar.gz
find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*' -delete
find /var/log -type f -exec truncate -s 0 {} +
