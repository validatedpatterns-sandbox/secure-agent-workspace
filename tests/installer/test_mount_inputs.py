"""Run the real saw-mount-inputs script (shipped by cloud-init) against fake
disks, with fake mount/mountpoint/install commands."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import CHART

SCRIPT = CHART / "files" / "guest" / "saw-mount-inputs.sh"
MOUNT_FAKES = Path(__file__).resolve().parent / "mountfakes"


@pytest.fixture
def disks(tmp_path):
    """Fake /dev/disk/by-id: each virtio-<serial> is a directory with content."""
    dev = tmp_path / "by-id"
    installer = dev / "virtio-saw-installer"
    installer.mkdir(parents=True)
    (installer / "config.json").write_text(json.dumps({"secrets": ["inference", "web-search"]}))
    (installer / "apply_bom.py").write_text("# installer\n")
    (dev / "virtio-saw-profiles").mkdir()
    (dev / "virtio-saw-profiles" / "profiles__p__ws__workspace.yaml").write_text("x: 1\n")
    (dev / "virtio-saw-proxy-ca").mkdir()
    (dev / "virtio-saw-proxy-ca" / "ca.crt").write_text("public-test-ca\n")
    for i, value in enumerate(["nvidia", "brave"]):
        (dev / f"virtio-saw-sec-{i}").mkdir()
        (dev / f"virtio-saw-sec-{i}" / "provider").write_text(value)
    return dev


def run_script(tmp_path, dev):
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    env = {**os.environ, "PATH": f"{MOUNT_FAKES}:{os.environ['PATH']}", "FAKE_STATE": str(state),
           "SAW_DEV_DIR": str(dev), "SAW_ROOT": str(tmp_path / "run-saw"), "SAW_DEV_WAIT": "0"}
    return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True), state


def log(state, name):
    path = state / name
    return path.read_text().splitlines() if path.exists() else []


def test_mounts_every_disk_by_serial(tmp_path, disks):
    result, state = run_script(tmp_path, disks)
    assert result.returncode == 0, result.stderr
    root = tmp_path / "run-saw"
    assert (root / "installer" / "apply_bom.py").is_file()
    assert (root / "profiles" / "profiles__p__ws__workspace.yaml").is_file()
    # Secret disks follow the order in config.json.
    assert (root / "secrets" / "inference" / "provider").read_text() == "nvidia"
    assert (root / "secrets" / "web-search" / "provider").read_text() == "brave"
    assert not list((root / "secrets").rglob("api_key"))
    assert (root / "proxy-ca" / "ca.crt").read_text() == "public-test-ca\n"
    mounts = log(state, "mount.log")
    assert len(mounts) == 5
    assert all(m.startswith("-t iso9660 -o ro,nosuid,nodev,noexec ") for m in mounts)


def test_second_run_touches_nothing_already_mounted(tmp_path, disks):
    """saw-install and saw-apply both run the script. The second run must
    not touch the read-only mounts (this failed with EROFS before)."""
    first, state = run_script(tmp_path, disks)
    assert first.returncode == 0, first.stderr
    mounts_before = len(log(state, "mount.log"))
    second, state = run_script(tmp_path, disks)
    assert second.returncode == 0, second.stderr
    assert len(log(state, "mount.log")) == mounts_before


def test_missing_installer_disk_fails(tmp_path, disks):
    import shutil
    shutil.rmtree(disks / "virtio-saw-installer")
    result, _ = run_script(tmp_path, disks)
    assert result.returncode == 1
    assert "required disk saw-installer is not attached" in result.stderr


def test_missing_proxy_ca_disk_fails(tmp_path, disks):
    import shutil
    shutil.rmtree(disks / "virtio-saw-proxy-ca")
    result, _ = run_script(tmp_path, disks)
    assert result.returncode == 1
    assert "required disk saw-proxy-ca is not attached" in result.stderr


def test_missing_optional_disks_are_fine(tmp_path, disks):
    import shutil
    shutil.rmtree(disks / "virtio-saw-profiles")
    shutil.rmtree(disks / "virtio-saw-sec-1")
    result, _ = run_script(tmp_path, disks)
    assert result.returncode == 0, result.stderr
    assert "optional disk saw-profiles is not attached" in result.stdout
    assert "optional disk saw-sec-1 is not attached" in result.stdout


def test_virtiofs_is_used_when_the_disk_is_absent(tmp_path, disks):
    import shutil
    shutil.rmtree(disks / "virtio-saw-profiles")
    virtio = tmp_path / "virtiofs"
    (virtio / "saw-profiles").mkdir(parents=True)
    (virtio / "saw-profiles" / "profiles__p__ws__workspace.yaml").write_text("live: 1\n")
    state = tmp_path / "state"
    state.mkdir()
    env = {**os.environ, "PATH": f"{MOUNT_FAKES}:{os.environ['PATH']}", "FAKE_STATE": str(state),
           "FAKE_VIRTIOFS": str(virtio), "SAW_DEV_DIR": str(disks),
           "SAW_ROOT": str(tmp_path / "run-saw"), "SAW_DEV_WAIT": "0"}
    result = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "run-saw" / "profiles" / "profiles__p__ws__workspace.yaml").read_text() == "live: 1\n"
    assert any(line.startswith("-t virtiofs ") for line in log(state, "mount.log"))


def test_invalid_secret_name_is_skipped(tmp_path, disks):
    (disks / "virtio-saw-installer" / "config.json").write_text(
        json.dumps({"secrets": ["../../etc", "inference"]}))
    result, _ = run_script(tmp_path, disks)
    assert result.returncode == 0, result.stderr
    assert "skipping invalid Secret name" in result.stderr
    assert not (tmp_path / "etc").exists()
    # The skipped name keeps its disk position: 'inference' is still disk 1.
    assert (tmp_path / "run-saw" / "secrets" / "inference" / "provider").read_text() == "brave"
