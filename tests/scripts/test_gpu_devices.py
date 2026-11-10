"""Run the guest boot helper with isolated device paths and command fakes."""
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "image-builder-charts/helm/openshell-gateway-image/files/saw-gpu-devices.sh"


@pytest.mark.parametrize("caps", [False, True])
@pytest.mark.parametrize("existing_uvm", [False, True])
def test_gpu_boot_prepares_uvm_and_optional_caps(tmp_path, caps, existing_uvm):
    dev = tmp_path / "dev"
    dev.mkdir()
    (dev / "nvidia0").symlink_to("/dev/null")
    if existing_uvm:
        (dev / "nvidia-uvm").symlink_to("/dev/null")
    if caps:
        capdir = dev / "nvidia-caps"
        capdir.mkdir()
        (capdir / "nvidia-cap1").symlink_to("/dev/null")
    proc = tmp_path / "proc-devices"
    proc.write_text("195 nvidia\n508 nvidia-uvm\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "calls"
    for name in ("modprobe", "nvidia-smi", "getsebool", "setsebool", "chcon", "chmod", "python3", "nvidia-ctk", "mknod"):
        stub = bindir / name
        stub.write_text('''#!/bin/bash
echo "${0##*/} $*" >> "$CALLS"
case "${0##*/}" in
  getsebool) echo 'container_use_devices --> on' ;;
  mknod) ln -s /dev/null "$3" ;;
  nvidia-ctk)
    [[ -c "$DEV/nvidia-uvm" && -c "$DEV/nvidia-uvm-tools" ]] || exit 7
    [[ "$*" == *"--feature-flag=no-additional-gids-for-device-nodes"* ]] || exit 8 ;;
esac
''')
        stub.chmod(0o755)
    isolated = tmp_path / "gpu-devices.sh"
    isolated.write_text(SCRIPT.read_text().replace("/dev/", str(dev) + "/")
                        .replace("/proc/devices", str(proc))
                        .replace("/etc/cdi", str(tmp_path / "cdi")))
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CALLS=str(calls), DEV=str(dev))
    for _ in range(2):
        result = subprocess.run(["bash", str(isolated)], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    commands = calls.read_text().splitlines()
    assert sum(line.startswith("mknod ") for line in commands) == (1 if existing_uvm else 2)
    assert commands.index("modprobe nvidia-uvm") < next(i for i, c in enumerate(commands) if c.startswith("nvidia-ctk "))
    assert sum(line.startswith("python3 ") for line in commands) == (2 if caps else 0)
    assert not any(line.startswith("setsebool ") for line in commands)
