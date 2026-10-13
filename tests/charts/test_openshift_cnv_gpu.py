"""Render the HyperConverged GPU host-device settings."""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openshift-cnv"
HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def render(*args):
    return subprocess.run([HELM, "template", "cnv-test", str(CHART), *args],
                          capture_output=True, text=True)


def test_gpu_requires_exact_host_device_values():
    result = render("--set", "gpu.enabled=true")
    assert result.returncode != 0
    assert "gpu.pciHostDevices must contain an exact PCI selector" in result.stderr


def test_gpu_uses_external_resource_provider():
    result = render("--set", "gpu.enabled=true", "--set-json",
                    'gpu.pciHostDevices=[{"pciDeviceSelector":"10DE:0001","resourceName":"example.com/gpu"}]')
    assert result.returncode == 0, result.stderr
    doc = next(d for d in yaml.safe_load_all(result.stdout) if d["kind"] == "HyperConverged")
    assert doc["spec"]["permittedHostDevices"]["pciHostDevices"] == [
        {"pciDeviceSelector": "10DE:0001", "resourceName": "example.com/gpu",
         "externalResourceProvider": True}]
