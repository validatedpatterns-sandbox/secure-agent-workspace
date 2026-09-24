"""The new data-only delivery mode never packages executable provisioning code."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def render(*values):
    assert shutil.which("helm"), "Helm is required; chart validation must not silently skip"
    command = ["helm", "template", "test-profiles", str(ROOT / "charts/saw-bom"), "--namespace", "saw-test"]
    for value in values:
        command += ["--set", value]
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)


def test_data_only_profiles():
    result = render("delivery.mode=data", "delivery.configMapName=alice-profiles")
    assert result.returncode == 0, result.stderr
    docs = list(yaml.safe_load_all(result.stdout))
    assert len(docs) == 1
    cm = docs[0]
    assert cm["metadata"]["name"] == "alice-profiles"
    assert "apply_bom.py" not in cm["data"]
    assert len(cm["data"]) == 6
    assert all(key.startswith("profiles__data-science__") for key in cm["data"])


def test_legacy_delivery_unchanged():
    result = render()
    assert result.returncode == 0, result.stderr
    cm = yaml.safe_load(result.stdout)
    assert cm["metadata"]["name"] == "saw-bom-profiles"
    assert "apply_bom.py" in cm["data"]


@pytest.mark.parametrize("value", ["delivery.mode=unknown", "profiles[0]=missing", "profiles[0]=../evil",
                                   "delivery.configMapName=Not-Valid", "profiles[1]=data-science"])
def test_invalid_profile_packaging_fails(value):
    assert render("delivery.mode=data", value).returncode != 0
