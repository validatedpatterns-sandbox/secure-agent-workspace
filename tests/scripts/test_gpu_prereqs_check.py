"""GPU preflight is read-only and fails before deployment on missing resources."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/gpu-prereqs-check.sh"
pytestmark = pytest.mark.skipif(not shutil.which("jq"), reason="jq is not installed")


def invoke(tmp_path, *, name="example.com/gpu", count="1", hco=True, allocatable="1", denied=False,
           layout="legacy"):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls"
    fake = bindir / "oc"
    fake.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["OC_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ["DENIED"] == "1":
    sys.exit("Forbidden")
if sys.argv[1:] == ["get", "hyperconverged", "kubevirt-hyperconverged", "-n", "openshift-cnv", "-o", "json"]:
    print(os.environ["HCO_JSON"])
elif sys.argv[1:] == ["get", "nodes", "-o", "json"]:
    print(os.environ["NODES_JSON"])
else:
    sys.exit("unexpected cluster mutation or read")
''')
    fake.chmod(0o755)
    devices = {"permittedHostDevices": {"pciHostDevices":
        [{"resourceName": "example.com/gpu"}] if hco else []}}
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", GPU_DEVICE_NAME=name,
               GPU_COUNT=count, OC_LOG=str(log), DENIED=str(int(denied)),
               HCO_JSON=json.dumps({"spec": devices if layout == "legacy" else {"virtualization": devices}}),
               NODES_JSON=json.dumps({"items": [{"status": {"allocatable": {
                   "example.com/gpu": allocatable}}}]}))
    result = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True)
    return result, [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_missing_device_name_stops_before_cluster_reads(tmp_path):
    result, calls = invoke(tmp_path, name="")
    assert result.returncode != 0 and "needs GPU_DEVICE_NAME" in result.stderr
    assert calls == []


@pytest.mark.parametrize("count", ["0", "-1", "false", "1.5", ""])
def test_invalid_count_stops_before_cluster_reads(tmp_path, count):
    result, calls = invoke(tmp_path, count=count)
    assert result.returncode != 0 and "positive integer" in result.stderr
    assert calls == []


def test_missing_hco_entry_stops_before_node_read(tmp_path):
    result, calls = invoke(tmp_path, hco=False)
    assert result.returncode != 0 and "no pciHostDevices entry" in result.stderr
    assert len(calls) == 1


@pytest.mark.parametrize("allocatable", ["0", "1"])
def test_insufficient_allocatable_is_rejected(tmp_path, allocatable):
    result, calls = invoke(tmp_path, count="2", allocatable=allocatable)
    assert result.returncode != 0 and "no node advertises 2" in result.stderr
    assert len(calls) == 2


@pytest.mark.parametrize("layout", ["legacy", "virtualization"])
def test_gpu_gate_passes_without_changing_cluster(tmp_path, layout):
    result, calls = invoke(tmp_path, count="2", allocatable="2", layout=layout)
    assert result.returncode == 0, result.stderr
    assert "at least 2 on one node" in result.stdout
    assert len(calls) == 2 and all(call[0] == "get" for call in calls)


def test_access_failure_is_reported(tmp_path):
    result, calls = invoke(tmp_path, denied=True)
    assert result.returncode != 0 and "Forbidden" in result.stderr
    assert len(calls) == 1
