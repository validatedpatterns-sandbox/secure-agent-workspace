"""Run the shell policy test's offline checks in the normal CI Python suite."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(not shutil.which("helm"), reason="helm is not installed")
def test_network_policy_script_offline():
    result = subprocess.run(
        ["bash", str(ROOT / "tests/test-network-policy.sh")], cwd=ROOT,
        env={**os.environ, "SKIP_LIVE": "1", "PYTHON": sys.executable},
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 failed" in result.stdout
