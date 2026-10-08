"""saw-with-lock holds one flock so two reconciles cannot overlap."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("flock") is None, reason="requires flock")
def test_two_locked_commands_do_not_overlap(tmp_path):
    script = Path(__file__).resolve().parents[2] / "charts" / "openshell-saw" / "files" / "guest" / "saw-with-lock"
    lock = tmp_path / "saw" / "lock"
    log = tmp_path / "log"
    env = {**os.environ, "SAW_LOCK_FILE": str(lock)}
    inner = f"echo start >> {log}; sleep 0.3; echo end >> {log}"
    cmd = ["bash", str(script), "bash", "-c", inner]
    first = subprocess.Popen(cmd, env=env)
    second = subprocess.Popen(cmd, env=env)
    assert first.wait(timeout=10) == 0
    assert second.wait(timeout=10) == 0
    assert log.read_text().split() == ["start", "end", "start", "end"]
