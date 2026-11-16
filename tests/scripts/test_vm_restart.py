"""Guest restart must not turn inaccessible or slow guests into a hard reset."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def restart_env(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy2(ROOT / "scripts/openshell-saw-restart.sh", scripts)
    helper = scripts / "openshell-saw-vm-ssh.sh"
    helper.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\nexit "${SSH_EXIT:-0}"\n')
    helper.chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    oc = bindir / "oc"
    oc.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
if sys.argv[1:3] == ['get', 'vm']:
    print(os.environ.get('STRATEGY', 'Always'), end='')
else:
    counter=pathlib.Path(os.environ['COUNTER'])
    n=int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(n+1))
    values=json.loads(os.environ['VMI_STATES'])
    print(values[min(n,len(values)-1)],end='')
''')
    oc.chmod(0o755)
    host = bindir / "virtctl"
    host.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$HOST_CALLS"\nexit 99\n')
    host.chmod(0o755)
    sleep = bindir / "sleep"
    sleep.write_text("#!/bin/sh\n")
    sleep.chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "SAW_NS": "saw-alice", "VM_NAME": "alice", "CALLS": str(tmp_path / "calls"),
           "COUNTER": str(tmp_path / "counter"), "HOST_CALLS": str(tmp_path / "host-calls"),
           "VMI_STATES": json.dumps(["old Running", "old Running", "", "new Pending", "new Running"])}
    return scripts / "openshell-saw-restart.sh", env


def run(restart_env, **overrides):
    script, env = restart_env
    return subprocess.run(["bash", str(script)], env={**env, **overrides},
                          capture_output=True, text=True, timeout=5)


def test_waits_through_old_missing_and_starting_instances(restart_env):
    result = run(restart_env)
    assert result.returncode == 0, result.stderr
    assert Path(restart_env[1]["CALLS"]).read_text() == "sudo systemctl poweroff\n"
    assert not Path(restart_env[1]["HOST_CALLS"]).exists()
    assert "Replacement VM saw-alice/alice is Running" in result.stdout
    assert "boot install/apply" in result.stdout


def test_non_always_strategy_is_refused_before_guest_changes(restart_env):
    result = run(restart_env, STRATEGY="Manual")
    assert result.returncode != 0
    assert "requires runStrategy: Always" in result.stderr
    assert not Path(restart_env[1]["CALLS"]).exists()


def test_failed_guest_command_does_not_claim_restart_or_force_it(restart_env):
    result = run(restart_env, SSH_EXIT="255")
    assert result.returncode != 0
    assert "Replacement VM" not in result.stdout
    assert not Path(restart_env[1]["HOST_CALLS"]).exists()
    assert Path(restart_env[1]["COUNTER"]).read_text() == "1"
    assert Path(restart_env[1]["CALLS"]).read_text() == "sudo systemctl poweroff\n"


def test_nonrunning_instance_is_refused_before_guest_changes(restart_env):
    result = run(restart_env, VMI_STATES=json.dumps(["old Failed"]))
    assert result.returncode != 0
    assert "must have a Running instance" in result.stderr
    assert not Path(restart_env[1]["CALLS"]).exists()
