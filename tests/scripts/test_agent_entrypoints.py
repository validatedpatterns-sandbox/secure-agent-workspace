"""Run the real TUI shell payload with fake executables and private test credentials."""
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


def executable(path, source):
    path.write_text(source)
    path.chmod(0o755)


@pytest.mark.parametrize("mode", ["nemoclaw", "openclaw"])
def test_tui_uses_the_local_password_without_putting_it_in_arguments(tmp_path, mode):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    output = tmp_path / "call.json"
    executable(bindir / "openshell", '''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
assert args[:3] == ["--gateway","alice","sandbox"]
assert "--tty" in args and "--no-tty" not in args
assert "-n" in args and args[args.index("-n")+1] == "cuda-sandbox"
assert args[args.index("--workspace")+1] == "cuda-dev"
Path(os.environ["TUI_TEST_ARGS"]).write_text(json.dumps(args))
os.execv("/bin/bash", ["bash","-c",args[-1]])
''')
    executable(bindir / "node", '#!/bin/sh\nprintf %s test-local-password\n')
    executable(bindir / "openclaw", '''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
Path(os.environ["TUI_TEST_OUTPUT"]).write_text(json.dumps({"args":sys.argv[1:],
    "env":{k:os.environ.get(k) for k in ("HOME","OPENCLAW_HOME","OPENCLAW_CONFIG_PATH",
        "OPENCLAW_GATEWAY_PASSWORD","SQLITE_TMPDIR","TMPDIR","OPENCLAW_NIX_MODE")}}))
''')
    executable(bindir / "ssh", '#!/bin/sh\necho "unexpected password-less SSH entrypoint" >&2\nexit 99\n')
    args = tmp_path / "args.json"
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", OPENSHELL_SAW_NAME="alice",
               SANDBOX_NAME="cuda-sandbox", WORKSPACE="cuda-dev", TUI_TEST_OUTPUT=str(output),
               TUI_TEST_ARGS=str(args))
    result = subprocess.run(["bash",str(ROOT / "scripts/saw-tui.sh"),mode],env=env,
                            text=True,capture_output=True)
    assert result.returncode == 0, result.stderr
    call = json.loads(output.read_text())
    assert call["args"] == ["tui"]
    assert call["env"] == {
        "HOME":"/sandbox", "OPENCLAW_HOME":"/sandbox",
        "OPENCLAW_CONFIG_PATH":"/sandbox/.openclaw/openclaw.json",
        "OPENCLAW_GATEWAY_PASSWORD":"test-local-password",
        "SQLITE_TMPDIR":"/sandbox/.openclaw/state", "TMPDIR":"/sandbox/.openclaw/state",
        "OPENCLAW_NIX_MODE":"0"}
    assert "test-local-password" not in args.read_text() + result.stdout + result.stderr
