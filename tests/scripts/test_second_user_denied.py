"""The default isolation check fails closed and prints no credentials."""
import base64
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-second-user-denied.sh"


def run_check(tmp_path, *, subject="bob-sub", status="403", route=True,
              expires=True, curl_fails=False):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    oc = bindir / "oc"
    oc.write_text("#!/bin/sh\n"
                  "if [ \"${ROUTE_PRESENT}\" = yes ]; then "
                  "printf '%s\\n' '{\"spec\":{\"host\":\"saw.example.test\"}}'; "
                  "else exit 1; fi\n")
    oc.chmod(0o755)
    curl = bindir / "curl"
    curl.write_text("#!/bin/sh\n"
                    "[ \"${CURL_FAIL}\" = yes ] && exit 7\n"
                    "printf '%s' \"${HTTP_STATUS}\"\n")
    curl.chmod(0o755)
    claims = {"sub": subject, "exp": int(time.time()) + (300 if expires else -300)}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    token_dir = tmp_path / "second"
    token_dir.mkdir()
    (token_dir / "token.json").write_text(json.dumps({"access_token": f"a.{payload}.c"}))
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
               TEST_SECOND_TOKEN_DIR=str(token_dir), TEST_OWNER_SUBJECT="alice-sub",
               TEST_ACTIVE_SAW_NAME="alice", TEST_ACTIVE_SAW_NS="saw-alice",
               ROUTE_PRESENT="yes" if route else "no", HTTP_STATUS=status,
               CURL_FAIL="yes" if curl_fails else "no")
    result = subprocess.run(["bash", str(SCRIPT)], env=env, cwd=ROOT,
                            text=True, capture_output=True)
    assert "a." not in result.stdout + result.stderr
    return result


def test_second_user_403_passes(tmp_path):
    result = run_check(tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"result": "denied", "status_code": 403}


@pytest.mark.parametrize("changes", [
    {"subject": "alice-sub"}, {"status": "200"}, {"status": "401"},
    {"route": False}, {"expires": False}, {"curl_fails": True},
])
def test_non_isolation_results_fail(tmp_path, changes):
    result = run_check(tmp_path, **changes)
    assert result.returncode != 0
    assert not result.stdout
