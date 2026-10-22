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


def run_check(tmp_path, *, subject="bob-sub", status="200", grpc_code="7", route=True,
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
    curl.write_text('''#!/usr/bin/env python3
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if os.environ["CURL_FAIL"] == "yes":
    sys.exit(7)
assert "--http2" in args
assert args[-1] == "https://saw.example.test/openshell.v1.OpenShell/ListSandboxes"
request = Path(args[args.index("--data-binary") + 1].removeprefix("@"))
assert request.read_bytes() == b"\\x00\\x00\\x00\\x00\\x0b\\x22\\x09\\x0a\\x07default"
assert request.stat().st_mode & 0o077 == 0
headers = [args[i + 1] for i, arg in enumerate(args) if arg == "--header"]
assert "Content-Type: application/grpc" in headers
assert "TE: trailers" in headers
authorization = Path(next(header[1:] for header in headers if header.startswith("@")))
assert authorization.read_text().startswith("Authorization: Bearer a.")
assert authorization.stat().st_mode & 0o077 == 0
response = Path(args[args.index("--dump-header") + 1])
grpc_code = os.environ["GRPC_CODE"]
response.write_bytes(b"HTTP/2 200\\r\\ncontent-type: application/grpc\\r\\n\\r\\n" +
                     (f"grpc-status: {grpc_code}\\r\\n".encode() if grpc_code else b""))
print(os.environ["HTTP_STATUS"], end="")
''')
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
               GRPC_CODE=grpc_code, CURL_FAIL="yes" if curl_fails else "no")
    result = subprocess.run(["bash", str(SCRIPT)], env=env, cwd=ROOT,
                            text=True, capture_output=True)
    assert "a." not in result.stdout + result.stderr
    return result


def test_second_user_permission_denied_passes(tmp_path):
    result = run_check(tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"result": "denied", "protocol": "grpc", "grpc_code": 7}


@pytest.mark.parametrize("changes", [
    {"subject": "alice-sub"}, {"status": "404"}, {"status": "401"},
    {"grpc_code": "0"}, {"grpc_code": "16"}, {"grpc_code": ""},
    {"route": False}, {"expires": False}, {"curl_fails": True},
])
def test_non_isolation_results_fail(tmp_path, changes):
    result = run_check(tmp_path, **changes)
    assert result.returncode != 0
    assert not result.stdout
