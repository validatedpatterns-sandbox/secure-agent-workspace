"""Verify the tools baked into both GHCR gateway disk variants."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def executable(path, body):
    path.write_text("#!/bin/bash\nset -euo pipefail\n" + body)
    path.chmod(0o755)


@pytest.mark.parametrize("floor", ["", "enforce"])
def test_gateway_verification_tools_are_installed(tmp_path, floor):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    executable(bindir / "curl", 'while [[ "$1" != "-o" ]]; do shift; done\nprintf cosign-test > "$2"\n')
    guest = tmp_path / "guest"
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", COSIGN_URL="https://example.test/cosign",
               COSIGN_SHA256=hashlib.sha256(b"cosign-test").hexdigest(), SIGNING_FLOOR=floor)
    result = subprocess.run(["bash", str(ROOT / "scripts/install-gateway-verification.sh"), str(guest)],
                            cwd=ROOT, env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert (guest / "usr/local/bin/cosign").read_bytes() == b"cosign-test"
    assert (guest / "usr/libexec/saw/verify-bundle").read_bytes() == (
        ROOT / "image-builder-charts/helm/openshell-gateway-image/files/verify-bundle").read_bytes()
    assert (guest / "etc/saw/trust").is_dir()
    mode = guest / "etc/saw/signing-mode"
    assert mode.exists() == bool(floor)
    if floor:
        assert mode.read_text() == floor
    failed_guest = tmp_path / "bad-guest"
    result = subprocess.run(["bash", str(ROOT / "scripts/install-gateway-verification.sh"), str(failed_guest)],
                            cwd=ROOT, env=dict(env, COSIGN_SHA256="0" * 64), text=True, capture_output=True)
    assert result.returncode != 0
    assert not (failed_guest / "usr/local/bin/cosign").exists()


@pytest.mark.skipif(not shutil.which("curl"), reason="curl is not installed")
@pytest.mark.parametrize("statuses,payload,attempts,success", [
    ([504, 504, 200], b"cosign-test", 3, True),
    ([504], b"cosign-test", 4, False),
    ([404], b"cosign-test", 1, False),
    ([504, 200], b"tampered", 2, False),
])
def test_cosign_download_retries_transient_errors_and_keeps_integrity_check(
        tmp_path, statuses, payload, attempts, success):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status = statuses[min(len(requests), len(statuses) - 1)]
            requests.append(status)
            body = payload if status == 200 else b"download failed"
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            if status == 504:
                self.send_header("Retry-After", "1")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    guest = tmp_path / "guest"
    archives = tmp_path / "archives"
    archives.mkdir()
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = dict(os.environ, COSIGN_URL=f"http://127.0.0.1:{server.server_port}/cosign",
                   COSIGN_SHA256=hashlib.sha256(b"cosign-test").hexdigest(), SIGNING_FLOOR="",
                   TMPDIR=str(archives), NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
        try:
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/install-gateway-verification.sh"), str(guest)],
                cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        finally:
            server.shutdown()
            thread.join()

    assert (result.returncode == 0) == success, result.stderr
    assert len(requests) == attempts
    installed = guest / "usr/local/bin/cosign"
    assert installed.exists() == success
    if success:
        assert installed.read_bytes() == b"cosign-test"
    assert not list(archives.iterdir())
