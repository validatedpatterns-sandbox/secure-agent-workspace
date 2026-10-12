"""Verify the tools baked into both GHCR gateway disk variants."""
import hashlib
import os
import subprocess
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
    executable(bindir / "curl", '[[ "$1 $2" == "-fsSL -o" ]]\nprintf cosign-test > "$3"\n')
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
