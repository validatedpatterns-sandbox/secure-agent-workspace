"""Regression coverage for Helm rendering and the VM cache helper."""
import os
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def rendered_scripts():
    rendered = subprocess.check_output([
        "helm", "template", "openshell-saw", str(ROOT / "charts/openshell-saw"),
        "--namespace", "openshell-agents",
        "-f", str(ROOT / "overrides/openshell-saw.yaml"),
    ], text=True)
    return next(doc["data"] for doc in yaml.safe_load_all(rendered)
                if doc and doc.get("kind") == "ConfigMap"
                and doc["metadata"]["name"] == "openshell-saw-scripts")


@pytest.mark.parametrize("digest,expected", [("sha256:" + "a" * 64, 0), ("", 1), ('[{"Id":"bad"}]', 1)])
def test_rendered_cache_helper(rendered_scripts, tmp_path, digest, expected):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    runtime = bindir / "docker"
    runtime.write_text('#!/bin/bash\nif [[ "$1" == "images" ]]; then printf "%s\\n" "$TEST_DIGEST"; fi\n')
    runtime.chmod(0o755)
    # Substitute only the installed binary source; write into the real temp cache.
    installer = bindir / "install"
    installer.write_text('#!/bin/bash\ncp "$TEST_BINARY" "$4" && chmod "$2" "$4"\n')
    installer.chmod(0o755)
    binary = tmp_path / "supervisor"
    binary.write_text("ODH sandbox binary")
    env = dict(os.environ, HOME=str(tmp_path), PATH=f"{bindir}:{os.environ['PATH']}",
               TEST_DIGEST=digest, TEST_BINARY=str(binary))
    result = subprocess.run(["bash", "-s", "--", "docker"],
                            input=rendered_scripts["prepopulate-supervisor-cache.sh"],
                            env=env, text=True, capture_output=True)
    assert result.returncode == expected, result.stderr
    cache = tmp_path / ".local/share/openshell/docker-supervisor" / ("sha256-" + "a" * 64) / "openshell-sandbox"
    if expected == 0:
        assert cache.read_text() == "ODH sandbox binary"
        assert cache.stat().st_mode & 0o777 == 0o755
    else:
        assert not cache.exists()


def test_rendered_dropin_transfer(rendered_scripts, tmp_path):
    script = rendered_scripts["upgrade-openshell.sh"]
    block = script.split("# --- Pre-populate", 1)[1].split("# --- Patch OIDC", 1)[0]
    block = "# --- Pre-populate" + block
    # Execute the local heredoc and parse every remote command without running it.
    stubs = '''set -euo pipefail
guest_scp() { test -f "$1"; }
guest_ssh() { printf '%s\\n' "$1" >> "$WORK_DIR/remote-commands"; printf '%s\\n' "$1" | bash -n; if [[ "$1" == 'id -u' ]]; then echo 1000; fi; }
'''
    (tmp_path / "prepopulate-supervisor-cache.sh").write_text(rendered_scripts["prepopulate-supervisor-cache.sh"])
    (tmp_path / "configure-docker-mtu.sh").write_text(rendered_scripts["configure-docker-mtu.sh"])
    result = subprocess.run(["bash"], input=stubs + block, text=True, capture_output=True,
                            env=dict(os.environ, WORK_DIR=str(tmp_path), SCRIPTS_DIR=str(tmp_path), RUNTIME="docker"))
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "zz-prepopulate-cache.conf").read_text() == (
        "[Service]\nExecStartPre=/usr/local/bin/openshell-prepopulate-cache docker\n")
    commands = (tmp_path / "remote-commands").read_text()
    assert 'install -m 644 /tmp/zz-prepopulate-cache.conf "$HOME/.config/systemd/user/openshell-gateway.service.d/zz-prepopulate-cache.conf"' in commands
    assert 'rm -f "$HOME/.config/systemd/user/openshell-gateway.service.d/prepopulate-cache.conf"' in commands
    # systemd applies drop-ins lexically; route-san.conf resets ExecStartPre.
    assert "zz-prepopulate-cache.conf" > "route-san.conf"
    unit = (tmp_path / "openshell-docker-mtu.service").read_text()
    assert "Before=user@1000.service" in unit
    assert "Requires=docker.service" in unit
    assert "PartOf=docker.service" in unit
    assert "ExecStart=/usr/local/bin/openshell-configure-docker-mtu" in unit
    assert "sudo" not in unit
    assert 'sudo systemctl restart openshell-docker-mtu.service' in commands
    assert 'rm -f "$HOME/.config/systemd/user/openshell-gateway.service.d/zz-docker-mtu.conf"' in commands
