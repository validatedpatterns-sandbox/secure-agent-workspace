"""Trusted-proxy GUI launch must retain the owner-authenticated route."""
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("matches", [0, 1, 2])
def test_trusted_gui_selects_one_matching_sso_route_without_forwarding(tmp_path, matches):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    def executable(name, body):
        p = bindir / name
        p.write_text("#!/bin/bash\nset -euo pipefail\n" + body)
        p.chmod(0o755)
    secret = "synthetic-private-gateway-password"
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"gateway": {"auth": {"mode": "trusted-proxy", "password": secret}}}))
    route = {"metadata": {"annotations": {"openshell.pattern/workspace": "cuda-dev",
             "openshell.pattern/sandbox": "cuda-sandbox"}},
             "spec": {"host": "cuda-ui.example.test", "tls": {"termination": "edge"}}}
    unrelated = {**route, "metadata": {"annotations": {"openshell.pattern/workspace": "other",
                 "openshell.pattern/sandbox": "cuda-sandbox"}}}
    routes = tmp_path / "routes.json"
    routes.write_text(json.dumps({"items": [unrelated, *[route] * matches]}))
    executable("openshell", 'cat "$GUI_CONFIG"\n')
    executable("oc", 'printf "%s\\n" "$@" > "$OC_ARGS"\ncat "$GUI_ROUTES"\n')
    executable("lsof", "exit 0\n")  # SSO launch must not depend on a local port.
    executable("ssh", 'touch "$SSH_CALLED"\nexit 3\n')
    for name in ("open", "xdg-open"):
        executable(name, 'printf "%s" "$1" > "$OPENED_URL"\n')
    result = subprocess.run(["bash", "scripts/openshell-saw-gui.sh"], cwd=ROOT,
        env=dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
                 GATEWAY_NAME="audit-a", SANDBOX_NAME="cuda-sandbox", WORKSPACE="cuda-dev", SAW_NS="",
                 GUI_CONFIG=str(cfg), GUI_ROUTES=str(routes), OC_ARGS=str(tmp_path / "oc-args"),
                 OPENED_URL=str(tmp_path / "opened"), SSH_CALLED=str(tmp_path / "ssh")),
        capture_output=True, text=True)
    assert not (tmp_path / "ssh").exists()
    assert secret not in result.stdout + result.stderr
    assert "saw-audit-a" in (tmp_path / "oc-args").read_text()
    if matches == 1:
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "opened").read_text() == "https://cuda-ui.example.test"
    else:
        assert result.returncode != 0
        assert "one owner-authenticated route" in result.stderr
        assert not (tmp_path / "opened").exists()
