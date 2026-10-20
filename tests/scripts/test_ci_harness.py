"""Exercise CI bootstrap and runner failures without a live cluster."""

import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = load_module("ci_gateway_login", ROOT / "scripts/ci-gateway-login.py")
runner = load_module("ci_script_runner", ROOT / "tests/ci/script_runner.py")


@pytest.fixture
def setup(tmp_path):
    env = runner.make_ci_environment(tmp_path, {"PATH": os.environ["PATH"],
                                               "VP_HUBCONFIG": "/ci/kubeconfig"})
    return bootstrap.Bootstrap(env)


def token_response(setup, **extra):
    path = Path(setup.env["OIDC_TOKEN_DIR"]) / "token.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"access_token": "access-secret", "refresh_token": "refresh-secret",
                                "saved_at": int(time.time()), "expires_in": 600, **extra}))


def test_gateway_token_is_converted_to_cli_contract(setup):
    token_response(setup)
    setup.write_gateway("gateway.example", "https://keycloak/realms/openshell")
    path = setup.gateway_dir / "oidc_token.json"
    token = json.loads(path.read_text())
    assert token["access_token"] == "access-secret"
    assert token["refresh_token"] == "refresh-secret"
    assert token["issuer"] == "https://keycloak/realms/openshell"
    assert token["client_id"] == "openshell-cli"
    assert time.time() + 590 < token["expires_at"] <= time.time() + 600
    metadata = json.loads((setup.gateway_dir / "metadata.json").read_text())
    assert metadata["gateway_endpoint"] == "https://gateway.example"
    assert metadata["auth_mode"] == "oidc"
    assert path.stat().st_mode & 0o777 == 0o600
    assert setup.gateway_dir.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("extra", [{"expires_in": -1}, {"access_token": {}},
                                   {"expires_in": "invalid"}])
def test_invalid_tokens_do_not_create_a_gateway(setup, extra):
    token_response(setup, **extra)
    with pytest.raises(bootstrap.SetupError, match="invalid or expired"):
        setup.write_gateway("gateway", "issuer")
    assert not (setup.gateway_dir / "oidc_token.json").exists()


def test_full_bootstrap_targets_alice_and_never_invokes_browser(setup, monkeypatch):
    calls = []
    status_reads = 0
    monkeypatch.setattr(bootstrap.shutil, "which", lambda *a, **kw: "/bin/tool")
    monkeypatch.setattr(bootstrap.time, "sleep", lambda seconds: None)

    def run(args, *, env=None, **kwargs):
        nonlocal status_reads
        calls.append((args, env))
        output = ""
        if "jsonpath={.spec.host}" in args:
            output = "gateway.example"
        elif args[-1].endswith("keycloak-host.sh") or "keycloak-host.sh" in " ".join(args):
            output = "keycloak.example"
        elif "jsonpath={.data.alice}" in args:
            output = base64.b64encode(b"generated-password").decode()
        elif "oidc-login.sh" in " ".join(args):
            assert env["OIDC_PASSWORD"] == "generated-password"
            assert env["OIDC_FLOW"] == "password"
            token_response(setup)
        elif args[-1] == "sudo cat /var/lib/saw/status.json":
            status_reads += 1
            output = json.dumps({"install": {"phase": "Done"},
                                 "apply": {"phase": "Running" if status_reads == 1 else "Done"}})
        return subprocess.CompletedProcess(args, 0, output, "")

    monkeypatch.setattr(setup, "run", run)
    setup.setup()
    assert status_reads == 2
    assert all("gateway" not in args or "add" not in args for args, _ in calls)
    assert all("generated-password" not in " ".join(args) for args, _ in calls)
    assert calls[-1][0] == ["openshell", "--gateway", "alice", "sandbox", "exec",
                            "-n", "notebook", "--workspace", "default", "--no-tty", "--", "true"]
    assert setup.env["KUBECONFIG"] == "/ci/kubeconfig"


@pytest.mark.parametrize("error", ["Forbidden: cannot read secret", "Unauthorized",
                                   "Password login failed; invalid credentials",
                                   "Password login returned an invalid token response"])
def test_permission_and_login_errors_fail_without_retry(setup, error):
    calls = []

    def operation():
        calls.append(True)
        return subprocess.CompletedProcess([], 1, "", error)

    with pytest.raises(bootstrap.SetupError, match=error.split(":")[0]):
        setup.wait("login", operation)
    assert len(calls) == 1


def test_readiness_deadline_reports_the_stage(setup):
    setup.deadline = time.monotonic() + 0.01
    with pytest.raises(bootstrap.SetupError, match="timed out during gateway route"):
        setup.wait("gateway route", lambda: subprocess.CompletedProcess([], 1, "", "NotFound"))


def test_hung_command_is_bounded(setup):
    start = time.monotonic()
    result = setup.run(["bash", "-c", "sleep 30 & wait"], limit=0.05)
    assert result.returncode == 124
    assert time.monotonic() - start < 3


@pytest.mark.parametrize("output", ["progress\n{}", '[]', '{"apply":{"phase":"Failed"}}'])
def test_installer_invalid_or_failed_status_is_not_ready(output):
    with pytest.raises(bootstrap.SetupError):
        bootstrap.Bootstrap.installer_ready(output)


def test_environment_overrides_vp_workspace_and_keeps_kubeconfig(tmp_path):
    original = {"HOME": "/home/runner", "WORKSPACE": "/checkout/tests/ci",
                "VP_HUBCONFIG": "/ci/kubeconfig", "KUBECONFIG": "/wrong",
                "OPENSHELL_GATEWAY_ENDPOINT": "https://wrong", "OIDC_ISSUER": "https://old"}
    env = runner.make_ci_environment(tmp_path, original)
    assert original["WORKSPACE"] == "/checkout/tests/ci"
    assert env["WORKSPACE"] == "default" and env["KUBECONFIG"] == "/ci/kubeconfig"
    assert env["HOME"] == original["HOME"]
    assert "OPENSHELL_GATEWAY_ENDPOINT" not in env and "OIDC_ISSUER" not in env
    assert env["XDG_CONFIG_HOME"] == str(tmp_path / "config")


def test_script_failure_includes_output(tmp_path, monkeypatch):
    (tmp_path / "failure.sh").write_text("echo harness-output; echo failure-detail >&2; exit 7\n")
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    with pytest.raises(AssertionError, match=r"exit 7") as error:
        runner.run_script("failure.sh", os.environ, timeout=5)
    assert "harness-output" in str(error.value) and "failure-detail" in str(error.value)


def test_script_timeout_includes_output(tmp_path, monkeypatch):
    (tmp_path / "hang.sh").write_text("echo starting; sleep 30 & wait\n")
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    with pytest.raises(AssertionError, match="timed out") as error:
        runner.run_script("hang.sh", os.environ, timeout=0.05)
    assert "starting" in str(error.value)


def test_missing_clients_are_staged_from_cluster_metadata_and_pinned_bom(setup, monkeypatch):
    bindir = Path(setup.env["CI_BIN_DIR"])
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name, **kw: None)
    monkeypatch.setattr(bootstrap.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(bootstrap.platform, "system", lambda: "Linux")
    image = "quay.io/example/cli@sha256:" + "a" * 64
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        output = ""
        if "consoleclidownloads" in args:
            output = json.dumps({"items": [{"spec": {"links": [
                {"href": "https://cluster/arm64/linux/virtctl.tar.gz"},
                {"href": "https://cluster/amd64/linux/virtctl.tar.gz"}]}}]})
        elif "router-ca" in args:
            output = base64.b64encode(b"cluster ingress CA").decode()
        elif args[0] == "curl":
            assert "--cacert" in args and "--insecure" not in args
            assert args[-1] == "https://cluster/amd64/linux/virtctl.tar.gz"
            with tarfile.open(args[args.index("-o") + 1], "w:gz") as archive:
                for name in ("../../unwanted", "virtctl"):
                    member = tarfile.TarInfo(name)
                    member.size = 6
                    archive.addfile(member, io.BytesIO(b"binary"))
        elif "configmap" in args:
            output = json.dumps({"data": {"installer-bom.yaml":
                f"spec:\n  openshell:\n    cli:\n      image: {image}\n      version: 0.1.2-rhaiv.0\n"}})
        elif args[:3] == ["oc", "image", "extract"]:
            assert args[3] == image and "--filter-by-os=linux/amd64" in args
            (bindir / "openshell").write_text("binary")
        elif args[-1] == "--version":
            output = "openshell 0.1.2-rhaiv.0\n"
        else:
            pytest.fail(f"Unexpected tool install command: {args}")
        return subprocess.CompletedProcess(args, 0, output, "")

    monkeypatch.setattr(setup, "run", run)
    setup.ensure_tools()
    assert (bindir / "virtctl").read_bytes() == b"binary"
    assert not (bindir.parent.parent / "unwanted").exists()
    assert setup.env["PATH"].split(os.pathsep)[0] == str(bindir)
    assert (bindir / "openshell").stat().st_mode & 0o777 == 0o700
