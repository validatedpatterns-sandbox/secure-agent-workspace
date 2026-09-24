"""Release-data and single-script contracts; no OpenShell API/client dependency."""

import base64
import io
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def bom():
    return yaml.safe_load((ROOT / "examples/saw/installer-bom.yaml").read_text())


@pytest.fixture
def snapshot(bom):
    return {"installerBOM": bom, "enrollmentIdentity": "a" * 64, "ownerSubject": "owner",
            "credentials": {"provider-secret": {"api_key": base64.b64encode(b"PRIVATE-CANARY").decode()}},
            "workspaces": [{"profile": "research", "name": "research",
                "workspace": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Workspace",
                              "metadata": {"name": "research"},
                              "spec": {"members": [{"subject": "owner", "role": "admin"}]}},
                "providers": [{"name": "nvidia", "type": "nvidia",
                               "secretRef": {"name": "provider-secret", "key": "api_key"}}],
                "sandboxes": []}]}


@pytest.mark.parametrize("version", ["0.0.116-rhaiv.0", "0.0.120-rhaiv.3", "1.2.3"])
def test_release_selects_versions_without_fixed_116_gate(installer, bom, version, monkeypatch):
    for component in bom["spec"]["openshell"].values():
        component["version"] = version
        component["image"] = "registry.test/new-release@sha256:" + "a" * 64
    assert installer.validate_installer_bom(bom) == bom
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["timeout"] == 15
        assert not kwargs.get("shell")
        return subprocess.CompletedProcess(command, 0, "openshell " + version, "")

    monkeypatch.setattr(installer.subprocess, "run", run)
    installer.verify_installed_software(bom)
    assert len(calls) == 3
    assert all(command[1:] == ["--version"] for command in calls)


@pytest.mark.parametrize("mutation", ["missing-image", "mutable-image", "command", "script-url", "inline-secret", "installer-version", "missing-component", "unknown-component"])
def test_bom_rejects_unsafe_or_incomplete_release_before_execution(installer, bom, mutation):
    spec = bom["spec"]
    if mutation == "missing-image":
        del spec["openshell"]["cli"]["image"]
    elif mutation == "mutable-image":
        spec["openshell"]["cli"]["image"] = "registry.test/cli:latest"
    elif mutation == "installer-version":
        spec["installerVersion"] = "999.0.0"
    elif mutation == "missing-component":
        del spec["openshell"]["supervisor"]
    elif mutation == "unknown-component":
        spec["openshell"]["untrusted"] = deepcopy(spec["openshell"]["cli"])
    else:
        spec[mutation] = "PRIVATE-CANARY"
    with pytest.raises(ValueError):
        installer.validate_installer_bom(bom)


def test_version_mismatch_is_not_reported_as_installed(installer, bom, monkeypatch):
    monkeypatch.setattr(installer.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 0, "openshell wrong-version", ""))
    with pytest.raises(installer.InstallerError, match="SoftwareReleaseMismatch"):
        installer.verify_installed_software(bom)


def test_validate_only_cli_never_deploys(installer, bom, tmp_path):
    path = tmp_path / "release.yaml"
    path.write_text(yaml.safe_dump(bom))
    result = subprocess.run([sys.executable, str(ROOT / "installer/apply_bom.py"),
        "--installer-bom", str(path), "--validate-installer-bom"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "no installation" in result.stdout


def test_bom_duplicate_keys_are_rejected(installer, bom, tmp_path):
    path = tmp_path / "duplicate.yaml"
    path.write_text(yaml.safe_dump(bom) + "kind: InstallerBOM\n")
    with pytest.raises(ValueError):
        installer.load_installer_bom(path)


def test_guest_refuses_sandbox_profiles_before_partial_apply(installer, bom, snapshot, monkeypatch, capsys):
    digest = "a" * 64
    snapshot["workspaces"][0]["sandboxes"] = [{"name": "notebook", "type": "generic",
        "image": "registry.test/image@sha256:" + digest,
        "data": {"name": "notebook", "mountPath": "/sandbox/persist", "retainOnDelete": True}}]
    request = {"version": 1, "revision": {"id": "a" * 32, "snapshot": snapshot}}
    monkeypatch.setattr(installer, "load_installer_bom", lambda path: bom)
    monkeypatch.setattr(installer.sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))
    monkeypatch.setattr(installer.subprocess, "run", lambda *a, **kw: pytest.fail("must reject before commands"))
    assert installer.guest_main("apply") == 1
    response = capsys.readouterr()
    assert "PRIVATE-CANARY" not in response.out + response.err
    assert json.loads(response.out)["reason"] == "SandboxApplyNotImplemented"


def test_changed_software_bom_cannot_silently_overwrite_running_binaries(installer, bom, monkeypatch):
    desired = deepcopy(bom)
    desired["spec"]["openshell"]["gateway"]["version"] = "9.1.0"
    monkeypatch.setattr(installer, "load_installer_bom", lambda path: bom)
    with pytest.raises(installer.InstallerError, match="SoftwareUpgradeNotImplemented"):
        installer.validate_guest_release({"installerBOM": desired, "workspaces": []})


def test_installer_logic_version_can_advance_with_same_image_payload(installer, bom, monkeypatch):
    installed = deepcopy(bom)
    installed["spec"]["installerVersion"] = "0.1.0"
    monkeypatch.setattr(installer, "load_installer_bom", lambda path: installed)
    monkeypatch.setattr(installer, "verify_installed_software", lambda release: None)
    snapshot = {"installerBOM": bom, "workspaces": [], "enrollmentIdentity": "a" * 64,
                "ownerSubject": "owner"}
    assert installer.validate_guest_release(snapshot) == bom


def test_bad_request_errors_are_public_safe(installer, monkeypatch, capsys):
    monkeypatch.setattr(installer.sys, "stdin", io.TextIOWrapper(io.BytesIO(b"PRIVATE-CANARY invalid json")))
    assert installer.guest_main("apply") == 1
    result = capsys.readouterr()
    assert "PRIVATE-CANARY" not in result.out + result.err
    assert json.loads(result.out)["ok"] is False


def test_no_separate_adapter_or_vendored_protocol_is_shipped():
    for path in ("guest/saw_guest/adapter.py", "guest/saw_guest/rpc.py", "guest/saw_guest/runtime.py",
                 "guest/saw_guest/control_plane.py", "guest/bin/saw-openshell-adapter",
                 "tools/saw/build_api_descriptor.py", "guest/runtime-lock.json"):
        assert not (ROOT / path).exists()
    assert not list((ROOT / "guest").rglob("*.proto"))
    for path in ("requirements-saw-test.txt", "guest/requirements.txt"):
        text = (ROOT / path).read_text()
        assert "grpc" not in text and "protobuf" not in text


class LocalGateway:
    """CLI-contract simulator. Not evidence that a real gateway was qualified."""

    def __init__(self):
        self.workspaces, self.members, self.providers = {}, {}, {}
        self.inference = {}
        self.calls = []
        self.fail_after_create = False

    def run(self, command, **options):
        self.calls.append((command, deepcopy(options["env"])))
        assert command[:4] == ["/usr/local/bin/openshell", "--gateway=saw-local",
            "--gateway-endpoint=https://127.0.0.1:17670", "--color=never"]
        assert options["stdin"] == subprocess.DEVNULL
        assert options["stderr"] == subprocess.DEVNULL
        assert options["timeout"] == 20
        assert not options.get("shell")
        args = command[4:]
        flags = dict(arg[2:].split("=", 1) for arg in args if arg.startswith("--") and "=" in arg)
        scope = flags.get("workspace")
        output = None
        if args[:2] == ["workspace", "list"]:
            output = list(self.workspaces.values())
        elif args[:3] == ["workspace", "member", "list"]:
            output = list(self.members[scope].values())
        elif args[:2] == ["provider", "list"]:
            output = list(self.providers[scope].values())
        elif args[:2] == ["inference", "set"]:
            assert "--no-verify" not in args and "--system" not in args
            self.inference[scope] = {"provider": flags["provider"], "model": flags["model"]}
        elif args[:2] == ["inference", "get"]:
            route = self.inference.get(scope)
            text = (f"Inference:\n  Workspace: {scope}\n  Provider: {route['provider']}\n"
                    f"  Model: {route['model']}\n  Version: 1\n  Timeout: 60s\n") if route else "Inference:\n  Not configured\n"
            options["stdout"].write((text + "\nSystem inference:\n  Not configured\n").encode())
        elif args[:2] == ["workspace", "create"]:
            name = flags["name"]
            assert name not in self.workspaces
            key, value = flags["label"].split("=", 1)
            assert len(value) <= 63
            self.workspaces[name] = {"name": name, "status": "Active", "labels": {key: value}}
            self.members[name], self.providers[name] = {}, {}
        elif args[:3] == ["workspace", "member", "add"]:
            subject = flags["subject"]
            assert subject not in self.members[scope]
            self.members[scope][subject] = {"subject": subject, "role": flags["role"]}
        elif args[:3] == ["workspace", "member", "remove"]:
            del self.members[scope][flags["subject"]]
        elif args[:2] in (["provider", "create"], ["provider", "update"]):
            key = flags["credential"]
            assert key == "NVIDIA_API_KEY"
            value = options["env"][key]
            assert value not in " ".join(command)
            if args[1] == "create":
                name = flags["name"]
                assert name not in self.providers[scope]
                self.providers[scope][name] = {"name": name, "workspace": scope,
                    "type": flags["type"], "credential_keys": [key]}
            else:
                name = args[2]
                assert name in self.providers[scope]
            # Test-only private value, intentionally not part of CLI output.
            self.last_credential = (scope, name, value)
            if self.fail_after_create:
                self.fail_after_create = False
                raise subprocess.TimeoutExpired(command, 20, output="PRIVATE-CANARY")
        else:
            raise AssertionError(args)
        if output is not None:
            start = int(flags["offset"])
            options["stdout"].write(json.dumps(output[start:start + 100]).encode())
        return subprocess.CompletedProcess(command, 0)

    def mutations(self):
        return [cmd for cmd, _ in self.calls if "list" not in cmd]


@pytest.fixture
def gateway(installer, bom, monkeypatch):
    runtime = LocalGateway()
    monkeypatch.setattr(installer, "check_guest_client", lambda: None)
    monkeypatch.setattr(installer, "verify_installed_software", lambda bom: None)
    monkeypatch.setattr(installer, "load_installer_bom", lambda path: bom)
    monkeypatch.setattr(installer, "prepare_guest_gateway", lambda snapshot, phase: True)
    monkeypatch.setattr(installer.subprocess, "run", runtime.run)
    return runtime


def test_mounted_profile_preflight_apply_verify_and_retry(installer, snapshot, gateway):
    installer.validate_guest_release(snapshot)
    installer.reconcile_guest_profiles(snapshot, "validate")
    assert not gateway.mutations()
    installer.reconcile_guest_profiles(snapshot, "apply")
    assert gateway.last_credential == ("research", "nvidia", "PRIVATE-CANARY")
    before = len(gateway.mutations())
    installer.reconcile_guest_profiles(snapshot, "verify")
    assert len(gateway.mutations()) == before
    installer.reconcile_guest_profiles(snapshot, "apply")
    assert len(gateway.workspaces) == 1
    assert len(gateway.providers["research"]) == 1
    assert len(gateway.members["research"]) == 1


def test_retry_after_provider_write_timeout_does_not_delete_or_duplicate(installer, snapshot, gateway):
    gateway.fail_after_create = True
    with pytest.raises(installer.InstallerError, match="OpenShellCommandFailed"):
        installer.reconcile_guest_profiles(snapshot, "apply")
    installer.reconcile_guest_profiles(snapshot, "apply")
    installer.reconcile_guest_profiles(snapshot, "verify")
    assert len(gateway.providers["research"]) == 1
    assert not any("delete" in c for c, _ in gateway.calls)


def test_credential_rotation_does_not_use_environment_fallback(installer, snapshot, gateway, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "WRONG-INHERITED-SECRET")
    monkeypatch.setenv("OPENSHELL_GATEWAY_INSECURE", "true")
    installer.reconcile_guest_profiles(snapshot, "apply")
    snapshot["credentials"]["provider-secret"]["api_key"] = base64.b64encode(b"ROTATED-SECRET").decode()
    installer.reconcile_guest_profiles(snapshot, "apply")
    assert gateway.last_credential[-1] == "ROTATED-SECRET"
    for command, env in gateway.calls:
        assert "WRONG-INHERITED-SECRET" not in env.values()
        assert "OPENSHELL_GATEWAY_INSECURE" not in env
        assert "ROTATED-SECRET" not in " ".join(command)
        if not any(arg.startswith("--credential=") for arg in command):
            assert "NVIDIA_API_KEY" not in env


def test_same_provider_name_is_scoped_per_workspace(installer, snapshot, gateway):
    second = deepcopy(snapshot["workspaces"][0])
    second["name"] = second["workspace"]["metadata"]["name"] = "second"
    second["providers"][0]["secretRef"]["name"] = "second-secret"
    snapshot["credentials"]["second-secret"] = {"api_key": base64.b64encode(b"SECOND-SECRET").decode()}
    snapshot["workspaces"].append(second)
    installer.validate_guest_profiles(snapshot)
    installer.reconcile_guest_profiles(snapshot, "apply")
    installer.reconcile_guest_profiles(snapshot, "verify")
    assert gateway.last_credential == ("second", "nvidia", "SECOND-SECRET")
    assert set(gateway.providers) == {"research", "second"}


def test_membership_changes_revoke_before_provider_write(installer, snapshot, gateway):
    installer.reconcile_guest_profiles(snapshot, "apply")
    gateway.members["research"].update({"revoked": {"subject": "revoked", "role": "admin"},
                                       "demoted": {"subject": "demoted", "role": "admin"}})
    snapshot["workspaces"][0]["workspace"]["spec"]["members"].append({"subject": "demoted", "role": "member"})
    with pytest.raises(installer.InstallerError, match="WorkspaceMembersNotConverged"):
        installer.reconcile_guest_profiles(snapshot, "verify")
    gateway.calls.clear()
    installer.reconcile_guest_profiles(snapshot, "apply")
    installer.reconcile_guest_profiles(snapshot, "verify")
    assert "revoked" not in gateway.members["research"]
    assert gateway.members["research"]["demoted"]["role"] == "user"
    mutations = gateway.mutations()
    assert all("member" in cmd for cmd in mutations[:-1])
    assert "provider" in mutations[-1]


@pytest.mark.parametrize("conflict,reason", [("owner", "WorkspaceOwnershipConflict"),
    ("unlabeled", "WorkspaceOwnershipConflict"), ("status", "WorkspaceNotActive"),
    ("provider-type", "ProviderTypeChangeRequiresMigration"), ("provider-scope", "ProviderWorkspaceMismatch")])
def test_conflicts_block_all_mutations(installer, snapshot, gateway, conflict, reason):
    installer.reconcile_guest_profiles(snapshot, "apply")
    if conflict == "owner":
        gateway.workspaces["research"]["labels"][installer.GUEST_OWNER_LABEL] = "someone-else"
    elif conflict == "unlabeled":
        gateway.workspaces["research"]["labels"] = {}
    elif conflict == "status":
        gateway.workspaces["research"]["status"] = "Terminating"
    elif conflict == "provider-type":
        gateway.providers["research"]["nvidia"]["type"] = "openai"
    else:
        gateway.providers["research"]["nvidia"]["workspace"] = "foreign"
    gateway.calls.clear()
    with pytest.raises(installer.InstallerError, match=reason):
        installer.reconcile_guest_profiles(snapshot, "apply")
    assert not gateway.mutations()


@pytest.mark.parametrize("mutation", ["missing-secret", "empty", "nul", "non-utf8", "bad-base64",
    "unsupported-provider", "owner-missing", "duplicate-member", "disabled-inference-provider", "unknown-field"])
def test_profile_preflight_rejects_invalid_input_before_cli(installer, snapshot, gateway, mutation):
    ws = snapshot["workspaces"][0]
    if mutation == "missing-secret":
        snapshot["credentials"] = {}
    elif mutation in {"empty", "nul", "non-utf8", "bad-base64"}:
        raw = {"empty": b" ", "nul": b"x\x00", "non-utf8": b"\xff", "bad-base64": b"unused"}[mutation]
        snapshot["credentials"]["provider-secret"]["api_key"] = (
            "not-base64!" if mutation == "bad-base64" else base64.b64encode(raw).decode())
    elif mutation == "unsupported-provider":
        ws["providers"][0]["type"] = "custom"
    elif mutation == "owner-missing":
        ws["workspace"]["spec"]["members"] = []
    elif mutation == "duplicate-member":
        ws["workspace"]["spec"]["members"] *= 2
    elif mutation == "disabled-inference-provider":
        ws["providers"][0]["enabled"] = False
        ws["workspace"]["spec"]["inference"] = {"provider": "nvidia", "model": "example/model"}
    else:
        ws["providers"][0]["script"] = "PRIVATE-CANARY"
    with pytest.raises(ValueError):
        installer.validate_guest_release(snapshot)
    assert not gateway.calls


def test_flag_like_subject_is_one_argument_not_an_option(installer, snapshot, gateway):
    snapshot["workspaces"][0]["workspace"]["spec"]["members"].append({
        "subject": "--role=admin $(touch nope)", "role": "member"})
    installer.validate_guest_profiles(snapshot)
    installer.reconcile_guest_profiles(snapshot, "apply")
    assert gateway.members["research"]["--role=admin $(touch nope)"]["role"] == "user"


def test_json_pagination_covers_later_pages(installer, snapshot, gateway):
    for i in range(100):
        gateway.workspaces[f"foreign-{i}"] = {"name": f"foreign-{i}", "labels": {}}
    installer.reconcile_guest_profiles(snapshot, "apply")
    installer.reconcile_guest_profiles(snapshot, "verify")
    assert any("--offset=100" in c for c, _ in gateway.calls)


@pytest.mark.parametrize("page", [{"items": []}, [{"name": "same"}, {"name": "same"}], ["bad"]])
def test_malformed_cli_collections_are_not_treated_as_absence(installer, monkeypatch, page):
    monkeypatch.setattr(installer, "guest_cli", lambda *a, **kw: page)
    with pytest.raises(installer.InstallerError, match="InvalidOpenShellCollection"):
        installer.guest_list(["workspace", "list"])


def test_cli_failure_never_exposes_output_or_credential(installer, snapshot, gateway, monkeypatch, capsys):
    def fail(command, **options):
        options["stdout"].write(b"PRIVATE-CANARY already exists")
        return subprocess.CompletedProcess(command, 1)
    monkeypatch.setattr(installer.subprocess, "run", fail)
    request = {"version": 1, "revision": {"id": "a" * 32, "snapshot": snapshot}}
    monkeypatch.setattr(installer.sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))
    assert installer.guest_main("apply") == 1
    output = capsys.readouterr()
    assert "PRIVATE-CANARY" not in output.out + output.err
    assert json.loads(output.out)["reason"] == "OpenShellCommandFailed"


def test_verify_requires_provider_and_credential_key(installer, snapshot, gateway):
    installer.reconcile_guest_profiles(snapshot, "apply")
    gateway.providers["research"]["nvidia"]["credential_keys"] = []
    with pytest.raises(installer.InstallerError, match="ProviderNotConverged"):
        installer.reconcile_guest_profiles(snapshot, "verify")
    gateway.providers["research"].clear()
    with pytest.raises(installer.InstallerError, match="ProviderNotConverged"):
        installer.reconcile_guest_profiles(snapshot, "verify")


def test_workspace_inference_apply_readback_and_update(installer, snapshot, gateway):
    spec = snapshot["workspaces"][0]["workspace"]["spec"]
    spec["inference"] = {"provider": "nvidia", "model": "example/first"}
    installer.validate_guest_profiles(snapshot)
    installer.reconcile_guest_profiles(snapshot, "apply")
    installer.reconcile_guest_profiles(snapshot, "verify")
    spec["inference"]["model"] = "example/second"
    with pytest.raises(installer.InstallerError, match="InferenceNotConverged"):
        installer.reconcile_guest_profiles(snapshot, "verify")
    installer.reconcile_guest_profiles(snapshot, "apply")
    installer.reconcile_guest_profiles(snapshot, "verify")
    assert gateway.inference["research"]["model"] == "example/second"


@pytest.mark.parametrize("output", ["Inference:\n  Not configured\n", "Inference:\n  Error: unavailable\n",
    "unknown-output", "Inference:\n  Workspace: wrong\n  Provider: nvidia\n  Model: example/model\n  Version: 1\n",
    "Inference:\n  Workspace: research\n  Provider: nvidia\n  Model: example/model\n  Version: 0\n"])
def test_zero_exit_inference_errors_cannot_pass_readiness(installer, monkeypatch, output):
    monkeypatch.setattr(installer, "guest_cli", lambda *a, **kw: output)
    with pytest.raises(installer.InstallerError, match="InferenceNotConverged"):
        installer.verify_guest_inference("research", {"provider": "nvidia", "model": "example/model"})


@pytest.mark.parametrize("unsafe", [None, "symlink", "writable", "key-readable", "foreign-owner", "stored-login", "missing"])
def test_local_mtls_identity_is_private_and_cannot_select_other_auth(installer, monkeypatch, tmp_path, unsafe):
    config = tmp_path / "client"
    gateway = config / "openshell/gateways/saw-local"
    directory = gateway / "mtls"
    directory.mkdir(parents=True)
    for filename in ("ca.crt", "tls.crt", "tls.key"):
        path = directory / filename
        path.write_text("test-only")
        path.chmod(0o600)
    if unsafe == "symlink":
        (directory / "ca.crt").unlink()
        (directory / "ca.crt").symlink_to(directory / "tls.crt")
    elif unsafe == "writable":
        directory.chmod(0o777)
    elif unsafe == "key-readable":
        (directory / "tls.key").chmod(0o644)
    elif unsafe == "stored-login":
        (gateway / "oidc_token.json").write_text("test-only")
    elif unsafe == "missing":
        (directory / "tls.key").unlink()
    original = Path.lstat

    def lstat(path):
        # Simulate root ownership without requiring privileged tests. Ancestors
        # above this fixture represent the production /var/lib/saw path.
        info = original(path)
        mode = info.st_mode if path.is_relative_to(tmp_path) else 0o40755
        return SimpleNamespace(st_mode=mode, st_uid=1234 if unsafe == "foreign-owner" else 0)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(installer, "GUEST_CLIENT_CONFIG", config)
    if unsafe:
        with pytest.raises((installer.InstallerError, OSError)):
            installer.check_guest_client()
    else:
        installer.check_guest_client()


def test_guest_journal_with_real_apply_logic_rotates_and_repairs_drift(installer, snapshot, gateway, tmp_path):
    from saw_guest.reconcile import InstallerFailed, Reconciler, State

    class Inputs:
        def capture(self):
            return deepcopy(snapshot)

    class Script:
        def call(self, phase, revision):
            try:
                installer.validate_guest_release(revision["snapshot"])
                installer.reconcile_guest_profiles(revision["snapshot"], phase)
                return True
            except installer.InstallerError:
                if phase == "verify":
                    return False
                raise InstallerFailed() from None

        def preflight(self, revision):
            self.call("validate", revision)

        def apply(self, revision):
            self.call("apply", revision)

        def verify(self, revision):
            return self.call("verify", revision)

    state = State(tmp_path / "state")
    reconciler = Reconciler(Inputs(), state, Script())
    assert reconciler.run()
    mutations = len(gateway.mutations())
    assert reconciler.run()
    assert len(gateway.mutations()) == mutations
    gateway.members["research"]["unexpected"] = {"subject": "unexpected", "role": "admin"}
    assert reconciler.run()
    assert "unexpected" not in gateway.members["research"]
    snapshot["credentials"]["provider-secret"]["api_key"] = base64.b64encode(b"ROTATED").decode()
    assert reconciler.run()
    assert gateway.last_credential[-1] == "ROTATED"
    assert state.read()["pending"] is None
    assert state.read()["accepted"]["snapshot"] == snapshot
