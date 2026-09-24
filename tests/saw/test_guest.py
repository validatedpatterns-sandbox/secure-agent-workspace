"""Guest-only reconciliation contracts using synthetic mounts/runtime, no API access."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tarfile
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from openshell_saw.blueprints import ValidationError
from saw_guest.inputs import InputsChanged, MountedInputs, canonical, validate_settings
from saw_guest.health import ready
from saw_guest.mounts import mount_plan
from saw_guest.reconcile import InstallerFailed, Busy, Reconciler, State, plan

ROOT = Path(__file__).resolve().parents[2]


class FakeRuntime:
    """Test-only runtime with no subprocess, containers, network or credentials."""
    def __init__(self):
        self.current = None
        self.calls = []
        self.fail = None

    def preflight(self, revision):
        self.calls.append(("preflight", deepcopy(revision)))
        if self.fail == "preflight":
            raise InstallerFailed()

    def apply(self, revision):
        self.calls.append(("apply", deepcopy(revision)))
        self.current = deepcopy(revision)
        if self.fail == "apply":
            raise RuntimeError("synthetic failure containing PRIVATE-CREDENTIAL")

    def verify(self, revision):
        self.calls.append(("verify", deepcopy(revision)))
        return self.fail != "verify" and self.current == revision


@pytest.fixture
def guest(tmp_path, profile_inputs):
    selections, cms = profile_inputs
    mounts = tmp_path / "mounts"
    (mounts / "intent").mkdir(parents=True)
    intent = {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "SawInstance",
              "metadata": {"name": "research"},
              "spec": {"ownerSubject": "owner", "workspaces": selections}}
    (mounts / "intent/instance.yaml").write_text(yaml.safe_dump(intent))
    (mounts / "installer").mkdir()
    (mounts / "installer/installer-bom.yaml").write_text((ROOT / "examples/saw/installer-bom.yaml").read_text())
    directory = mounts / "profiles/profiles"
    directory.mkdir(parents=True)
    for key, value in cms[0]["data"].items():
        (directory / key).write_text(value)
    secret = mounts / "credentials/saw-provider-nvidia"
    secret.mkdir(parents=True)
    (secret / "api_key").write_bytes(b"PRIVATE-CREDENTIAL")
    settings = {"namespace": "saw-test", "instance": "research", "ownerSubject": "owner",
                "enrollmentIdentity": "a" * 64, "profileConfigMaps": ["profiles"],
                "providerSecrets": {"saw-provider-nvidia": ["api_key"]}}
    inputs = MountedInputs(mounts, settings)
    state = State(tmp_path / "state")
    runtime = FakeRuntime()
    return Reconciler(inputs, state, runtime), mounts


def read_status(reconciler):
    return json.loads((reconciler.state.directory / "status.json").read_text())


def edit_yaml(path, mutate):
    doc = yaml.safe_load(path.read_text())
    mutate(doc)
    path.write_text(yaml.safe_dump(doc))


def test_boot_then_unchanged_inputs_only_verify(guest):
    reconciler, _ = guest
    assert reconciler.run()
    first = reconciler.state.read()["accepted"]
    assert reconciler.run()
    assert reconciler.state.read()["accepted"] == first
    assert [op for op, _ in reconciler.installer.calls].count("apply") == 1
    assert read_status(reconciler)["phase"] == "Converged"
    assert "PRIVATE" not in canonical(read_status(reconciler))


def test_inference_removal_requires_explicit_decommission(guest):
    reconciler, _ = guest
    before = reconciler.inputs.capture()
    after = deepcopy(before)
    del after["workspaces"][0]["workspace"]["spec"]["inference"]
    with pytest.raises(ValidationError, match="inference removal"):
        plan(before, after)


def test_credential_rotation_and_metadata_touch(guest):
    reconciler, mounts = guest
    assert reconciler.run()
    first = reconciler.state.read()["accepted"]["id"]
    key = mounts / "credentials/saw-provider-nvidia/api_key"
    key.touch()
    assert reconciler.run()
    assert reconciler.state.read()["accepted"]["id"] == first
    key.write_bytes(b"ROTATED-PRIVATE-CREDENTIAL")
    assert reconciler.run()
    revision = reconciler.state.read()["accepted"]
    assert revision["id"] != first
    assert {"resource": "provider/default/nvidia", "action": "rotate-credentials"} in revision["actions"]
    assert "ROTATED" not in canonical(read_status(reconciler))


def test_image_update_plan_preserves_data_identity(guest):
    reconciler, mounts = guest
    assert reconciler.run()
    previous = reconciler.state.read()["accepted"]
    path = mounts / "profiles/profiles/profiles__data-science__default__sandbox.yaml"
    edit_yaml(path, lambda d: d["spec"]["sandboxes"][0].update(image="registry.test/image@sha256:" + "c" * 64))
    assert reconciler.run()
    updated = reconciler.state.read()["accepted"]
    assert updated["actions"] == [{"resource": "sandbox/default/notebook", "action": "update"}]
    assert previous["snapshot"]["workspaces"][0]["sandboxes"][0]["data"] == updated["snapshot"]["workspaces"][0]["sandboxes"][0]["data"]


@pytest.mark.parametrize("failure", ["apply", "verify"])
def test_restart_reuses_pending_id_and_does_not_accept_unverified_state(guest, failure):
    reconciler, _ = guest
    reconciler.installer.fail = failure
    assert not reconciler.run()
    state = reconciler.state.read()
    assert state["accepted"] is None and state["pending"] is not None
    pending = state["pending"]
    restarted = Reconciler(reconciler.inputs, State(reconciler.state.directory), reconciler.installer)
    restarted.installer.fail = None
    assert restarted.run()
    assert restarted.state.read()["accepted"] == pending
    ids = {r["id"] for op, r in restarted.installer.calls if op == "apply"}
    assert ids == {pending["id"]}


def test_changed_inputs_do_not_replay_revoked_pending_credentials(guest):
    reconciler, mounts = guest
    reconciler.installer.fail = "apply"
    assert not reconciler.run()
    count = len(reconciler.installer.calls)
    (mounts / "credentials/saw-provider-nvidia/api_key").write_bytes(b"new-credential")
    reconciler.installer.fail = None
    assert not reconciler.run()
    assert len(reconciler.installer.calls) == count
    assert read_status(reconciler)["phase"] == "Blocked"


def test_input_change_during_apply_does_not_report_convergence(guest):
    reconciler, mounts = guest
    original = reconciler.installer.apply

    def apply(revision):
        original(revision)
        (mounts / "credentials/saw-provider-nvidia/api_key").write_bytes(b"new-credential")

    reconciler.installer.apply = apply
    assert not reconciler.run()
    assert reconciler.state.read()["accepted"] is None
    assert reconciler.state.read()["pending"] is not None


def test_runtime_drift_is_reapplied(guest):
    reconciler, _ = guest
    assert reconciler.run()
    previous = reconciler.state.read()['accepted']
    reconciler.installer.current = None
    restarted = Reconciler(reconciler.inputs, State(reconciler.state.directory), reconciler.installer)
    assert restarted.run()
    repaired = restarted.state.read()['accepted']
    assert repaired['snapshot'] == previous['snapshot']
    assert repaired['id'] != previous['id']
    assert repaired['actions'] == []
    assert restarted.run()
    assert restarted.state.read()['accepted'] == repaired
    assert [op for op, _ in reconciler.installer.calls].count("apply") == 2


def test_input_change_during_unchanged_verification_invalidates_readiness(guest):
    reconciler, mounts = guest
    assert reconciler.run()
    accepted = reconciler.state.read()["accepted"]
    verify = reconciler.installer.verify

    def rotating_verify(revision):
        result = verify(revision)
        (mounts / "credentials/saw-provider-nvidia/api_key").write_bytes(b"new-credential")
        return result

    reconciler.installer.verify = rotating_verify
    assert not reconciler.run()
    assert reconciler.state.read()["accepted"] == accepted
    assert not ready(reconciler.state.directory)


@pytest.mark.parametrize("kind", ["workspace", "provider", "sandbox"])
def test_disabling_existing_resources_requires_explicit_lifecycle(guest, kind):
    reconciler, _ = guest
    previous = reconciler.inputs.capture()
    desired = deepcopy(previous)
    workspace = desired["workspaces"][0]
    if kind == "workspace":
        workspace["workspace"]["spec"]["enabled"] = False
    else:
        workspace[{"provider": "providers", "sandbox": "sandboxes"}[kind]][0]["enabled"] = False
    with pytest.raises(ValidationError, match="disable"):
        plan(previous, desired)


def test_failed_installer_does_not_create_pending_or_fake_applied(guest):
    reconciler, _ = guest
    reconciler.installer.fail = "preflight"
    assert not reconciler.run()
    assert reconciler.state.read()["pending"] is None
    assert read_status(reconciler)["phase"] == "InstallerFailed"


@pytest.mark.parametrize("mutation", ["remove", "data-change", "mutable-image", "inline-command", "bad-owner"])
def test_unsafe_updates_keep_accepted_state_and_do_not_call_installer(guest, mutation):
    reconciler, mounts = guest
    assert reconciler.run()
    accepted = reconciler.state.read()["accepted"]
    calls = len(reconciler.installer.calls)
    sandbox = mounts / "profiles/profiles/profiles__data-science__default__sandbox.yaml"
    if mutation == "remove":
        edit_yaml(sandbox, lambda d: d["spec"].update(sandboxes=[]))
    elif mutation == "data-change":
        edit_yaml(sandbox, lambda d: d["spec"]["sandboxes"][0]["data"].update(name="other-data"))
    elif mutation == "mutable-image":
        edit_yaml(sandbox, lambda d: d["spec"]["sandboxes"][0].update(image="registry.test/image:latest"))
    elif mutation == "inline-command":
        edit_yaml(mounts / "intent/instance.yaml", lambda d: d["spec"].update(command="run-untrusted-code"))
    else:
        edit_yaml(mounts / "intent/instance.yaml", lambda d: d["spec"].update(ownerSubject="other-owner"))
    assert not reconciler.run()
    assert reconciler.state.read()["accepted"] == accepted
    assert len(reconciler.installer.calls) == calls


def test_private_state_and_no_errors_or_secret_hashes_in_status(guest, capsys):
    reconciler, _ = guest
    reconciler.installer.fail = "apply"
    assert not reconciler.run()
    assert reconciler.state.directory.stat().st_mode & 0o777 == 0o700
    for file in ("state.json", "status.json", "lock"):
        assert (reconciler.state.directory / file).stat().st_mode & 0o777 == 0o600
    assert "PRIVATE-CREDENTIAL" not in capsys.readouterr().out
    assert base64.b64encode(b"PRIVATE-CREDENTIAL").decode() not in canonical(read_status(reconciler))


def test_single_writer_lock(guest):
    reconciler, _ = guest
    with reconciler.state.lock():
        with pytest.raises(Busy):
            reconciler.run()
    assert reconciler.run()


def test_projection_symlink_swap_is_observed(guest):
    reconciler, mounts = guest
    directory = mounts / "credentials/saw-provider-nvidia"
    key = directory / "api_key"
    key.unlink()
    (directory / "..v1").mkdir()
    (directory / "..v2").mkdir()
    (directory / "..v1/api_key").write_bytes(b"first")
    (directory / "..v2/api_key").write_bytes(b"second")
    (directory / "..data").symlink_to("..v1")
    key.symlink_to("..data/api_key")
    assert reconciler.run()
    original = reconciler.state.read()["accepted"]["id"]
    (directory / "..next").symlink_to("..v2")
    os.replace(directory / "..next", directory / "..data")
    assert reconciler.run()
    assert reconciler.state.read()["accepted"]["id"] != original


def test_symlink_escape_rejected(guest, tmp_path):
    reconciler, mounts = guest
    foreign = tmp_path / "not-a-provider"
    foreign.write_bytes(b"foreign-secret")
    key = mounts / "credentials/saw-provider-nvidia/api_key"
    key.unlink()
    key.symlink_to(foreign)
    with pytest.raises(ValidationError, match="escapes"):
        reconciler.inputs.capture()
    assert not reconciler.run()
    assert reconciler.installer.calls == []


def test_changing_projection_detected_during_collection(guest):
    reconciler, mounts = guest
    capture = reconciler.inputs._capture
    count = 0

    def racing_capture():
        nonlocal count
        count += 1
        if count == 2:
            (mounts / "credentials/saw-provider-nvidia/api_key").write_bytes(b"different")
        return capture()

    reconciler.inputs._capture = racing_capture
    with pytest.raises(InputsChanged):
        reconciler.inputs.capture()


@pytest.mark.parametrize("payload", [b"", b"a" * 65537])
def test_empty_and_oversized_credentials_rejected(guest, payload):
    reconciler, mounts = guest
    (mounts / "credentials/saw-provider-nvidia/api_key").write_bytes(payload)
    assert not reconciler.run()
    assert reconciler.installer.calls == []


def test_missing_credentials_never_fall_back_to_host_environment(guest, monkeypatch):
    reconciler, mounts = guest
    (mounts / "credentials/saw-provider-nvidia/api_key").unlink()
    monkeypatch.setenv("NVIDIA_API_KEY", "not-authorized")
    assert not reconciler.run()
    assert reconciler.installer.calls == []


def test_profile_cannot_read_unenrolled_secret(guest):
    reconciler, _ = guest
    reconciler.inputs.settings["providerSecrets"] = {}
    assert not reconciler.run()
    assert reconciler.installer.calls == []


def test_corrupt_state_is_not_reset(guest):
    reconciler, _ = guest
    path = reconciler.state.directory / "state.json"
    path.write_text("corrupt")
    path.chmod(0o600)
    assert not reconciler.run()
    assert path.read_text() == "corrupt"
    assert reconciler.installer.calls == []


def test_state_directory_permissions_are_required(tmp_path):
    directory = tmp_path / "public"
    directory.mkdir(mode=0o755)
    with pytest.raises(ValidationError):
        State(directory)


def test_shared_data_is_not_accidentally_enabled(guest):
    reconciler, _ = guest
    snapshot = reconciler.inputs.capture()
    second = deepcopy(snapshot["workspaces"][0]["sandboxes"][0])
    second["name"] = "second"
    snapshot["workspaces"][0]["sandboxes"].append(second)
    with pytest.raises(ValidationError, match="sharing"):
        plan(None, snapshot)


def test_mount_plan_only_uses_static_enrolled_paths(guest):
    reconciler, _ = guest
    assert mount_plan(reconciler.inputs.settings) == [
        ("saw-intent", "/run/saw/intent"), ("saw-installer-bom", "/run/saw/installer"),
        ("saw-profile-0", "/run/saw/profiles/profiles"),
        ("saw-secret-0", "/run/saw/credentials/saw-provider-nvidia")]
    settings = deepcopy(reconciler.inputs.settings)
    settings["profileConfigMaps"] = ["../../etc"]
    with pytest.raises(ValidationError):
        validate_settings(settings)


@pytest.mark.parametrize("profile", [{"unexpected": "mapping"}, ["nested"], None])
def test_invalid_catalog_entries_report_validation_error(guest, profile):
    reconciler, _ = guest
    settings = deepcopy(reconciler.inputs.settings)
    settings["profileConfigMaps"] = [profile]
    with pytest.raises(ValidationError):
        validate_settings(settings)


def test_guest_bundle_is_reproducible_and_contains_no_credentials_or_controller(tmp_path):
    outputs = [tmp_path / "first.tar.gz", tmp_path / "second.tar.gz"]
    for output in outputs:
        subprocess.run([sys.executable, str(ROOT / "tools/saw/build_guest_bundle.py"),
                        "--installer-bom", str(ROOT / "examples/saw/installer-bom.yaml"), "--output", str(output)],
                       check=True, capture_output=True, text=True)
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    with tarfile.open(outputs[0]) as archive:
        files = archive.getnames()
        assert len(files) == 18
        assert "etc/systemd/system/saw-guest.service" in files
        assert "opt/saw/guest/saw_guest/reconcile.py" in files
        assert all(m.uid == 0 and m.gid == 0 and m.mtime == 0 for m in archive.getmembers())
        assert all(m.mode == 0o644 for m in archive.getmembers())
        assert "opt/saw/guest/saw_guest/release.py" in files
        assert "opt/saw/guest/saw_guest/release_exec.py" in files
        manifest = json.load(archive.extractfile("opt/saw/guest/build.json"))
        assert manifest["gatewayUnitSha256"] == hashlib.sha256(archive.extractfile("etc/systemd/system/saw-openshell-gateway.service").read()).hexdigest()
        assert not any("controller" in p or "values" in p or "api.pb" in p or "adapter" in p for p in files)
    second_attempt = subprocess.run([sys.executable, str(ROOT / "tools/saw/build_guest_bundle.py"),
                        "--installer-bom", str(ROOT / "examples/saw/installer-bom.yaml"),
                                     "--output", str(outputs[0])], capture_output=True)
    assert second_attempt.returncode != 0


def test_required_runtime_image_inputs_are_preserved():
    bom = yaml.safe_load((ROOT / "examples/saw/installer-bom.yaml").read_text())
    for component in ("cli", "gateway", "supervisor"):
        assert bom["spec"]["openshell"][component]["image"].startswith(f"quay.io/opendatahub/odh-openshell-{component}@sha256:")


def test_custom_controller_publication_path_removed():
    for path in ("charts/saw-blueprint/templates/controller.yaml", "controller/saw_controller/reconcile.py",
                 ".github/workflows/saw-controller-image.yml"):
        assert not (ROOT / path).exists()
    makefile = (ROOT / "Makefile-saw").read_text()
    assert "saw-controller" not in makefile


def test_readiness_requires_fresh_runtime_verified_convergence(guest):
    reconciler, _ = guest
    assert not ready(reconciler.state.directory)
    assert reconciler.run()
    assert ready(reconciler.state.directory)
    reconciler.status("Applying")
    assert not ready(reconciler.state.directory)
    reconciler.state.write("status.json", {"phase": "Converged", "checkedAt": "2000-01-01T00:00:00+00:00"})
    assert not ready(reconciler.state.directory)


@pytest.mark.parametrize("ok", [True, False])
def test_installer_uses_fixed_script_and_private_stdin(monkeypatch, ok):
    from saw_guest import installer
    # Use an existing root-owned executable only for trust checks; it is NOT run.
    monkeypatch.setattr(installer, "SCRIPT", Path("/usr/bin/true"))
    calls = []

    class Process:
        returncode = 0 if ok else 1

        def __init__(self, command, **kwargs):
            calls.append((command, kwargs))
            self.output = kwargs["stdout"]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def communicate(self, input, timeout):
            assert timeout == 120
            request = json.loads(input)
            assert request["revision"]["snapshot"]["credentials"] == {"private": "PRIVATE-CREDENTIAL"}
            self.output.write(json.dumps({"version": 1, "revision": "r1", "ok": ok}).encode())

    monkeypatch.setattr(installer.subprocess, "Popen", Process)
    revision = {"id": "r1", "snapshot": {"credentials": {"private": "PRIVATE-CREDENTIAL"}}}
    assert installer.BomInstaller().verify(revision) is ok
    command, kwargs = calls[0]
    assert command == ["/usr/bin/python3", "-I", "/usr/bin/true", "--guest-phase", "verify"]
    assert "PRIVATE-CREDENTIAL" not in str(command) + str(kwargs["env"])
    assert kwargs["start_new_session"] and not kwargs.get("shell")


def test_installer_timeout_kills_cli_process_group_before_retry(monkeypatch):
    from saw_guest import installer
    monkeypatch.setattr(installer, "SCRIPT", Path("/usr/bin/true"))
    events = []

    class Process:
        pid = 12345

        def __init__(self, *args, **kwargs):
            assert kwargs["start_new_session"]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            events.append("exit")

        def communicate(self, input=None, timeout=None):
            if input is not None:
                raise subprocess.TimeoutExpired("installer", timeout)
            events.append("reaped")

    monkeypatch.setattr(installer.subprocess, "Popen", Process)
    monkeypatch.setattr(installer.os, "killpg", lambda pid, sig: events.append((pid, sig)))
    with pytest.raises(InstallerFailed):
        installer.BomInstaller().apply({"id": "r1"})
    assert events == [(12345, installer.signal.SIGKILL), "reaped", "exit"]


def test_untrusted_or_missing_installer_never_runs(monkeypatch, tmp_path):
    from saw_guest import installer
    executable = tmp_path / "apply_bom.py"
    executable.write_text("not code")
    executable.chmod(0o777)
    monkeypatch.setattr(installer, "SCRIPT", executable)
    with pytest.raises(InstallerFailed):
        installer.BomInstaller().verify({"id": "r1"})


@pytest.mark.parametrize('reason,expected', [
    ('UnqualifiedGatewayUnit', 'UnqualifiedGatewayUnit'),
    ('PRIVATE-CREDENTIAL', 'InstallerFailed'), ('AlphabeticCredential', 'InstallerFailed'),
    ('UnsafeGatewayState\nsecret', 'InstallerFailed'), (None, 'InstallerFailed'),
    ({'secret': 'PRIVATE'}, 'InstallerFailed'), (['PRIVATE'], 'InstallerFailed'),
])
def test_safe_failure_reason_reaches_status_and_logs(guest, caplog, reason, expected):
    reconciler, _ = guest
    def fail(_revision):
        raise InstallerFailed(reason, 'validate')
    reconciler.installer.preflight = fail
    assert not reconciler.run()
    result = read_status(reconciler)
    assert result['reason'] == expected
    assert result['operation'] == 'validate'
    assert 'PRIVATE' not in json.dumps(result) + caplog.text
    assert 'AlphabeticCredential' not in json.dumps(result) + caplog.text
    assert 'secret' not in json.dumps(result) + caplog.text
    assert reconciler.state.read()['pending'] is None


def test_all_installer_reason_literals_are_registered():
    import ast
    from saw_guest.errors import REASONS
    tree = ast.parse((ROOT / 'installer/apply_bom.py').read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'InstallerError':
            assert len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
            assert node.args[0].value in REASONS


@pytest.mark.parametrize('reason', ['UnqualifiedGatewayUnit', 'PRIVATE-CREDENTIAL', {'secret': 'PRIVATE'}])
def test_runner_preserves_only_allowlisted_failed_reply(monkeypatch, reason):
    from saw_guest import installer
    monkeypatch.setattr(installer, 'SCRIPT', Path('/usr/bin/true'))
    class Process:
        returncode = 1
        def __init__(self, _command, **kwargs):
            self.output = kwargs['stdout']
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def communicate(self, input, timeout):
            self.output.write(json.dumps({'version': 1, 'revision': 'r1', 'ok': False, 'reason': reason}).encode())
    monkeypatch.setattr(installer.subprocess, 'Popen', Process)
    with pytest.raises(InstallerFailed) as failure:
        installer.BomInstaller().preflight({'id': 'r1'})
    assert failure.value.reason == ('UnqualifiedGatewayUnit' if reason == 'UnqualifiedGatewayUnit' else 'InstallerFailed')
    assert failure.value.phase == 'validate'


def test_cli_check_inputs_is_not_apply_and_leaks_no_credentials(guest, tmp_path):
    reconciler, mounts = guest
    settings = tmp_path / "guest.json"
    settings.write_text(json.dumps(reconciler.inputs.settings))
    result = subprocess.run([sys.executable, "-m", "saw_guest", "--settings", str(settings),
                             "--inputs", str(mounts), "--check-inputs"],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "NOT been verified" in result.stdout
    assert "PRIVATE" not in result.stdout + result.stderr
    assert reconciler.state.read()["accepted"] is None
