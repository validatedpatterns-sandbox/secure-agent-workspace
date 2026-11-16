"""A failed workload must be archived even when its gateway CA is current."""
from pathlib import Path

import pytest


@pytest.fixture
def broken_sandbox(ab, tmp_path, fake_env, config, monkeypatch):
    monkeypatch.setattr(ab.ProfileApplier, "POLL_SECONDS", 0)
    monkeypatch.setattr(ab.ProfileApplier, "BROKEN_GRACE_SECONDS", 0)
    ws = ab.Workspace(name="default")
    sb = ab.Sandbox(name="tools", type="generic")
    ws.sandboxes = [sb]
    profile = ab.Profile(name="test", workspaces=[ws])
    config = {**config, "prune": {"ledgerPath": str(tmp_path / "ledger.json")}}
    applier = ab.ProfileApplier(ab.Shell(), config, {})
    applier.apply([profile])
    state = fake_env.openshell_state()
    state["sandboxes"]["default/tools"].update(
        phase="Error", execBroken=True, files={"notes.md": "preserve me"},
        openclawConfig={"gateway.auth.password": "original-password"})
    fake_env.set_openshell_state(state)
    assert applier.sandbox_gateway_ca_ok(ws, sb)
    return applier, profile, ws, sb


@pytest.mark.parametrize("phase", ["Error", "Completed"])
def test_broken_sandbox_keeps_files_and_password(ab, broken_sandbox, fake_env, phase):
    applier, profile, _, _ = broken_sandbox
    state = fake_env.openshell_state()
    state["sandboxes"]["default/tools"]["phase"] = phase
    fake_env.set_openshell_state(state)
    applier.apply([profile])
    restored = fake_env.openshell_state()["sandboxes"]["default/tools"]
    assert restored["files"]["notes.md"] == "preserve me"
    assert restored["openclawConfig"]["gateway.auth.password"] == "original-password"
    assert sum(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls()) == 1
    assert sum(c[0] == "unshare" for c in fake_env.podman_calls()) == 1
    assert applier.migrations == {}
    assert not list(applier.archive_dir().glob("*.tar.gz"))


@pytest.mark.parametrize("failure", ["unshare", "missing-volume"])
def test_broken_sandbox_archive_failure_deletes_nothing(ab, broken_sandbox, fake_env, failure):
    applier, profile, _, _ = broken_sandbox
    if failure == "unshare":
        (fake_env.state / "unshare-fails").touch()
    else:
        state = fake_env.openshell_state()
        state["sandboxes"]["default/tools"]["noSandboxVolume"] = True
        fake_env.set_openshell_state(state)
    with pytest.raises(ab.InstallerError, match="nothing was deleted"):
        applier.apply([profile])
    assert not any(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls())
    original = fake_env.openshell_state()["sandboxes"]["default/tools"]
    assert original["files"]["notes.md"] == "preserve me"
    assert original["openclawConfig"]["gateway.auth.password"] == "original-password"
    assert not applier.migrations


def test_broken_sandbox_interrupted_recreation_resumes(ab, broken_sandbox, fake_env, monkeypatch):
    applier, profile, _, _ = broken_sandbox

    def interrupted(*args, **kwargs):
        raise ab.InstallerError("interrupted before delete")

    monkeypatch.setattr(applier, "delete_sandbox_and_wait", interrupted)
    with pytest.raises(ab.InstallerError, match="interrupted"):
        applier.apply([profile])
    archive = Path(applier.migrations["default/tools"]["archive"])
    assert archive.is_file()
    assert not any(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls())
    retry = ab.ProfileApplier(ab.Shell(), applier.cfg, {})
    retry.apply([profile])
    restored = fake_env.openshell_state()["sandboxes"]["default/tools"]
    assert restored["files"]["notes.md"] == "preserve me"
    assert restored["openclawConfig"]["gateway.auth.password"] == "original-password"
    assert not retry.migrations
    assert not archive.exists()


@pytest.mark.parametrize("failure", ["missing", "corrupt"])
def test_broken_sandbox_invalid_pending_archive_deletes_nothing(
        ab, broken_sandbox, fake_env, monkeypatch, failure):
    applier, profile, _, _ = broken_sandbox

    def interrupted(*args, **kwargs):
        raise ab.InstallerError("interrupted before delete")

    monkeypatch.setattr(applier, "delete_sandbox_and_wait", interrupted)
    with pytest.raises(ab.InstallerError, match="interrupted"):
        applier.apply([profile])
    archive = Path(applier.migrations["default/tools"]["archive"])
    if failure == "missing":
        archive.unlink()
    else:
        archive.write_text("damaged archive")
    retry = ab.ProfileApplier(ab.Shell(), applier.cfg, {})
    with pytest.raises(ab.InstallerError, match="nothing was deleted"):
        retry.apply([profile])
    assert not any(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls())
    assert fake_env.openshell_state()["sandboxes"]["default/tools"]["files"]["notes.md"] == "preserve me"


def test_broken_sandbox_unreadable_labels_changes_nothing(ab, broken_sandbox, fake_env, monkeypatch):
    applier, profile, _, _ = broken_sandbox
    before = fake_env.openshell_state()
    monkeypatch.setattr(applier, "sandbox_labels", lambda *args: None)
    with pytest.raises(ab.InstallerError, match="labels cannot be read"):
        applier.apply([profile])
    assert fake_env.openshell_state() == before
    assert not any(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls())


def test_broken_sandbox_dry_run_changes_nothing(broken_sandbox, fake_env, monkeypatch):
    applier, _, ws, sb = broken_sandbox
    before = fake_env.openshell_state()
    calls = len(fake_env.openshell_calls())
    states = iter(["broken", "broken", "missing"])
    monkeypatch.setattr(applier, "sandbox_state", lambda *args: next(states))
    applier.sh.dry_run = True
    applier.create_sandbox(ws, sb)
    assert fake_env.openshell_state() == before
    assert not any(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls()[calls:])
    assert not any(c[0] == "unshare" for c in fake_env.podman_calls())


def test_broken_sandbox_logs_workload_exit_and_oom(broken_sandbox, fake_env, capsys):
    applier, profile, _, _ = broken_sandbox
    state = fake_env.openshell_state()
    state["sandboxes"]["default/tools"]["workloadState"] = {
        "status": "exited", "exit": 137, "oom": True, "error": "killed"}
    fake_env.set_openshell_state(state)
    capsys.readouterr()
    applier.apply([profile])
    output = capsys.readouterr().out
    assert "Sandbox 'tools': Phase: Error" in output
    assert "exited exit=137 oom=true killed" in output


def test_broken_sandbox_diagnostics_are_bounded_and_masked(ab, broken_sandbox, monkeypatch, capsys):
    applier, _, ws, sb = broken_sandbox
    applier.sh.add_secret("diagnostic-secret")
    monkeypatch.setattr(applier, "cli", lambda *args, **kwargs: ab.Result(
        0, out="\x1b[31mPhase: Error\x1b[0m\nName: tools\n" +
        "\n".join(f"Message: diagnostic-secret {i}" for i in range(15))))
    monkeypatch.setattr(applier, "workload_container", lambda *args: None)
    capsys.readouterr()
    applier.log_broken_sandbox(ws, sb)
    output = capsys.readouterr().out
    assert output.count("Sandbox 'tools':") == 10
    assert "diagnostic-secret" not in output
    assert "Name: tools" not in output
    assert "\x1b" not in output
