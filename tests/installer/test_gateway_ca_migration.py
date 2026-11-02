"""CA rotation must archive the workload volume before deleting a sandbox."""
from pathlib import Path

import pytest


@pytest.fixture(params=["proxy", "direct"])
def credential_mode(request):
    return request.param


@pytest.fixture
def legacy(ab, tmp_path, fake_env, config, monkeypatch):
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
    state["sandboxes"]["default/tools"]["files"] = {
        "notes.md": "preserve me", "proj/proof.txt": "proof", ".saw/ignored": "installer-owned"}
    state["sandboxes"]["default/tools"]["execBroken"] = True
    state["labels"]["sandbox/default/tools"] = [
        label for label in state["labels"]["sandbox/default/tools"]
        if not label.startswith("saw.redhat.com/gateway-ca=")]
    fake_env.set_openshell_state(state)
    return applier, profile, ws, sb


@pytest.mark.parametrize("label,phase", [(None, "Ready"), ("old-ca", "Ready"), ("old-ca", "Error")])
def test_ca_rotation_preserves_files_without_supervisor_exec(ab, legacy, fake_env, label, phase):
    applier, profile, ws, sb = legacy
    state = fake_env.openshell_state()
    if label:
        state["labels"]["sandbox/default/tools"].append(f"saw.redhat.com/gateway-ca={label}")
    state["sandboxes"]["default/tools"]["phase"] = phase
    fake_env.set_openshell_state(state)
    applier.apply([profile])
    assert fake_env.openshell_state()["sandboxes"]["default/tools"]["files"] == {
        "notes.md": "preserve me", "proj/proof.txt": "proof"}
    calls = fake_env.openshell_calls()
    assert not any(c[:2] == ["sandbox", "download"] for c in calls)
    assert sum(c[:2] == ["sandbox", "create"] for c in calls) == 2
    assert sum(c[:2] == ["sandbox", "delete"] for c in calls) == 1
    assert sum(c[0] == "unshare" for c in fake_env.podman_calls()) == 1
    assert applier.migrations == {}
    assert not list(applier.archive_dir().glob("*.tar.gz"))


@pytest.mark.parametrize("failure", ["unshare", "missing-volume"])
def test_archive_failure_never_deletes_the_original(ab, legacy, fake_env, failure):
    applier, profile, _, _ = legacy
    if failure == "unshare":
        (fake_env.state / "unshare-fails").touch()
    else:
        state = fake_env.openshell_state()
        state["sandboxes"]["default/tools"]["noSandboxVolume"] = True
        fake_env.set_openshell_state(state)
    with pytest.raises(ab.InstallerError, match="nothing was deleted"):
        applier.apply([profile])
    assert not any(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls())
    assert not applier.migrations
    assert fake_env.openshell_state()["sandboxes"]["default/tools"]["files"]["notes.md"] == "preserve me"


def test_interrupted_migration_refreshes_from_the_volume(ab, legacy, fake_env, monkeypatch):
    applier, profile, _, _ = legacy
    def interrupted(*args, **kwargs):
        raise ab.InstallerError("interrupted before delete")
    monkeypatch.setattr(applier, "delete_sandbox_and_wait", interrupted)
    with pytest.raises(ab.InstallerError, match="interrupted"):
        applier.apply([profile])
    record = applier.migrations["default/tools"]
    assert record["via"] == "volume" and Path(record["archive"]).is_file()
    original = record["archive"]
    state = fake_env.openshell_state()
    state["sandboxes"]["default/tools"]["files"]["notes.md"] = "latest edits"
    fake_env.set_openshell_state(state)
    applier = ab.ProfileApplier(ab.Shell(), applier.cfg, {})
    applier.apply([profile])
    assert fake_env.openshell_state()["sandboxes"]["default/tools"]["files"]["notes.md"] == "latest edits"
    assert sum(c[0] == "unshare" for c in fake_env.podman_calls()) == 2
    assert not Path(original).exists()
    assert not applier.migrations


def test_failed_refresh_keeps_the_last_verified_archive(ab, legacy, fake_env, monkeypatch):
    applier, profile, _, _ = legacy
    monkeypatch.setattr(applier, "delete_sandbox_and_wait", lambda *args: (_ for _ in ()).throw(
        ab.InstallerError("interrupted")))
    with pytest.raises(ab.InstallerError, match="interrupted"):
        applier.apply([profile])
    original = Path(applier.migrations["default/tools"]["archive"])
    before = original.read_bytes()
    (fake_env.state / "unshare-fails").touch()
    applier = ab.ProfileApplier(ab.Shell(), applier.cfg, {})
    with pytest.raises(ab.InstallerError, match="nothing was deleted"):
        applier.apply([profile])
    assert original.read_bytes() == before
    assert not any(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls())


def test_ca_rotation_dry_run_never_archives_or_deletes(ab, legacy, fake_env):
    applier, profile, _, _ = legacy
    before = fake_env.openshell_state()
    calls = len(fake_env.openshell_calls())
    applier.sh.dry_run = True
    applier.apply([profile])
    assert fake_env.openshell_state() == before
    assert not any(c[:2] == ["sandbox", "delete"] for c in fake_env.openshell_calls()[calls:])
    assert not any(c[0] == "unshare" for c in fake_env.podman_calls())
