"""The cases the review of PR #135 reproduced, each now covered.

1. An existing sandbox is held to the same env rules as a new one
   (validation runs in preflight, before any gateway change).
2. A changed (or removed) env variable recreates the sandbox, carrying its
   /sandbox files over, so every process sees exactly the profile's env.
3. A custom, profile-backed provider type (vllm-prod) drives inference
   through the sandbox's typed `inference:` block (protocol, not type).
4. An empty default is one the form and the installer agree on: the field
   is optional, and absent means the default.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from conftest import ROOT

GH_PROFILE = ("id: github\ncredentials:\n  - name: api_token\n"
              "    env_vars: [GITHUB_TOKEN, GH_TOKEN]\n")
VLLM_PROFILE = ("id: vllm-prod\ncredentials:\n  - name: api_key\n"
                "    env_vars: [VLLM_API_KEY]\nendpoints:\n"
                "  - host: vllm.models.example\n    port: 443\n")


def _secret(dirpath, name, **keys):
    base = dirpath / name
    base.mkdir(parents=True, exist_ok=True)
    for key, value in keys.items():
        (base / key).write_text(value)


def _profiles(ab, sandbox, *providers):
    workspace = ab.Workspace(name="default", providers=list(providers), sandboxes=[sandbox])
    return [ab.Profile(name="test", workspaces=[workspace])]


# --- 1. preflight ------------------------------------------------------------------

def test_an_existing_sandbox_is_held_to_the_env_rules_too(ab, fake_env, config, tmp_path):
    github = ab.Provider(name="gh", type="github", credential_secret="gh",
                         credential_secret_key="token")
    sandbox = ab.Sandbox(name="tools", type="generic", providers=["gh"])
    profiles = _profiles(ab, sandbox, github)
    _secret(tmp_path, "gh", token="ghp-x")
    creds = ab.resolve_credentials(profiles, tmp_path)
    docs = {"github": GH_PROFILE}
    ab.ProfileApplier(ab.Shell(), config, creds, provider_profile_docs=docs).apply(profiles)
    assert "default/tools" in fake_env.openshell_state()["sandboxes"]

    # The sandbox exists; a later apply adds GH_TOKEN to its env.
    sandbox.env = {"GH_TOKEN": {"value": "plain"}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    before = len(fake_env.openshell_calls())
    with pytest.raises(ab.InstallerError, match="credential variable of provider 'gh'"):
        ab.ProfileApplier(ab.Shell(), config, creds, provider_profile_docs=docs).apply(profiles)
    # Refused before anything touched the gateway.
    assert fake_env.openshell_calls()[before:] == []


def test_a_named_credential_must_exist_in_the_profile(ab, config, tmp_path):
    github = ab.Provider(name="gh", type="github", credential_secret="gh",
                         credentials_spec={"token": {"secretKey": "token"}})   # profile: api_token
    profiles = _profiles(ab, ab.Sandbox(name="tools", type="generic", providers=["gh"]), github)
    _secret(tmp_path, "gh", token="ghp-x")
    creds = ab.resolve_credentials(profiles, tmp_path)
    with pytest.raises(ab.InstallerError, match="credential 'token' is not one the 'github' "
                                                "profile declares \\(api_token\\)"):
        ab.ProfileApplier(ab.Shell(), config, creds,
                          provider_profile_docs={"github": GH_PROFILE}).apply(profiles)


# --- 2. env updates recreate the sandbox, keeping /sandbox -----------------------------

def _env_sandbox(ab, env):
    provider = ab.Provider(name="inference", type="openai", model="gpt-4o",
                           credential_secret="inference", credential_secret_key="api_key")
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["inference"], env=env)
    return provider, sandbox, _profiles(ab, sandbox, provider)


def _apply(ab, config, tmp_path, profiles):
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)


def test_a_changed_env_recreates_the_sandbox_with_its_files(ab, fake_env, config, tmp_path):
    _, sandbox, profiles = _env_sandbox(ab, {"HF_HUB_OFFLINE": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    state = fake_env.openshell_state()
    first = state["sandboxes"]["default/chat"]
    assert first["env"] == ["HF_HUB_OFFLINE=1"]
    label = next(l for l in state["labels"]["sandbox/default/chat"] if l.startswith("saw.redhat.com/env="))
    # The user's files in /sandbox.
    first["files"] = {"notes.md": "keep me"}
    fake_env.set_openshell_state(state)

    sandbox.env = {"HF_HUB_OFFLINE": {"value": "0"}}
    _apply(ab, config, tmp_path, profiles)
    state = fake_env.openshell_state()
    second = state["sandboxes"]["default/chat"]
    assert second["env"] == ["HF_HUB_OFFLINE=0"]                       # every process sees it
    assert second["files"] == {"notes.md": "keep me"}                 # carried over
    assert "archives" not in second or not second["archives"]         # cleaned up
    new_label = next(l for l in state["labels"]["sandbox/default/chat"]
                     if l.startswith("saw.redhat.com/env="))
    assert new_label != label
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()]
    assert ops.count("sandbox create") == 2 and ops.count("sandbox delete") == 1
    assert "sandbox download" in ops and "sandbox upload" in ops


def test_removing_a_variable_recreates_too(ab, fake_env, config, tmp_path):
    _, sandbox, profiles = _env_sandbox(ab, {"HF_HUB_OFFLINE": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    sandbox.env = {}
    _apply(ab, config, tmp_path, profiles)
    second = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert "env" not in second                                       # no stale value left
    assert [" ".join(c[:2]) for c in fake_env.openshell_calls()].count("sandbox create") == 2


def test_an_unchanged_env_leaves_the_sandbox_alone(ab, fake_env, config, tmp_path):
    _, _, profiles = _env_sandbox(ab, {"HF_HUB_OFFLINE": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    _apply(ab, config, tmp_path, profiles)
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()]
    assert ops.count("sandbox create") == 1 and "sandbox delete" not in ops


def test_a_failed_backup_never_deletes_the_sandbox(ab, fake_env, config, tmp_path):
    """Review (bc750ad6, P1): the apply fails and the old sandbox, its files
    and its env stay exactly as they were."""
    _, sandbox, profiles = _env_sandbox(ab, {"A": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"]["files"] = {"notes.md": "keep me"}
    fake_env.set_openshell_state(state)
    (fake_env.state / "preserve-fail").write_text("")

    sandbox.env = {"A": {"value": "2"}}
    before = len(fake_env.openshell_calls())
    with pytest.raises(ab.InstallerError, match="could not archive /sandbox of 'chat'.*left as it is"):
        _apply(ab, config, tmp_path, profiles)
    after = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert after["env"] == ["A=1"] and after["files"] == {"notes.md": "keep me"}
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()[before:]]
    assert "sandbox delete" not in ops and "sandbox create" not in ops


def test_a_download_mismatch_never_deletes_the_sandbox(ab, fake_env, config, tmp_path, monkeypatch):
    _, sandbox, profiles = _env_sandbox(ab, {"A": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    monkeypatch.setattr(ab, "sha256_file", lambda path: "0" * 64)     # a corrupt download
    sandbox.env = {"A": {"value": "2"}}
    with pytest.raises(ab.InstallerError, match="does not match its checksum"):
        _apply(ab, config, tmp_path, profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/chat"]["env"] == ["A=1"]


def test_a_failed_restore_fails_the_apply_and_is_retried(ab, fake_env, config, tmp_path):
    """Review (bc750ad6, P1): a restore failure is an error, the pending
    restore is recorded on the VM, and the next apply finishes it; the
    migration is complete only once the restored files verify."""
    _, sandbox, profiles = _env_sandbox(ab, {"A": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    ledger = tmp_path / "state" / "managed.json"
    cfg = {**config, "prune": {"mode": "off", "ledgerPath": str(ledger)}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"]["files"] = {"notes.md": "keep me"}
    fake_env.set_openshell_state(state)

    (fake_env.state / "restore-fail").write_text("")
    sandbox.env = {"A": {"value": "2"}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    with pytest.raises(ab.InstallerError, match="could not restore the files of 'chat'.*retried"):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    # The new sandbox exists with the new env, but the files are not there
    # yet, and the pending restore is persisted with its archive.
    new = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert new["env"] == ["A=2"] and "notes.md" not in new.get("files", {})
    pending = json.loads(ledger.with_name("sandbox-migrations.json").read_text())
    assert set(pending) == {"default/chat"}
    assert Path(pending["default/chat"]["archive"]).is_file()

    (fake_env.state / "restore-fail").unlink()
    before = len(fake_env.openshell_calls())
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)       # same env: no recreation
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()[before:]]
    assert "sandbox delete" not in ops and "sandbox create" not in ops
    assert "sandbox upload" in ops
    final = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert final["files"] == {"notes.md": "keep me"} and final["env"] == ["A=2"]
    assert json.loads(ledger.with_name("sandbox-migrations.json").read_text()) == {}
    assert not Path(pending["default/chat"]["archive"]).exists()


def test_an_interrupted_recreation_is_finished_on_the_next_apply(ab, fake_env, config, tmp_path):
    """Killed between delete and create: the record and archive survive, the
    next apply creates the sandbox and restores the files."""
    _, sandbox, profiles = _env_sandbox(ab, {"A": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    ledger = tmp_path / "state" / "managed.json"
    cfg = {**config, "prune": {"mode": "off", "ledgerPath": str(ledger)}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    applier = ab.ProfileApplier(ab.Shell(), cfg, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"]["files"] = {"notes.md": "keep me"}
    fake_env.set_openshell_state(state)
    sandbox.env = {"A": {"value": "2"}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    ws = profiles[0].workspaces[0]
    applier = ab.ProfileApplier(ab.Shell(), cfg, creds)
    applier.begin_migration(ws, sandbox, applier.sandbox_labels(ws, sandbox))    # ...then it dies
    assert "default/chat" not in fake_env.openshell_state()["sandboxes"]

    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    final = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert final["files"] == {"notes.md": "keep me"} and final["env"] == ["A=2"]
    assert json.loads(ledger.with_name("sandbox-migrations.json").read_text()) == {}


def test_the_backup_excludes_only_the_installers_mounts(ab, tmp_path):
    """Review (52df5b54, P1): a bare --exclude=harness also drops a user's
    project/harness/. Run the real archive command against a /sandbox tree.
    The sandbox images carry GNU tar (--anchored); so must this test."""
    import subprocess
    tar = subprocess.run(["tar", "--version"], capture_output=True, text=True)
    if "GNU tar" not in tar.stdout:
        pytest.skip("needs GNU tar (--anchored); the sandbox images have it")
    nvidia = ab.Provider(name="nvidia", type="nvidia", credential_secret="inference")
    sb = ab.Sandbox(name="notebook", type="openclaw", providers=["nvidia"],
                    harness_ref={"name": "ds-default"})
    ws = ab.Workspace(name="default", providers=[nvidia], sandboxes=[sb])
    applier = ab.ProfileApplier(ab.Shell(), {"mtlsGateway": "g"}, {})
    # Capture the exact `sh -c` script the installer runs in the sandbox.
    captured = []

    class Captured(Exception):
        pass

    def capture(*args, **kwargs):
        captured.append(args[-1])
        raise Captured()
    applier.cli = capture
    with pytest.raises(Captured):
        applier.preserve_sandbox(ws, sb)
    script = captured[0]
    assert "--anchored" in script and "--exclude=harness" not in script

    root = tmp_path / "sandbox"
    for rel in ("harness/bundle.yaml", ".saw/trusted/gate.mjs", ".saw/audit/log.jsonl",
                "project/harness/test.py", "project/.saw/notes.md", "notes.md"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(rel)
    archive = tmp_path / "preserve.tar"
    run = script.replace("cd /sandbox", f"cd {root}").replace(
        "/tmp/saw-sandbox-preserve.tar", str(archive))
    subprocess.run(["sh", "-c", run], check=True, capture_output=True)
    names = subprocess.run(["tar", "-tf", str(archive)], check=True, capture_output=True,
                           text=True).stdout.split()
    kept = {n.lstrip("./") for n in names if not n.endswith("/")}
    assert "project/harness/test.py" in kept and "project/.saw/notes.md" in kept
    assert "notes.md" in kept
    assert not any(n.startswith(("harness/", ".saw/trusted", ".saw/audit")) for n in kept)


def test_a_surviving_original_is_never_overwritten_by_its_old_snapshot(
        ab, fake_env, config, tmp_path, monkeypatch):
    monkeypatch.setattr(ab.ProfileApplier, "POLL_SECONDS", 0)       # the denied delete's wait
    """Review (52df5b54, P1): the delete failed (or the installer died before
    it); the original keeps running and gains new work. The next apply must
    not restore the stale archive over it: it archives again and retries."""
    _, sandbox, profiles = _env_sandbox(ab, {"A": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    ledger = tmp_path / "state" / "managed.json"
    cfg = {**config, "prune": {"mode": "off", "ledgerPath": str(ledger)}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"]["files"] = {"notes.md": "old"}
    fake_env.set_openshell_state(state)

    # The recreation gets as far as recording the pending restore; the delete
    # never happens (simulated: deny it).
    sandbox.env = {"A": {"value": "2"}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    fake_env.deny("sandbox delete")
    applier = ab.ProfileApplier(ab.Shell(), cfg, creds)
    with pytest.raises(ab.InstallerError):
        applier.apply(profiles)
    pending = json.loads(ledger.with_name("sandbox-migrations.json").read_text())
    assert pending["default/chat"]["fromInstance"] and pending["default/chat"]["toInstance"]
    assert pending["default/chat"]["env"] == {"A": "2"}
    original = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert original["env"] == ["A=1"]                              # still the original

    # The user keeps working in it.
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"]["files"] = {"notes.md": "NEW work"}
    fake_env.set_openshell_state(state)

    fake_env.deny()                                                # delete allowed again
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    final = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert final["env"] == ["A=2"]
    assert final["files"] == {"notes.md": "NEW work"}             # the fresh archive, not the stale one
    assert json.loads(ledger.with_name("sandbox-migrations.json").read_text()) == {}


def test_removing_timeout_seconds_unsets_it(ab, fake_env, config, tmp_path):
    """Review (52df5b54, P2): OpenClaw's onboarding keeps an existing
    provider's settings, so a removed timeout must be unset explicitly."""
    vllm = ab.Provider(name="llm", type="openai", credential_secret="inference",
                       credential_secret_key="api_key")
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["llm"], inference={
        "providerRef": "llm", "protocol": "openai", "baseUrl": "https://llm.example/v1",
        "model": "m", "timeoutSeconds": "300"})
    profiles = _profiles(ab, sandbox, vllm)
    _secret(tmp_path, "inference", api_key="k")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    cfg = fake_env.openshell_state()["sandboxes"]["default/chat"]["openclawConfig"]
    assert cfg["models.providers.openai.timeoutSeconds"] == 300

    del sandbox.inference["timeoutSeconds"]
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    cfg = fake_env.openshell_state()["sandboxes"]["default/chat"]["openclawConfig"]
    assert "models.providers.openai.timeoutSeconds" not in cfg


def _ledger_cfg(config, tmp_path):
    return {**config, "prune": {"mode": "off", "ledgerPath": str(tmp_path / "state" / "managed.json")}}


def _migrations(tmp_path):
    return json.loads((tmp_path / "state" / "sandbox-migrations.json").read_text())


def _interrupted_recreation(ab, fake_env, config, tmp_path, new_env, native_id=""):
    """Create with A=1 and a user file, start a recreation to `new_env`, and
    stop right after the delete (before the replacement is created)."""
    _, sandbox, profiles = _env_sandbox(ab, {"A": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    cfg = _ledger_cfg(config, tmp_path)
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"]["files"] = {"notes.md": "keep me"}
    if native_id:
        state["sandboxes"]["default/chat"]["nativeId"] = native_id
    fake_env.set_openshell_state(state)
    sandbox.env = new_env
    creds = ab.resolve_credentials(profiles, tmp_path)
    applier = ab.ProfileApplier(ab.Shell(), cfg, creds)
    ws = profiles[0].workspaces[0]
    applier.begin_migration(ws, sandbox, applier.sandbox_labels(ws, sandbox))
    assert "default/chat" not in fake_env.openshell_state()["sandboxes"]
    archive = Path(_migrations(tmp_path)["default/chat"]["archive"])
    assert archive.is_file()
    return sandbox, profiles, cfg, archive


def test_rolling_the_env_back_during_recovery_keeps_the_files(ab, fake_env, config, tmp_path):
    """Review (888585cb, P1): interrupted after the delete, the profile is
    reverted to the original env. The empty replacement must not be taken
    for the original (that deleted the only backup); the files come back."""
    sandbox, profiles, cfg, archive = _interrupted_recreation(
        ab, fake_env, config, tmp_path, {"A": {"value": "2"}})
    sandbox.env = {"A": {"value": "1"}}                              # rolled back
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    # One apply: the replacement is created with the env the profile wants
    # now (A=1) and the files restored into it -- no intermediate sandbox.
    final = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert final["files"] == {"notes.md": "keep me"} and final["env"] == ["A=1"]
    assert _migrations(tmp_path) == {} and not archive.exists()
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()]
    assert ops.count("sandbox create") == 2           # the original, then the replacement


def test_changing_the_env_again_during_recovery_keeps_the_files(ab, fake_env, config, tmp_path):
    """Review (888585cb, P1): interrupted after the delete, the profile moves
    on to a third value. Files must not be left unrestored."""
    sandbox, profiles, cfg, _ = _interrupted_recreation(
        ab, fake_env, config, tmp_path, {"A": {"value": "2"}})
    sandbox.env = {"A": {"value": "3"}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    # Review (79411bca, P2): one apply ends with the files AND the current
    # env -- the installer service only restarts on failure, so a
    # successful apply must not leave settings for a "next" one.
    final = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert final["files"] == {"notes.md": "keep me"} and final["env"] == ["A=3"]
    assert _migrations(tmp_path) == {}


def test_the_archive_outlives_every_failed_restore(ab, fake_env, config, tmp_path):
    """The archive is deleted in exactly one place: after a verified restore."""
    sandbox, profiles, cfg, archive = _interrupted_recreation(
        ab, fake_env, config, tmp_path, {"A": {"value": "2"}})
    (fake_env.state / "restore-fail").write_text("")
    creds = ab.resolve_credentials(profiles, tmp_path)
    for _ in range(2):
        with pytest.raises(ab.InstallerError, match="retried"):
            ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
        assert archive.is_file() and "default/chat" in _migrations(tmp_path)
    (fake_env.state / "restore-fail").unlink()
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/chat"]["files"] == {"notes.md": "keep me"}
    assert not archive.exists()


def test_a_sandbox_recovering_from_error_still_gets_its_restore(ab, fake_env, config, tmp_path,
                                                                 monkeypatch):
    """Review (888585cb, P2): the replacement exists but reports Error for a
    while (found live after a VM restart); once it recovers the pending
    restore must still happen, not be skipped by the early 'already exists'."""
    monkeypatch.setattr(ab.ProfileApplier, "POLL_SECONDS", 0)
    sandbox, profiles, cfg, archive = _interrupted_recreation(
        ab, fake_env, config, tmp_path, {"A": {"value": "2"}})
    (fake_env.state / "restore-fail").write_text("")               # replacement created, restore fails
    creds = ab.resolve_credentials(profiles, tmp_path)
    with pytest.raises(ab.InstallerError):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    (fake_env.state / "restore-fail").unlink()
    state = fake_env.openshell_state()
    # The replacement starts the next apply in Error and recovers after two gets.
    state["sandboxes"]["default/chat"].update(phase="Error", after=[2, "Ready"])
    fake_env.set_openshell_state(state)
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    final = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert final["files"] == {"notes.md": "keep me"} and final["env"] == ["A=2"]
    assert _migrations(tmp_path) == {} and not archive.exists()


def test_an_unresolvable_identity_fails_the_apply(ab, fake_env, config, tmp_path):
    """Neither the original nor the replacement: refuse to guess, and never
    report success while a restore is pending."""
    sandbox, profiles, cfg, archive = _interrupted_recreation(
        ab, fake_env, config, tmp_path, {"A": {"value": "2"}})
    # Someone else created a sandbox of that name in the meantime.
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"] = {"image": None, "providers": ["inference"],
                                          "phase": "Ready", "env": ["A=9"], "files": {"theirs": "x"}}
    state["labels"]["sandbox/default/chat"] = ["saw.redhat.com/managed=true",
                                               "saw.redhat.com/env=zzzz", "saw.redhat.com/instance=other"]
    fake_env.set_openshell_state(state)
    creds = ab.resolve_credentials(profiles, tmp_path)
    for _ in range(2):
        with pytest.raises(ab.InstallerError, match="neither the sandbox it was taken from nor"):
            ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    other = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert other["files"] == {"theirs": "x"} and other["env"] == ["A=9"]   # untouched
    assert archive.is_file() and "default/chat" in _migrations(tmp_path)


@pytest.mark.parametrize("seen,recorded,same", [
    # instance agrees / disagrees: decisive
    ({"instance": "i1", "native": "", "env": "e"}, {"instance": "i1", "native": "", "env": "x"}, True),
    ({"instance": "i1", "native": "", "env": "e"}, {"instance": "i2", "native": "", "env": "e"}, False),
    # one side labelled, the other not: different creates, whatever the env
    ({"instance": "", "native": "", "env": "e"}, {"instance": "i1", "native": "", "env": "e"}, False),
    ({"instance": "i1", "native": "", "env": "e"}, {"instance": "", "native": "", "env": "e"}, False),
    # native id known on both sides: decisive, and a mismatch vetoes the env fallback
    ({"instance": "", "native": "n1", "env": "e"}, {"instance": "", "native": "n1", "env": "x"}, True),
    ({"instance": "", "native": "n1", "env": "e"}, {"instance": "", "native": "n2", "env": "e"}, False),
    # Review (f4488eac, P1): matching instance labels must not hide a
    # conflicting native id -- every known-both-sides signal is compared.
    ({"instance": "i1", "native": "n1", "env": "e"}, {"instance": "i1", "native": "n2", "env": "e"}, False),
    ({"instance": "i1", "native": "n1", "env": "e"}, {"instance": "i1", "native": "n1", "env": "x"}, True),
    # No strong signal on either side: never a match -- an env value never
    # establishes identity.
    ({"instance": "", "native": "", "env": "e"}, {"instance": "", "native": "", "env": "e"}, False),
    ({"instance": "", "native": "", "env": ""}, {"instance": "", "native": "", "env": "none"}, False),
    # native known on one side only, nothing else: no evidence, no match
    ({"instance": "", "native": "n1", "env": "e"}, {"instance": "", "native": "", "env": "e"}, False),
])
def test_identity_decision_table(ab, seen, recorded, same):
    assert ab.same_sandbox(seen, recorded) is same


def test_a_native_id_mismatch_vetoes_the_env_fallback(ab, fake_env, config, tmp_path):
    """Review (2b9dabec, P1): an unlabelled sandbox with the original's env
    but a different gateway id is NOT the original. Nothing is archived,
    deleted or replaced; the apply fails."""
    sandbox, profiles, cfg, archive = _interrupted_recreation(
        ab, fake_env, config, tmp_path, {"A": {"value": "2"}}, native_id="orig-123")
    before = archive.read_bytes()
    # An unrelated, unlabelled sandbox with the original's env appears.
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"] = {"image": None, "providers": ["inference"], "phase": "Ready",
                                          "env": ["A=1"], "files": {"theirs": "x"}, "nativeId": "other-999"}
    state["labels"]["sandbox/default/chat"] = ["saw.redhat.com/managed=true",
                                               "saw.redhat.com/env=" + ab.env_label({"A": "1"})]
    fake_env.set_openshell_state(state)
    creds = ab.resolve_credentials(profiles, tmp_path)
    before_calls = len(fake_env.openshell_calls())
    with pytest.raises(ab.InstallerError, match="neither the sandbox it was taken from nor"):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()[before_calls:]]
    assert "sandbox delete" not in ops and "sandbox download" not in ops
    assert archive.read_bytes() == before                             # the original archive, untouched
    assert fake_env.openshell_state()["sandboxes"]["default/chat"]["files"] == {"theirs": "x"}


def test_a_fully_unlabelled_legacy_sandbox_fails_clearly_after_a_failed_delete(
        ab, fake_env, config, tmp_path, monkeypatch):
    """A sandbox from before the instance label, on a CLI with no native id,
    cannot be identified after a failed delete. The installer does not guess
    from the env (that was behind two data-loss findings): it fails, naming
    the archive and the record, and touches neither sandbox nor archive."""
    monkeypatch.setattr(ab.ProfileApplier, "POLL_SECONDS", 0)
    _, sandbox, profiles = _env_sandbox(ab, {})
    _secret(tmp_path, "inference", api_key="k")
    cfg = _ledger_cfg(config, tmp_path)
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["labels"]["sandbox/default/chat"] = ["saw.redhat.com/managed=true"]   # strip both labels
    state["sandboxes"]["default/chat"]["files"] = {"notes.md": "keep me"}
    fake_env.set_openshell_state(state)

    sandbox.env = {"A": {"value": "1"}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    fake_env.deny("sandbox delete")
    with pytest.raises(ab.InstallerError):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    archive = Path(_migrations(tmp_path)["default/chat"]["archive"])
    fake_env.deny()
    for _ in range(2):
        with pytest.raises(ab.InstallerError, match="neither the sandbox it was taken from nor"):
            ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    still = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert "env" not in still and still["files"] == {"notes.md": "keep me"}   # untouched
    assert archive.is_file()


def test_a_legacy_sandbox_with_a_native_id_recovers(ab, fake_env, config, tmp_path, monkeypatch):
    """The same legacy sandbox on a CLI that prints the gateway's id: that
    strong signal identifies the original, and the recovery completes."""
    monkeypatch.setattr(ab.ProfileApplier, "POLL_SECONDS", 0)
    _, sandbox, profiles = _env_sandbox(ab, {})
    _secret(tmp_path, "inference", api_key="k")
    cfg = _ledger_cfg(config, tmp_path)
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["labels"]["sandbox/default/chat"] = ["saw.redhat.com/managed=true"]
    state["sandboxes"]["default/chat"].update(files={"notes.md": "keep me"}, nativeId="gw-1")
    fake_env.set_openshell_state(state)
    sandbox.env = {"A": {"value": "1"}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    fake_env.deny("sandbox delete")
    with pytest.raises(ab.InstallerError):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    assert _migrations(tmp_path)["default/chat"]["fromNative"] == "gw-1"
    fake_env.deny()
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    final = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert final["env"] == ["A=1"] and final["files"] == {"notes.md": "keep me"}
    assert _migrations(tmp_path) == {}


def test_copied_instance_labels_with_another_gateway_id_are_not_the_original(
        ab, fake_env, config, tmp_path):
    """Review (f4488eac, P1): a sandbox carrying the original's instance label
    (copied) but a different gateway id. Nothing is archived, deleted or
    replaced; the apply fails."""
    sandbox, profiles, cfg, archive = _interrupted_recreation(
        ab, fake_env, config, tmp_path, {"A": {"value": "2"}}, native_id="orig-123")
    rec = _migrations(tmp_path)["default/chat"]
    before = archive.read_bytes()
    state = fake_env.openshell_state()
    state["sandboxes"]["default/chat"] = {"image": None, "providers": ["inference"], "phase": "Ready",
                                          "env": ["A=1"], "files": {"theirs": "x"}, "nativeId": "other-999"}
    state["labels"]["sandbox/default/chat"] = ["saw.redhat.com/managed=true",
                                               "saw.redhat.com/env=" + ab.env_label({"A": "1"}),
                                               "saw.redhat.com/instance=" + rec["fromInstance"]]
    fake_env.set_openshell_state(state)
    creds = ab.resolve_credentials(profiles, tmp_path)
    n = len(fake_env.openshell_calls())
    with pytest.raises(ab.InstallerError, match="neither the sandbox it was taken from nor"):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()[n:]]
    assert "sandbox delete" not in ops and "sandbox download" not in ops
    assert archive.read_bytes() == before
    assert fake_env.openshell_state()["sandboxes"]["default/chat"]["files"] == {"theirs": "x"}


def test_unreadable_identity_with_a_pending_restore_fails_the_apply(ab, fake_env, config, tmp_path):
    """Review (2b9dabec, P2): if `sandbox get` cannot be read while a restore
    is pending, the apply fails (so the service retries) instead of
    succeeding with the files unrestored."""
    sandbox, profiles, cfg, archive = _interrupted_recreation(
        ab, fake_env, config, tmp_path, {"A": {"value": "2"}})
    creds = ab.resolve_credentials(profiles, tmp_path)
    # The replacement exists (created by a run that then failed to restore)...
    (fake_env.state / "restore-fail").write_text("")
    with pytest.raises(ab.InstallerError, match="retried"):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    (fake_env.state / "restore-fail").unlink()
    # ...and now the detailed `sandbox get --output json` fails (the plain
    # get, which says the sandbox is running, still works).
    (fake_env.state / "json-get-fails").write_text("")
    with pytest.raises(ab.InstallerError, match="labels cannot be read"):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    assert archive.is_file() and "default/chat" in _migrations(tmp_path)
    assert "notes.md" not in fake_env.openshell_state()["sandboxes"]["default/chat"].get("files", {})
    (fake_env.state / "json-get-fails").unlink()
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/chat"]["files"] == {"notes.md": "keep me"}


# --- 3. a custom provider type drives inference by protocol -----------------------------

def test_a_custom_profile_type_onboards_through_the_inference_block(ab, fake_env, config, tmp_path):
    vllm = ab.Provider(name="internal-llm", type="vllm-prod", credential_secret="vllm",
                       credential_secret_key="api_key")
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["internal-llm"], inference={
        "providerRef": "internal-llm", "protocol": "openai",
        "baseUrl": "https://vllm.models.example/v1", "model": "llama-3.1-8b",
        "timeoutSeconds": "300"})
    profiles = _profiles(ab, sandbox, vllm)
    ab.validate_profiles(profiles, known_profiles={"vllm-prod"})
    _secret(tmp_path, "vllm", api_key="vk")
    creds = ab.resolve_credentials(profiles, tmp_path)
    assert sandbox.inference_values == {"providerRef": "internal-llm", "protocol": "openai",
                                        "baseUrl": "https://vllm.models.example/v1",
                                        "model": "llama-3.1-8b", "timeoutSeconds": 300}
    ab.ProfileApplier(ab.Shell(), config, creds,
                      provider_profile_docs={"vllm-prod": VLLM_PROFILE}).apply(profiles)
    state = fake_env.openshell_state()
    # The credential went through the profile's env var...
    assert state["providers"]["default/internal-llm"]["credential"] == "VLLM_API_KEY=vk"
    # ...and the agent was onboarded against the endpoint, not skipped.
    onboard = next(c[-1] for c in fake_env.openshell_calls()
                   if c[:2] == ["sandbox", "exec"] and "openclaw onboard " in c[-1])
    assert "--auth-choice custom-api-key " in onboard
    assert "--custom-base-url https://vllm.models.example/v1 " in onboard
    assert "--custom-model-id llama-3.1-8b " in onboard
    assert 'CUSTOM_API_KEY="$VLLM_API_KEY"' in onboard
    # Review (bc750ad6, P2): timeoutSeconds reaches the agent's configuration.
    assert state["sandboxes"]["default/chat"]["openclawConfig"][
        "models.providers.vllm-prod.timeoutSeconds"] == 300


def test_provider_ref_picks_the_inference_provider(ab, fake_env, config, tmp_path):
    """Two providers on the sandbox; providerRef decides, not order or a
    provider-level model."""
    nvidia = ab.Provider(name="nvidia", type="nvidia", model="nvidia/x",
                         credential_secret="inference", credential_secret_key="api_key")
    openai = ab.Provider(name="openai", type="openai",
                         credential_secret="inference-openai", credential_secret_key="api_key")
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["nvidia", "openai"],
                         inference={"providerRef": "openai", "protocol": "openai", "model": "gpt-4o"})
    profiles = _profiles(ab, sandbox, nvidia, openai)
    _secret(tmp_path, "inference", api_key="nv")
    _secret(tmp_path, "inference-openai", api_key="sk")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    onboard = next(c[-1] for c in fake_env.openshell_calls()
                   if c[:2] == ["sandbox", "exec"] and "openclaw onboard " in c[-1])
    assert "--auth-choice openai-api-key" in onboard                  # the official API, natively


def test_inference_block_is_validated(ab):
    nvidia = ab.Provider(name="nvidia", type="nvidia", credential_secret="inference")
    bad = {"providerRef": "missing", "protocol": "grpc", "baseUrl": {"secretKeyRef": {"name": "x"}}}
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["nvidia"], inference=bad)
    with pytest.raises(ab.InstallerError) as err:
        ab.validate_profiles(_profiles(ab, sandbox, nvidia))
    text = str(err.value)
    assert "providerRef 'missing' is not an enabled provider" in text
    assert "protocol must be one of anthropic, openai" in text
    assert "inference needs model" in text
    assert "inference baseUrl secretKeyRef.key must be a valid Secret key" in text


# --- 4. empty default: optional in the form, default in the installer -------------------

def _catalog():
    spec = importlib.util.spec_from_file_location(
        "saw_profile_catalog", ROOT / "scripts" / "saw-profile-catalog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_an_empty_default_is_optional_in_the_form_and_the_installer(ab, tmp_path):
    cat = _catalog()
    src = {"secretKeyRef": {"name": "inference", "key": "org"}, "default": ""}
    field = cat.input_field(src, "text", "Org")
    assert field["required"] is False and field["default"] == ""
    # A default means "not required" unless said otherwise; no default means required.
    ref = {"secretKeyRef": {"name": "s", "key": "k"}}
    assert cat.input_field(ref, "text", "t")["required"] is True
    assert cat.input_field({**ref, "default": "x", "required": True}, "text", "t")["required"] is True
    # The installer: absent with an empty default is "" (no error).
    assert ab.resolve_input(src, tmp_path, "org") == ""
    with pytest.raises(ab.InstallerError, match="not found"):
        ab.resolve_input({"secretKeyRef": {"name": "inference", "key": "org"}}, tmp_path, "org")


def test_the_portal_accepts_an_absent_optional_field(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "portal", ROOT / "charts" / "openshell-rhdh" / "files" / "portal.py")
    portal = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portal)
    catalog = {"p": {"secrets": {"inference": {"provider": "openai", "fields": [
        {"key": "api_key", "kind": "secret", "required": True, "title": "API key"},
        {"key": "org", "kind": "text", "required": False, "default": "", "title": "Org"},
        {"key": "url", "kind": "url", "required": False, "default": "", "title": "URL"}]}}}}
    profile, secrets = portal.parse_request({"profile": "p", "inference.api_key": "sk"}, catalog)
    assert secrets == {"inference": {"api_key": "sk", "provider": "openai"}}
    with pytest.raises(portal.PortalError, match="needs: inference.api_key"):
        portal.parse_request({"profile": "p"}, catalog)


def test_the_shipped_form_fields_match_the_profiles():
    cat = json.loads((ROOT / "charts" / "openshell-rhdh" / "files" /
                      "profile-catalog.json").read_text())["profiles"]
    custom = {f["key"]: f for f in cat["custom-inference"]["secrets"]["inference"]["fields"]}
    assert set(custom) == {"api_key", "url", "model"}
    assert custom["url"]["kind"] == "url" and custom["url"]["required"]
    ds = {f["key"]: f for f in cat["data-science"]["secrets"]["inference"]["fields"]}
    # One model field per sandbox: selections are not coupled.
    assert {"model", "cuda_model"} <= set(ds)
    assert ds["model"]["title"] != ds["cuda_model"]["title"]
    assert not ds["model"]["required"] and ds["model"]["default"].startswith("nvidia/")
