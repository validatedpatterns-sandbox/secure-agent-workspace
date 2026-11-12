"""Applying SAW-BOM profiles through the (fake) OpenShell CLI over mTLS."""
from conftest import TEST_PROXY

import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import harness_files


@pytest.fixture
def profiles(ab, shipped_profile_files):
    return ab.parse_profiles(shipped_profile_files)


@pytest.fixture
def creds(ab, profiles, secrets_dir, config, credential_mode):
    return ab.resolve_credentials(profiles, secrets_dir, config["credentialProxy"], credential_mode)


def _shipped_harness(ab):
    """Matches the digest pinned on the real 'notebook' sandbox in the shipped
    profile, so tests that don't care about the harness still get a working
    default instead of an 'unknown bundle' error."""
    return {"bundles": ab.parse_harness_files(harness_files())}


def make_applier(ab, config, creds, harness=None, **overrides):
    return ab.ProfileApplier(ab.Shell(), {**config, **overrides}, creds,
                             harness=harness if harness is not None else _shipped_harness(ab))


def cli_ops(fake_env):
    """Calls as 'noun verb' strings, e.g. 'workspace create'."""
    return [" ".join(c[:2]) for c in fake_env.openshell_calls()]


@pytest.mark.parametrize("credential_mode", ["proxy", "direct"], indirect=True)
def test_shipped_profile_lifecycle(ab, fake_env, config, profiles, creds, capsys):
    applier = applier_with_shipped_profiles(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()

    # Only the nonadmin relay entry remains in persistent CLI state.
    assert state["gateways"] == [{"name": "saw-relay", "endpoint": "https://127.0.0.1:17670",
                                  "local": True, "roles": ["openshell-user"]}]
    assert state["selected"] == "saw-relay"
    assert all("oidc" not in " ".join(c).lower() for c in fake_env.openshell_calls())

    assert state["workspaces"] == ["default", "cuda-dev"]
    assert set(state["providers"]) == {"default/nvidia", "default/brave", "cuda-dev/nvidia"}
    assert state["providers"]["default/nvidia"] == {
        "type": "nvidia", "credential": "NVIDIA_API_KEY=" + creds["default"]["nvidia"]}
    assert state["providers"]["default/brave"]["credential"] == "BRAVE_API_KEY=" + creds["default"]["brave"]
    assert all(c["xdg"] == config["adminConfigHome"] for c in fake_env.openshell_env_calls()
               if c["args"][0] != "gateway")

    # OpenShell 0.1.x has no inference routes: nothing calls `openshell inference`.
    assert not [c for c in fake_env.openshell_calls() if c[:1] == ["inference"]]

    # Enabled sandboxes only.
    assert set(state["sandboxes"]) == {"default/notebook", "cuda-dev/cuda-sandbox"}
    assert state["sandboxes"]["default/notebook"]["providers"] == ["nvidia"]
    before_verify = len(fake_env.openshell_calls())
    assert applier.verify(profiles) == []
    checks = [c for c in fake_env.openshell_calls()[before_verify:]
              if c[:2] == ["sandbox", "exec"] and c[-1] == "openclaw --version"]
    assert sorted(c[c.index("-n") + 1] for c in checks) == ["cuda-sandbox", "notebook"]
    assert not [c for c in fake_env.openshell_calls() if c[:2] == ["provider", "profile"]]
    name = ab.harness_volume_name("default", "notebook")
    notebook = fake_env.openshell_state()["sandboxes"]["default/notebook"]
    assert notebook["driverConfig"]["podman"]["mounts"][0] == {
        "type": "volume", "source": name,
        "target": "/sandbox/harness", "read_only": True}
    assert len(notebook["driverConfig"]["podman"]["mounts"]) == 3
    volume = fake_env.state / "volumes" / name
    assert (volume / "skills" / "pattern-author" / "SKILL.md").is_file()
    scripts = "\n".join(c[-1] for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"])
    assert "base64 -d" not in scripts
    assert """openclaw config set plugins.load.paths '["/sandbox/harness", "/sandbox/harness/plugins", "/sandbox/.saw/trusted/plugin"]'""" in scripts
    assert "openclaw config set tools.fs.workspaceOnly true --strict-json" in scripts
    # The bundle and its native plugin, each enabled (2026.9.x keeps them off).
    assert "openclaw plugins enable ds-default --accept-capabilities" in scripts
    assert "openclaw plugins enable saw-echo --accept-capabilities" in scripts
    # The bundle's MCP server, re-declared where OpenClaw expands ${VAR}.
    cfg = fake_env.openshell_state()["sandboxes"]["default/notebook"]["openclawConfig"]
    echo = cfg["mcp.servers.saw-mcp-echo"]
    assert echo["args"] == ["/sandbox/harness/mcp/echo-server.mjs"]
    assert echo["env"]["NODE_EXTRA_CA_CERTS"] == "${NODE_EXTRA_CA_CERTS}"

    onboard = next(c[-1] for c in fake_env.openshell_calls()
                   if c[:2] == ["sandbox", "exec"] and "onboard" in c[-1] and "notebook" in c)
    assert '--custom-base-url https://integrate.api.nvidia.com/v1 ' in onboard
    assert 'CUSTOM_API_KEY="$NVIDIA_API_KEY"' in onboard
    assert "inference.local" not in onboard
    calls = fake_env.other_calls("nemoclaw")
    assert len(calls) == 1
    assert calls[0]["args"][:2] == ["onboard", "--fresh"] and "cuda-sandbox" in calls[0]["args"]
    assert calls[0]["has_key"]
    tees = [c for c in fake_env.other_calls("sudo") if c["args"][:2] == ["-n", "tee"]]
    units = {c["args"][2]: c["stdin"] for c in tees}
    assert set(units) == {"/etc/systemd/system/openshell-sandbox-notebook.service",
                          "/etc/systemd/system/openshell-sandbox-cuda-sandbox.service"}
    cuda = units["/etc/systemd/system/openshell-sandbox-cuda-sandbox.service"]
    assert "--workspace cuda-dev" in cuda and "User=cloud-user" in cuda
    # Credential arguments name environment variables; provider state contains markers only.
    credential_args = [c[i + 1] for c in fake_env.openshell_calls()
                       for i, arg in enumerate(c[:-1]) if arg == "--credential"]
    assert set(credential_args) == {"NVIDIA_API_KEY", "BRAVE_API_KEY"}
    assert "--credential NVIDIA_API_KEY" in capsys.readouterr().out

    before = fake_env.openshell_state()
    make_applier(ab, config, creds).apply(profiles)
    after = fake_env.openshell_state()
    for field in ("workspaces", "providers", "sandboxes"):
        assert after[field] == before[field]
    creates = [c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "create"]]
    assert len(creates) == 2
    assert len(fake_env.other_calls("nemoclaw")) == 1


def _creates(fake_env, name):
    found = []
    for call in fake_env.openshell_calls():
        if call[:2] == ["sandbox", "create"] and "--name" in call:
            if call[call.index("--name") + 1] == name:
                found.append(call)
    return found


def test_sandbox_create_omits_gpu_unless_the_profile_asks(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    creates = [c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "create"]]
    assert creates and all("--gpu" not in c for c in creates)
    onboard = fake_env.other_calls("nemoclaw")[0]
    assert onboard["gpu"] == "" and onboard["gpu_count"] == ""
    assert "--sandbox-gpu" not in onboard["args"] and "--gpu" not in onboard["args"]


def test_sandbox_create_passes_gpu_when_the_profile_asks(ab, fake_env, config, profiles, creds):
    cuda = next(s for p in profiles for ws in p.workspaces for s in ws.sandboxes
                if s.name == "cuda-sandbox" and s.enabled)
    cuda.gpu_enabled = True
    cuda.gpu_count = 2
    make_applier(ab, config, creds).apply(profiles)
    create = _creates(fake_env, "cuda-sandbox")
    assert len(create) == 1
    assert create[0][create[0].index("--gpu") + 1] == "2"
    assert _creates(fake_env, "notebook") and "--gpu" not in _creates(fake_env, "notebook")[0]
    # nemoclaw onboard does not read NEMOCLAW_GPU_* and has no count flag.
    onboard = fake_env.other_calls("nemoclaw")[0]
    assert onboard["gpu"] == "" and onboard["gpu_count"] == ""
    assert "--sandbox-gpu" not in onboard["args"] and "--gpu" not in onboard["args"]
    make_applier(ab, config, creds).verify(profiles)
    assert any(call[:2] == ["sandbox", "exec"] and "--no-login-shell" in call
               and ["nvidia-smi", "-L"] == call[-2:]
               for call in fake_env.openshell_calls())


@pytest.mark.parametrize("before, after", [(None, 1), (1, 2), (1, None)])
def test_gpu_drift_recreates_and_preserves_files(ab, fake_env, config, profiles, creds,
                                                capsys, before, after):
    cuda = next(s for p in profiles for ws in p.workspaces for s in ws.sandboxes
                if s.name == "cuda-sandbox" and s.enabled)
    cuda.gpu_enabled, cuda.gpu_count = before is not None, before or 1
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["cuda-dev/cuda-sandbox"]["files"] = {"proof.txt": "keep this work"}
    (fake_env.state / "openshell.json").write_text(json.dumps(state))
    cuda.gpu_enabled, cuda.gpu_count = after is not None, after or 1
    make_applier(ab, config, creds).apply(profiles)
    creates = _creates(fake_env, "cuda-sandbox")
    assert len(creates) == 2
    assert len(_creates(fake_env, "notebook")) == 1
    if after is None:
        assert "--gpu" not in creates[-1]
    else:
        assert creates[-1][creates[-1].index("--gpu") + 1] == str(after)
        assert f"{ab.GPU_LABEL_KEY}={after}" in creates[-1]
    assert fake_env.openshell_state()["sandboxes"]["cuda-dev/cuda-sandbox"]["files"]["proof.txt"] == "keep this work"
    assert "a different GPU request; recreating it" in capsys.readouterr().out
    make_applier(ab, config, creds).apply(profiles)
    assert len(_creates(fake_env, "cuda-sandbox")) == 2


def test_gpu_off_upgrade_keeps_sandboxes_without_gpu_labels(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert all(ab.GPU_LABEL_KEY not in labels for labels in state["labels"].values())
    make_applier(ab, config, creds).apply(profiles)
    assert len(_creates(fake_env, "cuda-sandbox")) == 1
    assert len(_creates(fake_env, "notebook")) == 1


def test_gpu_inspection_read_failure_does_not_trigger_recreation(ab, fake_env, config, profiles, creds):
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    fake_env.deny("sandbox get")
    ws = next(ws for p in profiles for ws in p.workspaces if ws.name == "cuda-dev")
    assert applier.sandbox_gpu_ok(ws, ws.sandboxes[0]) is True


def test_changed_proxy_ca_recreates_sandboxes(ab, fake_env, config, profiles, creds, capsys):
    make_applier(ab, config, creds).apply(profiles)
    before = len([c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "create"]])
    changed = {**config, "credentialProxy": {**config["credentialProxy"],
                                               "caFingerprint": "different-proxy-ca"}}
    make_applier(ab, changed, creds).apply(profiles)
    after = len([c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "create"]])
    assert after == before + 2
    assert "its /sandbox files are carried over" in capsys.readouterr().out


def test_broken_nemoclaw_sandbox_is_onboarded_again(ab, fake_env, config, profiles, creds, monkeypatch):
    monkeypatch.setattr(ab.ProfileApplier, "BROKEN_GRACE_SECONDS", 0)
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["cuda-dev/cuda-sandbox"]["phase"] = "Error"
    (fake_env.state / "openshell.json").write_text(json.dumps(state))
    make_applier(ab, config, creds).apply(profiles)
    assert len(fake_env.other_calls("nemoclaw")) == 2
    assert fake_env.openshell_state()["sandboxes"]["cuda-dev/cuda-sandbox"]["phase"] == "Ready"


def test_owner_subject_becomes_admin_of_each_workspace(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds, ownerSubject="f3c1-owner-subject").apply(profiles)
    members = fake_env.openshell_state()["members"]
    assert members == [["cuda-dev", "saw-relay", "user"],
                       ["cuda-dev", "f3c1-owner-subject", "admin"],
                       ["default", "saw-relay", "user"],
                       ["default", "f3c1-owner-subject", "admin"]]
    # Re-running does not fail on the existing membership.
    make_applier(ab, config, creds, ownerSubject="f3c1-owner-subject").apply(profiles)


def test_no_owner_subject_fails_agent_apply(ab, fake_env, config, profiles, creds):
    with pytest.raises(ab.InstallerError, match="ownerSubject is required"):
        make_applier(ab, config, creds, ownerSubject="").apply(profiles)
    assert fake_env.openshell_state()["members"] == [
        ["cuda-dev", "saw-relay", "user"], ["default", "saw-relay", "user"]]


def test_owner_recreation_removes_stale_membership(ab, fake_env, config, profiles, creds, tmp_path):
    config = {**config, "prune": {"ledgerPath": str(tmp_path / "managed.json")}}
    make_applier(ab, config, creds, ownerSubject="old-subject").apply(profiles)
    make_applier(ab, config, creds, ownerSubject="new-subject").apply(profiles)
    assert fake_env.openshell_state()["members"] == [
        ["cuda-dev", "saw-relay", "user"], ["default", "saw-relay", "user"],
        ["cuda-dev", "new-subject", "admin"], ["default", "new-subject", "admin"]]
    with pytest.raises(ab.InstallerError, match="ownerSubject is required"):
        make_applier(ab, config, creds, ownerSubject="").apply(profiles)
    assert fake_env.openshell_state()["members"] == [
        ["cuda-dev", "saw-relay", "user"], ["default", "saw-relay", "user"]]


def test_owner_revocation_clears_retained_disabled_workspace(
        ab, fake_env, config, profiles, creds, tmp_path):
    config = {**config, "prune": {"mode": "report", "ledgerPath": str(tmp_path / "managed.json")}}
    make_applier(ab, config, creds, ownerSubject="old-subject").apply(profiles)
    for profile in profiles:
        for workspace in profile.workspaces:
            if workspace.name == "cuda-dev":
                workspace.enabled = False

    with pytest.raises(ab.InstallerError, match="ownerSubject is required"):
        make_applier(ab, config, creds, ownerSubject="").apply(profiles)

    state = fake_env.openshell_state()
    assert "cuda-dev" in state["workspaces"]
    assert state["members"] == [["cuda-dev", "saw-relay", "user"],
                                 ["default", "saw-relay", "user"]]
    assert json.loads((tmp_path / "owner-memberships.json").read_text()) == {}


def test_mtls_client_without_admin_fails_clearly(ab, fake_env, config, profiles, creds):
    fake_env.deny("workspace create")
    with pytest.raises(ab.InstallerError, match="platform admin; check the mTLS identity has the openshell-admin role"):
        make_applier(ab, config, creds).apply(profiles)


def test_gateway_unreachable_fails_before_any_change(ab, fake_env, config, profiles, creds):
    fake_env.deny("workspace list")
    with pytest.raises(ab.InstallerError, match="cannot list workspaces"):
        make_applier(ab, config, creds).apply(profiles)
    assert "workspace create" not in cli_ops(fake_env)


@pytest.mark.parametrize("failure", ["connection was not ready", "TLS handshake: UnknownIssuer",
                                     "received fatal alert: UnknownCA",
                                     "transport error: stream closed because of a broken pipe"])
def test_first_admin_rpc_waits_for_the_client_ca_reload(ab, config, monkeypatch, failure):
    applier = ab.ProfileApplier(ab.Shell(), config, {})
    attempts, sleeps, relays = [], [], []

    def cli(*args, **kwargs):
        if args == ("workspace", "list"):
            attempts.append(args)
            return ab.Result(1, err=failure) if len(attempts) < 3 else ab.Result(0, out="default")
        return ab.Result(0)

    monkeypatch.setattr(applier, "cli", cli)
    monkeypatch.setattr(applier, "register_relay_gateway", lambda: relays.append(len(attempts)))
    monkeypatch.setattr(ab.time, "sleep", sleeps.append)
    applier.register_gateway()
    assert len(attempts) == 3 and len(sleeps) == 2
    assert relays == [3]


def test_first_admin_rpc_reload_wait_is_bounded(ab, config, monkeypatch):
    applier = ab.ProfileApplier(ab.Shell(), config, {})
    times = iter([0, 0, 31])
    attempts = []

    def cli(*args, **kwargs):
        if args == ("workspace", "list"):
            attempts.append(args)
            return ab.Result(1, err="connection was not ready")
        return ab.Result(0)

    monkeypatch.setattr(applier, "cli", cli)
    monkeypatch.setattr(ab.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(ab.time, "sleep", lambda _: None)
    monkeypatch.setattr(applier, "register_relay_gateway", lambda: pytest.fail("relay registered before admin RPC succeeded"))
    with pytest.raises(ab.InstallerError, match="cannot list workspaces"):
        applier.register_gateway()
    assert len(attempts) == 2

def test_provider_failure_stops_the_apply(ab, fake_env, config, profiles, creds):
    fake_env.deny("provider create")
    with pytest.raises(ab.InstallerError, match="provider create"):
        make_applier(ab, config, creds).apply(profiles)
    assert "sandbox create" not in cli_ops(fake_env)


def test_errored_sandbox_is_recreated(ab, fake_env, config, profiles, creds, monkeypatch):
    monkeypatch.setattr(ab.ProfileApplier, "BROKEN_GRACE_SECONDS", 0)
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"]["phase"] = "Error"
    fake_env.set_openshell_state(state)
    make_applier(ab, config, creds).apply(profiles)
    ops = fake_env.openshell_calls()
    assert ["sandbox", "delete", "notebook"] in ops
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["phase"] == "Ready"


@pytest.fixture
def fast_polls(fake_clock):
    return fake_clock


def test_a_sandbox_that_recovers_is_not_recreated(ab, fake_env, config, profiles, creds, fast_polls):
    """Found live after a VM restart: the notebook reported an error while
    its supervisor reconnected. Recreating it would lose /sandbox."""
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"].update(phase="Error", after=[2, "Ready"])
    fake_env.set_openshell_state(state)
    make_applier(ab, config, creds).apply(profiles)
    assert ["sandbox", "delete", "notebook"] not in fake_env.openshell_calls()
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["phase"] == "Ready"


def test_a_recreate_waits_for_the_deletion(ab, fake_env, config, profiles, creds, fast_polls, monkeypatch):
    """Found live: `sandbox delete` only accepts the deletion, and the create
    right after it failed with "already exists"."""
    monkeypatch.setattr(ab.ProfileApplier, "BROKEN_GRACE_SECONDS", 0)
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"]["phase"] = "Error"
    state["deleteDelay"] = 3
    fake_env.set_openshell_state(state)
    make_applier(ab, config, creds).apply(profiles)
    ops = fake_env.openshell_calls()
    delete = ops.index(["sandbox", "delete", "notebook"])
    creates = [i for i, c in enumerate(ops) if c[:2] == ["sandbox", "create"] and "notebook" in c]
    gets = [i for i, c in enumerate(ops) if c[:3] == ["sandbox", "get", "notebook"] and delete < i < creates[-1]]
    assert len(creates) == 2 and delete < creates[-1]
    assert len(gets) >= 3, "polled until the deletion finished"
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["phase"] == "Ready"


def test_a_deletion_left_by_an_earlier_run_is_finished(ab, fake_env, config, profiles, creds, fast_polls):
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"].update(phase="Deleting", after=[2, "gone"])
    fake_env.set_openshell_state(state)
    make_applier(ab, config, creds).apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["phase"] == "Ready"


def test_a_deletion_that_never_finishes_fails_clearly(ab, fake_env, config, profiles, creds, fast_polls,
                                                       monkeypatch):
    monkeypatch.setattr(ab.ProfileApplier, "DELETE_WAIT_SECONDS", 0)
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"].update(phase="Deleting", after=[99, "gone"])
    fake_env.set_openshell_state(state)
    with pytest.raises(ab.InstallerError, match="still being deleted"):
        make_applier(ab, config, creds).apply(profiles)


def test_the_gateway_waits_until_the_sandbox_accepts_exec(ab, fake_env, config, profiles, creds,
                                                          fast_polls):
    """Found live after a VM restart: execs failed with "not ready" while the
    sandbox was still Provisioning, and the OpenClaw gateway never started."""
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["notReadyExecs"] = 4
    fake_env.set_openshell_state(state)
    before = len(fake_env.openshell_calls())
    make_applier(ab, config, creds).apply(profiles)
    calls = fake_env.openshell_calls()[before:]
    probes = [c for c in calls if c[:2] == ["sandbox", "exec"] and c[-1] == "true"]
    assert len(probes) >= 5
    run = [i for i, c in enumerate(calls) if c[:2] == ["sandbox", "exec"] and 'cat > "$SUP"' in c[-1]]
    assert run and run[-1] > calls.index(probes[-1])
    assert fake_env.openshell_state()["notReadyExecs"] == 0


def test_verify_reports_missing_resources(ab, fake_env, config, profiles, creds):
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    del state["providers"]["default/brave"]
    state["sandboxes"]["default/notebook"]["providers"] = []
    state["workspaces"].remove("cuda-dev")
    fake_env.set_openshell_state(state)
    failures = applier.verify(profiles)
    assert "provider 'brave' in 'default' is missing" in failures
    assert "sandbox 'notebook' is missing provider 'nvidia'" in failures
    assert "workspace 'cuda-dev' is missing" in failures


def test_workspace_name_match_is_exact(ab, fake_env, config, creds, profiles):
    # A workspace called "cuda-dev-old" must not satisfy "cuda-dev".
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    state["workspaces"] = ["default", "cuda-dev-old"]
    fake_env.set_openshell_state(state)
    assert "workspace 'cuda-dev' is missing" in applier.verify(profiles)


def test_dry_run_calls_nothing(ab, fake_env, config, profiles, creds):
    applier = ab.ProfileApplier(ab.Shell(dry_run=True), config, creds, harness=_shipped_harness(ab))
    applier.apply(profiles)
    assert fake_env.openshell_calls() == []


# -- providers the gateway has no profile for (governance off) --------------

def default_ws(ab, profiles):
    return next(ws for _, ws in ab.enabled_workspaces(profiles) if ws.name == "default")


def test_provider_without_gateway_profile_is_skipped_not_fatal(ab, fake_env, config, profiles, creds):
    """Live: with governance off, OpenShell 0.0.116 has no 'brave' profile and
    `provider create --type brave` failed the whole apply."""
    fake_env.without_profiles("brave")
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    assert "default/brave" not in state["providers"]
    assert {"default/nvidia", "cuda-dev/nvidia"} <= set(state["providers"])
    assert set(state["sandboxes"]) == {"default/notebook", "cuda-dev/cuda-sandbox"}
    assert applier.skipped == {("default", "brave")}
    assert applier.verify(profiles) == []


def test_sandbox_is_created_without_a_skipped_provider(ab, fake_env, config, profiles, creds):
    fake_env.without_profiles("brave")
    notebook = next(sb for sb in default_ws(ab, profiles).sandboxes if sb.name == "notebook")
    notebook.providers = ["nvidia", "brave"]
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["providers"] == ["nvidia"]
    assert applier.verify(profiles) == []


def test_other_provider_errors_still_fail(ab, fake_env, config, profiles, creds):
    fake_env.deny("provider create")
    with pytest.raises(ab.InstallerError, match="could not create provider"):
        make_applier(ab, config, creds).apply(profiles)


# -- importing a shipped provider profile the gateway lacks ------------------

SHIPPED_PROFILES = Path(__file__).resolve().parents[2] / "charts" / "openshell-saw" / "files" / "provider-profiles"


def applier_with_shipped_profiles(ab, config, creds):
    docs = {p.stem: p.read_text() for p in SHIPPED_PROFILES.glob("*.yaml")}
    return ab.ProfileApplier(ab.Shell(), config, creds, docs, harness=_shipped_harness(ab))


def test_missing_profile_is_imported_from_the_chart_then_provider_created(ab, fake_env, config, profiles, creds):
    """Governance off: the gateway has no 'brave' profile. The installer imports
    the shipped copy (same file as governance-policy/profiles/brave.yaml) into
    the workspace and creates the provider."""
    fake_env.without_profiles("brave")
    applier = applier_with_shipped_profiles(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    assert state["imported_profiles"] == {"default": ["brave"]}
    assert state["providers"]["default/brave"]["credential"] == "BRAVE_API_KEY=saw-cred.web-search.api_key"
    assert applier.skipped == set()
    assert applier.verify(profiles) == []
    imports = [c for c in fake_env.openshell_calls() if c[:3] == ["provider", "profile", "import"]]
    assert len(imports) == 1 and "--workspace" not in imports[0]      # default workspace
    applier_with_shipped_profiles(ab, config, creds).apply(profiles)
    imports = [c for c in fake_env.openshell_calls() if c[:3] == ["provider", "profile", "import"]]
    assert len(imports) == 1


def test_failed_profile_import_stops_the_apply(ab, fake_env, config, profiles, creds):
    fake_env.without_profiles("brave")
    applier = ab.ProfileApplier(ab.Shell(), config, creds, {"brave": "display_name: no id\n"},
                                harness=_shipped_harness(ab))
    with pytest.raises(ab.InstallerError, match="could not import the 'brave' provider profile"):
        applier.apply(profiles)


def test_provider_profiles_are_read_from_the_installer_disk(ab, tmp_path):
    (tmp_path / "provider-profile-brave.yaml").write_text("id: brave\n")
    (tmp_path / "config.json").write_text("{}")
    assert ab.provider_profiles(tmp_path) == {"brave": "id: brave\n"}


def test_verify_fails_when_openclaw_cannot_run_in_the_sandbox(ab, fake_env, config, profiles, creds):
    """A gate that cannot be enabled fails the apply before gateway startup."""
    fake_env.exec_fails_in("notebook")
    applier = make_applier(ab, config, creds)
    with pytest.raises(ab.InstallerError, match="could not enable saw-tool-gate"):
        applier.apply(profiles)


# -- the installer's mTLS identity is platform admin --------------------------

def cert_field(path, *args):
    return subprocess.run(["openssl", "x509", "-noout", *args, "-in", str(path)],
                          capture_output=True, text=True, check=True).stdout.strip()


def test_installer_uses_an_admin_client_certificate_under_rbac(ab, fake_env, config, profiles, creds):
    """The temporary admin CA authorizes apply; the persistent entry is user-only."""
    fake_env.rbac()
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert state["gateways"] == [{"name": "saw-relay", "endpoint": "https://127.0.0.1:17670",
                                  "local": True, "roles": ["openshell-user"]}]
    assert state["selected"] == "saw-relay"
    assert "cuda-dev" in state["workspaces"]
    crt = fake_env.admin_cert()
    subject = cert_field(crt, "-subject", "-nameopt", "sep_multiline")
    assert "OU=openshell-admin" in subject and "CN=saw-installer" in subject
    ca = fake_env.home / ".local/state/openshell/tls/client-ca.pem"
    assert subprocess.run(["openssl", "verify", "-CAfile", str(ca), str(crt)], capture_output=True).returncode == 0
    assert "TLS Web Client Authentication" in cert_field(crt, "-ext", "extendedKeyUsage")
    assert oct((crt.parent / "tls.key").stat().st_mode & 0o777) == "0o600"
    assert oct(crt.parent.parent.stat().st_mode & 0o777) == "0o700"


def test_gateways_own_user_certificate_is_refused_under_rbac(ab, fake_env, config, profiles, creds):
    """The fake enforces the rule: without the override the gateway's own
    client certificate (OU=openshell-user) cannot create workspaces."""
    fake_env.rbac()
    fake_env.set_openshell_state({"gateways": [{"name": "saw-installer", "roles": ["openshell-user"]}],
                                  "selected": "saw-installer", "workspaces": ["default"], "members": [],
                                  "providers": {}, "sandboxes": {}})
    applier = make_applier(ab, config, creds)
    with pytest.raises(ab.InstallerError, match="openshell-admin"):
        applier.apply_workspace(next(ws for _, ws in ab.enabled_workspaces(profiles) if ws.name == "cuda-dev"))


def test_admin_certificate_uses_a_separate_ca_in_tmpfs(ab, fake_env, real_admin_config, profiles, creds):
    make_applier(ab, real_admin_config, creds).register_gateway()
    crt = fake_env.admin_cert()
    gateway_ca = fake_env.home / ".local/state/openshell/tls/ca.crt"
    assert subprocess.run(["openssl", "verify", "-CAfile", str(gateway_ca), str(crt)],
                          capture_output=True).returncode != 0
    assert subprocess.run(["openssl", "verify", "-CAfile", str(gateway_ca.parent / "client-ca.pem"),
                           str(crt)], capture_output=True).returncode == 0
    assert fake_env.admin_tls.is_relative_to(Path(os.environ["SAW_RUNTIME_DIR"]))
    assert not list(fake_env.home.rglob("ca.key"))


def test_missing_gateway_ca_is_a_clear_error(ab, fake_env):
    (fake_env.home / ".local/state/openshell/tls/ca.crt").unlink()
    with pytest.raises(ab.InstallerError, match="gateway CA certificate is missing"):
        with ab.admin_session({}, fake_env.home, None, as_current_user=True):
            pass


def test_key_never_appears_in_argv_or_logs(ab, fake_env, config, profiles, creds, capsys):
    make_applier(ab, config, creds).register_gateway()
    key = (fake_env.admin_cert().parent / "tls.key").read_text()
    body = "".join(l for l in key.splitlines() if not l.startswith("-----"))
    assert body[:40] not in capsys.readouterr().err


# -- keyless (in-cluster MCP) providers ---------------------------------------


KEYLESS_CATALOG = {
    "nvidia": ["integrate.api.nvidia.com"],
    "local-mcp": {"id": "local-mcp", "credentials": [],
                  "endpoints": [{"host": "mcp.apps.svc.cluster.local", "port": 8080,
                                 "protocol": "mcp", "enforcement": "enforce"}]},
}


def with_keyless(ab, profiles, **overrides):
    """Add a keyless 'local-mcp' provider to the default workspace and to the
    notebook sandbox, as an in-cluster MCP Service needs."""
    ws = next(w for p in profiles for w in p.workspaces if w.name == "default")
    ws.providers.append(ab.Provider(name="local-mcp", type="local-mcp",
                                    credential_free=True, **overrides))
    for sb in ws.sandboxes:
        if sb.name == "notebook":
            sb.providers = [*sb.providers, "local-mcp"]
    return profiles


def test_a_keyless_provider_is_created_without_a_credential(ab, fake_env, config, profiles, creds):
    fake_env.set_catalog(KEYLESS_CATALOG)
    make_applier(ab, config, creds).apply(with_keyless(ab, profiles))
    state = fake_env.openshell_state()
    assert state["providers"]["default/local-mcp"] == {"type": "local-mcp", "credential": None}
    assert "local-mcp" in state["sandboxes"]["default/notebook"]["providers"]
    create = next(c for c in fake_env.openshell_calls()
                  if c[:2] == ["provider", "create"] and "local-mcp" in c)
    assert "--credential" not in create


def test_a_keyless_provider_needs_a_profile_that_requires_no_credential(
        ab, fake_env, config, profiles, creds):
    fake_env.set_catalog({**KEYLESS_CATALOG,
                          "local-mcp": {"id": "local-mcp", "endpoints": [],
                                        "credentials": [{"name": "api_key", "required": True,
                                                         "env_vars": ["LOCAL_MCP_API_KEY"]}]}})
    with pytest.raises(ab.InstallerError, match="credentials are required"):
        make_applier(ab, config, creds).apply(with_keyless(ab, profiles))


def test_a_keyless_provider_refuses_an_unenforced_endpoint(ab, fake_env, config, profiles, creds):
    """Without a key, the governance profile is the only gate."""
    fake_env.set_catalog({**KEYLESS_CATALOG,
                          "local-mcp": {"id": "local-mcp", "credentials": [],
                                        "endpoints": [{"host": "mcp.apps.svc.cluster.local",
                                                       "enforcement": "monitor"}]}})
    with pytest.raises(ab.InstallerError, match="not enforced"):
        make_applier(ab, config, creds).apply(with_keyless(ab, profiles))


def test_a_keyless_profile_may_omit_its_credentials(ab, fake_env, config, profiles, creds):
    """A profile with no key leaves `credentials` out, as the shipped
    web-search profile does; that is not 'malformed'."""
    fake_env.set_catalog({**KEYLESS_CATALOG,
                          "local-mcp": {"id": "local-mcp",
                                        "endpoints": [{"host": "mcp.apps.svc.cluster.local",
                                                       "port": 8080, "enforcement": "enforce"}]}})
    make_applier(ab, config, creds).apply(with_keyless(ab, profiles))
    assert fake_env.openshell_state()["providers"]["default/local-mcp"]["credential"] is None


def test_a_keyless_provider_refuses_an_endpoint_that_does_not_declare_enforcement(
        ab, fake_env, config, profiles, creds):
    """An undeclared enforcement is not assumed to be 'enforce': this check
    is what the missing key would otherwise be."""
    fake_env.set_catalog({**KEYLESS_CATALOG,
                          "local-mcp": {"id": "local-mcp", "credentials": [],
                                        "endpoints": [{"host": "mcp.apps.svc.cluster.local",
                                                       "port": 8080}]}})
    with pytest.raises(ab.InstallerError, match="not enforced"):
        make_applier(ab, config, creds).apply(with_keyless(ab, profiles))


def test_a_keyless_provider_refuses_an_outside_host(ab, fake_env, config, profiles, creds):
    """credentialFree is for in-cluster Services. Shipped web-search declares
    no credential and would otherwise qualify for keyless egress to npmjs."""
    fake_env.set_catalog({**KEYLESS_CATALOG,
                          "local-mcp": {"id": "local-mcp",
                                        "endpoints": [{"host": "registry.npmjs.org", "port": 443,
                                                       "enforcement": "enforce"}]}})
    with pytest.raises(ab.InstallerError, match="not an in-cluster Service"):
        make_applier(ab, config, creds).apply(with_keyless(ab, profiles))


def test_in_cluster_host(ab):
    assert ab.in_cluster_host("mcp.apps.svc")
    assert ab.in_cluster_host("mcp.apps.svc.cluster.local")
    assert not ab.in_cluster_host("registry.npmjs.org")
    assert not ab.in_cluster_host("svc.evil.com")
    assert not ab.in_cluster_host("mcp.apps.svc.cluster.local.evil.com")


def test_a_keyless_provider_refuses_a_profile_without_endpoints(
        ab, fake_env, config, profiles, creds):
    fake_env.set_catalog({**KEYLESS_CATALOG,
                          "local-mcp": {"id": "local-mcp", "credentials": [], "endpoints": []}})
    with pytest.raises(ab.InstallerError, match="declares no endpoints"):
        make_applier(ab, config, creds).apply(with_keyless(ab, profiles))


def test_a_keyless_provider_does_not_reuse_a_keyed_one_of_the_same_name(
        ab, fake_env, config, profiles, creds):
    fake_env.set_catalog(KEYLESS_CATALOG)
    fake_env.set_openshell_state({
        "gateways": [], "selected": None, "workspaces": ["default"], "members": [],
        "providers": {"default/local-mcp": {"type": "local-mcp", "credential": "api_key"}},
        "sandboxes": {}})
    with pytest.raises(ab.InstallerError, match="already has credentials"):
        make_applier(ab, config, creds).apply(with_keyless(ab, profiles))


def test_a_keyless_provider_reaches_a_sandbox_that_already_runs(
        ab, fake_env, config, profiles, creds, shipped_profile_files):
    """The attachment is the sandbox's permission to reach the Service. Adding
    the provider to an existing SAW must attach it to the running sandbox and
    restart OpenClaw, which only covers processes started after the attach."""
    fake_env.set_catalog(KEYLESS_CATALOG)
    make_applier(ab, config, creds).apply(profiles)
    before = len([c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "create"]])

    later = with_keyless(ab, ab.parse_profiles(shipped_profile_files))
    make_applier(ab, config, creds).apply(later)

    state = fake_env.openshell_state()
    assert state["sandboxes"]["default/notebook"]["providers"] == ["nvidia", "local-mcp"]
    attach = next(c for c in fake_env.openshell_calls()
                  if c[:3] == ["sandbox", "provider", "attach"] and "local-mcp" in c)
    assert "--wait" in attach
    creates = [c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "create"]]
    assert len(creates) == before, "the running sandbox must not be recreated to attach a provider"


def test_attaching_a_keyless_provider_marks_openclaw_for_restart(
        ab, fake_env, config, profiles, creds, shipped_profile_files):
    """The attachment covers processes started after it, so the running
    OpenClaw gateway needs the restart that openclaw_gateway_script does for
    a refilled harness."""
    fake_env.set_catalog(KEYLESS_CATALOG)
    make_applier(ab, config, creds).apply(profiles)

    later = with_keyless(ab, ab.parse_profiles(shipped_profile_files))
    ws = next(w for p in later for w in p.workspaces if w.name == "default")
    sb = next(s for s in ws.sandboxes if s.name == "notebook")
    applier = make_applier(ab, config, creds)
    applier.cli("provider", "create", "--name", "local-mcp", "--type", "local-mcp")
    applier.attach_missing_providers(ws, sb)
    assert applier.harness_refilled[("default", "notebook")] is True


@pytest.mark.parametrize("target", ["default/notebook", "cuda-dev/cuda-sandbox"])
@pytest.mark.parametrize("fault", [
    {"setFail": True}, {"getFail": True}, {"response": "false"},
    {"response": '"true"'}, {"response": "1"}, {"response": "null"},
    {"response": "not-json"}, {"response": '{"tools.fs.workspaceOnly": true}'},
])
def test_workspace_confinement_failure_stops_apply(
        ab, fake_env, config, profiles, creds, target, fault):
    (fake_env.state / "workspace-confinement.json").write_text(json.dumps({target: fault}))
    with pytest.raises(ab.InstallerError):
        applier_with_shipped_profiles(ab, config, creds).apply(profiles)
    sandbox = fake_env.openshell_state()["sandboxes"][target]
    assert sandbox["agentStopped"] is True
    ws, name = target.split("/")
    calls = [c for c in fake_env.openshell_calls()
             if c[:2] == ["sandbox", "exec"] and name in c]
    assert not any("openclaw plugins enable saw-tool-gate" in c[-1] for c in calls)
    assert not any('cat > "$SUP"' in c[-1] for c in calls)


@pytest.mark.parametrize("target", ["default/notebook", "cuda-dev/cuda-sandbox"])
def test_existing_workspace_confinement_is_repaired_before_policy_update(
        ab, fake_env, config, profiles, creds, target, monkeypatch):
    applier = applier_with_shipped_profiles(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"][target]["openclawConfig"]["tools.fs.workspaceOnly"] = False
    fake_env.set_openshell_state(state)
    before = len(fake_env.openshell_calls())
    applier.apply(profiles)
    repaired = fake_env.openshell_state()["sandboxes"][target]
    assert repaired["openclawConfig"]["tools.fs.workspaceOnly"] is True
    assert repaired["agentStopped"] is False
    calls = fake_env.openshell_calls()[before:]
    name = target.split("/")[1]
    scripts = [c[-1] for c in calls if c[:2] == ["sandbox", "exec"] and name in c]
    assert any("# SAW: quiesce OpenClaw" in s for s in scripts)
    before = len(fake_env.openshell_calls())
    applier.apply(profiles)
    assert not any("# SAW: quiesce OpenClaw" in c[-1]
                   for c in fake_env.openshell_calls()[before:])

    # Reapply failure leaves the old mounted policy intact and the agent stopped.
    state = fake_env.openshell_state()
    state["sandboxes"][target]["openclawConfig"].pop("tools.fs.workspaceOnly")
    fake_env.set_openshell_state(state)
    (fake_env.state / "workspace-confinement.json").write_text(json.dumps({target: {"setFail": True}}))
    fills = []
    original = applier.volumes.fill
    def record_fill(*args, **kwargs):
        fills.append(args[0])
        return original(*args, **kwargs)
    monkeypatch.setattr(applier.volumes, "fill", record_fill)
    with pytest.raises(ab.InstallerError):
        applier.apply(profiles)
    ws, name = target.split("/")
    assert ab.sandbox_volume_name(ab.GATE_VOLUME_PREFIX, ws, name) not in fills
    assert fake_env.openshell_state()["sandboxes"][target]["agentStopped"] is True


def test_gateway_get_failure_cannot_replace_a_running_agents_policy(
        ab, fake_env, config, profiles, creds, monkeypatch):
    applier = applier_with_shipped_profiles(ab, config, creds)
    applier.apply(profiles)
    fake_env.deny("sandbox get")
    fills = []
    original = applier.volumes.fill
    def record_fill(*args, **kwargs):
        fills.append(args[0])
        return original(*args, **kwargs)
    monkeypatch.setattr(applier.volumes, "fill", record_fill)
    with pytest.raises(ab.InstallerError, match="refusing to replace its tool policy"):
        applier.apply(profiles)
    assert not fills
    assert all(sb["agentStopped"] for sb in fake_env.openshell_state()["sandboxes"].values())


@pytest.mark.parametrize("target", ["default/notebook", "cuda-dev/cuda-sandbox"])
@pytest.mark.parametrize("use_ledger", [False, True])
def test_confinement_host_stop_survives_later_applies_without_recreation(
        ab, fake_env, config, profiles, creds, target, use_ledger, tmp_path, fake_clock):
    if use_ledger:
        config = {**config, "prune": {"ledgerPath": str(tmp_path / "managed.json")}}
    applier = applier_with_shipped_profiles(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"][target].setdefault("files", {})["only-copy.txt"] = "must survive"
    state["sandboxes"][target]["nativeId"] = "original-sandbox"
    fake_env.set_openshell_state(state)
    fault_file = fake_env.state / "workspace-confinement.json"
    fault_file.write_text(json.dumps({target: {"getFail": True, "quiesceFail": True}}))
    with pytest.raises(ab.InstallerError, match="cannot quiesce OpenClaw"):
        applier.apply(profiles)
    sb = fake_env.openshell_state()["sandboxes"][target]
    assert sb["agentStopped"] is True and sb["phase"] == "Completed"
    ws, name = target.split("/")
    assert ["stop", "--time", "5", f"openshell-{ws}--{name}-0000"] in fake_env.podman_calls()
    assert target in json.loads(applier.confinement_stops_path.read_text())

    # Every retry is a new installer process. Even after the exec fault clears,
    # Completed must not fall through the 90-second grace period to deletion.
    fault_file.unlink()
    before = len(fake_env.openshell_calls())
    for _ in range(2):
        retry = applier_with_shipped_profiles(ab, config, creds)
        with pytest.raises(ab.InstallerError, match="held for workspace confinement repair"):
            retry.apply(profiles)
        sb = fake_env.openshell_state()["sandboxes"][target]
        assert sb["files"]["only-copy.txt"] == "must survive"
        assert sb["nativeId"] == "original-sandbox"
        assert sb["phase"] == "Completed"
    assert not any(c[:2] in (["sandbox", "delete"], ["sandbox", "create"])
                   and name in c for c in fake_env.openshell_calls()[before:])

    # An operator recovers the existing workload in place. Only a successful
    # confinement check and agent startup release the durable hold.
    state = fake_env.openshell_state()
    state["sandboxes"][target]["phase"] = "Ready"
    fake_env.set_openshell_state(state)
    recovered = applier_with_shipped_profiles(ab, config, creds)
    recovered.apply(profiles)
    sb = fake_env.openshell_state()["sandboxes"][target]
    assert sb["files"]["only-copy.txt"] == "must survive"
    assert sb["nativeId"] == "original-sandbox"
    assert sb["openclawConfig"]["tools.fs.workspaceOnly"] is True
    assert sb["agentStopped"] is False
    assert target not in json.loads(recovered.confinement_stops_path.read_text())


@pytest.mark.parametrize("target", ["default/notebook", "cuda-dev/cuda-sandbox"])
@pytest.mark.parametrize("failed_first", [False, True])
@pytest.mark.parametrize("provider_mode", ["missing", "no-endpoint"])
def test_confinement_repair_resumes_existing_agent_without_usable_provider(
        ab, fake_env, config, profiles, creds, target, failed_first, provider_mode, monkeypatch):
    applier_with_shipped_profiles(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    original_config = state["sandboxes"][target]["openclawConfig"].copy()
    state["sandboxes"][target]["openclawConfig"]["tools.fs.workspaceOnly"] = False
    fake_env.set_openshell_state(state)
    if failed_first:
        fault_file = fake_env.state / "workspace-confinement.json"
        fault_file.write_text(json.dumps({target: {"setFail": True}}))
        with pytest.raises(ab.InstallerError):
            applier_with_shipped_profiles(ab, config, creds).apply(profiles)
        assert fake_env.openshell_state()["sandboxes"][target]["agentStopped"] is True
        fault_file.unlink()
    retry = applier_with_shipped_profiles(ab, config, creds)
    if provider_mode == "missing":
        monkeypatch.setattr(retry, "find_provider", lambda *args: None)
    else:
        monkeypatch.setattr(ab._saw_core, "sandbox_endpoint", lambda *args: "")
        monkeypatch.setattr(ab._saw_core, "NATIVE_BASE_URLS", {})
        monkeypatch.setattr(ab._saw_core, "PROTOCOL_NATIVE_BASE_URLS", {})
        monkeypatch.setattr(ab._saw_core, "OPENCLAW_AUTH_CHOICES", {})
    before = len(fake_env.openshell_calls())
    retry.apply(profiles)
    sb = fake_env.openshell_state()["sandboxes"][target]
    assert sb["agentStopped"] is False
    assert sb["openclawConfig"]["tools.fs.workspaceOnly"] is True
    assert sb["openclawConfig"]["agents.entries.main.model"] == original_config["agents.entries.main.model"]
    assert target not in json.loads(retry.confinement_stops_path.read_text())
    calls = fake_env.openshell_calls()[before:]
    assert not any("openclaw onboard" in c[-1] for c in calls)
    assert any('cat > "$SUP"' in c[-1] for c in calls)


def test_no_provider_does_not_start_an_unonboarded_agent(
        ab, fake_env, config, profiles, creds, monkeypatch):
    for _ in range(2):
        applier = applier_with_shipped_profiles(ab, config, creds)
        monkeypatch.setattr(applier, "find_provider", lambda *args: None)
        applier.apply(profiles)
    assert not any('cat > "$SUP"' in c[-1] for c in fake_env.openshell_calls())


def test_unreadable_confinement_stop_state_fails_closed(ab, fake_env, config, creds):
    applier = applier_with_shipped_profiles(ab, config, creds)
    applier.confinement_stops_path.parent.mkdir(parents=True, exist_ok=True)
    applier.confinement_stops_path.write_text("not JSON")
    before = len(fake_env.openshell_calls())
    with pytest.raises(ab.InstallerError, match="cannot read confinement stop state"):
        applier_with_shipped_profiles(ab, config, creds)
    assert len(fake_env.openshell_calls()) == before


@pytest.mark.parametrize("failed_step", ["saved-supervisor", "gateway-start"])
def test_failed_providerless_resume_keeps_confinement_hold(
        ab, fake_env, config, profiles, creds, monkeypatch, failed_step):
    applier_with_shipped_profiles(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"]["openclawConfig"]["tools.fs.workspaceOnly"] = False
    fake_env.set_openshell_state(state)
    retry = applier_with_shipped_profiles(ab, config, creds)
    monkeypatch.setattr(retry, "find_provider", lambda *args: None)
    original_cli = retry.cli
    marker = ("# SAW: check saved OpenClaw supervisor" if failed_step == "saved-supervisor"
              else 'cat > "$SUP"')
    def fail_resume(*args, **kwargs):
        if args[:2] == ("sandbox", "exec") and "notebook" in args and marker in args[-1]:
            raise ab.InstallerError("resume transport failed")
        return original_cli(*args, **kwargs)
    monkeypatch.setattr(retry, "cli", fail_resume)
    with pytest.raises(ab.InstallerError, match="resume transport failed"):
        retry.apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["agentStopped"] is True
    assert "default/notebook" in json.loads(retry.confinement_stops_path.read_text())
    # Readback is already true on the next process, but the saved stop still
    # requires an actual resume rather than an early return.
    recovered = applier_with_shipped_profiles(ab, config, creds)
    monkeypatch.setattr(recovered, "find_provider", lambda *args: None)
    recovered.apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["agentStopped"] is False
    assert "default/notebook" not in json.loads(recovered.confinement_stops_path.read_text())
