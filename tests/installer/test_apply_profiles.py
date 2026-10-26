"""Applying SAW-BOM profiles through the (fake) OpenShell CLI over mTLS."""

import json
import subprocess
from pathlib import Path

import pytest

from conftest import harness_files


@pytest.fixture
def profiles(ab, shipped_profile_files):
    return ab.parse_profiles(shipped_profile_files)


@pytest.fixture
def creds(ab, profiles, secrets_dir):
    return ab.resolve_credentials(profiles, secrets_dir)


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


def test_fresh_apply_creates_everything(ab, fake_env, config, profiles, creds):
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()

    # Local mTLS gateway only (the installer's admin identity): no OIDC login,
    # no token files, and the default `openshell` entry is not touched.
    assert state["gateways"] == [{"name": "saw-installer", "endpoint": "https://127.0.0.1:17670",
                                  "local": True, "roles": ["openshell-admin"]}]
    assert state["selected"] == "saw-installer"
    assert all("oidc" not in " ".join(c).lower() for c in fake_env.openshell_calls())

    assert state["workspaces"] == ["default", "cuda-dev"]
    assert set(state["providers"]) == {"default/nvidia", "default/brave", "cuda-dev/nvidia"}
    assert state["providers"]["default/nvidia"] == {
        "type": "nvidia", "credential": "NVIDIA_API_KEY=nvapi-TEST-KEY-123"}
    assert state["providers"]["default/brave"]["credential"] == "BRAVE_API_KEY=brave-TEST-KEY-456"

    # OpenShell 0.1.x has no inference routes: nothing calls `openshell inference`.
    assert not [c for c in fake_env.openshell_calls() if c[:1] == ["inference"]]

    # Enabled sandboxes only.
    assert set(state["sandboxes"]) == {"default/notebook", "cuda-dev/cuda-sandbox"}
    assert state["sandboxes"]["default/notebook"]["providers"] == ["nvidia"]
    assert applier.verify(profiles) == []


def test_openclaw_calls_the_native_endpoint_with_the_placeholder_key(
        ab, fake_env, config, profiles, creds):
    """0.1.x removed https://inference.local: OpenClaw calls NVIDIA directly,
    with the placeholder the sandbox holds in NVIDIA_API_KEY (expanded inside
    the sandbox, never by the installer)."""


def test_system_inference_skipped_without_default_workspace_model(ab, fake_env, config, profiles, creds):
    for _, ws in ab.enabled_workspaces(profiles):
        if ws.name == "default":
            for p in ws.providers:
                p.model = None
    make_applier(ab, config, creds).apply(profiles)
    onboard = next(c[-1] for c in fake_env.openshell_calls()
                   if c[:2] == ["sandbox", "exec"] and "onboard" in c[-1] and "notebook" in c)
    assert '--custom-base-url https://integrate.api.nvidia.com/v1 ' in onboard
    assert 'CUSTOM_API_KEY="$NVIDIA_API_KEY"' in onboard
    assert "inference.local" not in onboard and "nvapi-TEST-KEY-123" not in onboard


def test_nemoclaw_gets_the_provider_key_via_environment(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    calls = fake_env.other_calls("nemoclaw")
    assert len(calls) == 1
    assert calls[0]["args"][:2] == ["onboard", "--fresh"] and "cuda-sandbox" in calls[0]["args"]
    assert calls[0]["has_key"]


def test_keepalive_units_are_written_for_agent_sandboxes(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    tees = [c for c in fake_env.other_calls("sudo") if c["args"][:2] == ["-n", "tee"]]
    units = {c["args"][2]: c["stdin"] for c in tees}
    assert set(units) == {"/etc/systemd/system/openshell-sandbox-notebook.service",
                          "/etc/systemd/system/openshell-sandbox-cuda-sandbox.service"}
    cuda = units["/etc/systemd/system/openshell-sandbox-cuda-sandbox.service"]
    assert "--workspace cuda-dev" in cuda and "User=cloud-user" in cuda


def test_second_apply_is_idempotent(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    before = fake_env.openshell_state()
    make_applier(ab, config, creds).apply(profiles)
    after = fake_env.openshell_state()
    assert after["workspaces"] == before["workspaces"]
    assert after["providers"] == before["providers"]
    assert after["sandboxes"] == before["sandboxes"]
    creates = [c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "create"]]
    assert len(creates) == 2          # existing Ready sandboxes are not recreated
    # Live: on a reboot `nemoclaw onboard --fresh` refused the running gateway
    # (gateway.port.uncontested). A running sandbox is onboarded only once.
    assert len(fake_env.other_calls("nemoclaw")) == 1


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
    assert members == [["cuda-dev", "f3c1-owner-subject", "admin"],
                       ["default", "f3c1-owner-subject", "admin"]]
    # Re-running does not fail on the existing membership.
    make_applier(ab, config, creds, ownerSubject="f3c1-owner-subject").apply(profiles)


def test_no_owner_subject_fails_agent_apply(ab, fake_env, config, profiles, creds):
    with pytest.raises(ab.InstallerError, match="ownerSubject is required"):
        make_applier(ab, config, creds, ownerSubject="").apply(profiles)
    assert fake_env.openshell_state()["members"] == []


def test_owner_recreation_removes_stale_membership(ab, fake_env, config, profiles, creds, tmp_path):
    config = {**config, "prune": {"ledgerPath": str(tmp_path / "managed.json")}}
    make_applier(ab, config, creds, ownerSubject="old-subject").apply(profiles)
    make_applier(ab, config, creds, ownerSubject="new-subject").apply(profiles)
    assert fake_env.openshell_state()["members"] == [
        ["cuda-dev", "new-subject", "admin"], ["default", "new-subject", "admin"]]
    with pytest.raises(ab.InstallerError, match="ownerSubject is required"):
        make_applier(ab, config, creds, ownerSubject="").apply(profiles)
    assert fake_env.openshell_state()["members"] == []


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
    assert state["members"] == []
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


def test_provider_failure_stops_the_apply(ab, fake_env, config, profiles, creds):
    fake_env.deny("provider create")
    with pytest.raises(ab.InstallerError, match="provider create"):
        make_applier(ab, config, creds).apply(profiles)
    assert "sandbox create" not in cli_ops(fake_env)


def test_credentials_never_appear_in_logs(ab, fake_env, config, profiles, creds, capsys):
    make_applier(ab, config, creds).apply(profiles)
    out = capsys.readouterr().out
    assert "nvapi-TEST-KEY-123" not in out and "brave-TEST-KEY-456" not in out
    assert "--credential NVIDIA_API_KEY" in out      # the CLI reads the key from $NVIDIA_API_KEY


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
def fast_polls(ab, monkeypatch):
    monkeypatch.setattr(ab.ProfileApplier, "POLL_SECONDS", 0)


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


def test_recovered_sandbox_with_old_workload_api_mount_is_recreated(
        ab, fake_env, config, profiles, creds, fast_polls, monkeypatch):
    """Identity opt-out must inspect mounts even when an Error phase recovers."""
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"].update(phase="Error", after=[2, "Ready"])
    fake_env.set_openshell_state(state)
    monkeypatch.setattr(
        ab.ProfileApplier, "workload_api_mount_must_go",
        lambda self, ws, sb: ws.name == "default" and sb.name == "notebook")

    make_applier(ab, config, creds).apply(profiles)
    assert ["sandbox", "delete", "notebook"] in fake_env.openshell_calls()
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
    run = [i for i, c in enumerate(calls) if c[:2] == ["sandbox", "exec"] and "openclaw gateway run" in c[-1]]
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
    assert state["providers"]["default/brave"]["credential"] == "BRAVE_API_KEY=brave-TEST-KEY-456"
    assert applier.skipped == set()
    assert applier.verify(profiles) == []
    imports = [c for c in fake_env.openshell_calls() if c[:3] == ["provider", "profile", "import"]]
    assert len(imports) == 1 and "--workspace" not in imports[0]      # default workspace


def test_profile_is_imported_once_across_applies(ab, fake_env, config, profiles, creds):
    fake_env.without_profiles("brave")
    applier_with_shipped_profiles(ab, config, creds).apply(profiles)
    applier_with_shipped_profiles(ab, config, creds).apply(profiles)
    imports = [c for c in fake_env.openshell_calls() if c[:3] == ["provider", "profile", "import"]]
    assert len(imports) == 1


def test_no_import_when_the_gateway_has_the_profile(ab, fake_env, config, profiles, creds):
    """Governance on: the interceptor serves 'brave'; nothing is imported."""
    applier_with_shipped_profiles(ab, config, creds).apply(profiles)
    assert not [c for c in fake_env.openshell_calls() if c[:2] == ["provider", "profile"]]
    assert "default/brave" in fake_env.openshell_state()["providers"]


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


def test_verify_runs_openclaw_in_agent_sandboxes_only(ab, fake_env, config, profiles, creds):
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    before = len(fake_env.openshell_calls())
    assert applier.verify(profiles) == []
    checks = [c for c in fake_env.openshell_calls()[before:]
              if c[:2] == ["sandbox", "exec"] and c[-1] == "openclaw --version"]
    assert sorted(c[c.index("-n") + 1] for c in checks) == ["cuda-sandbox", "notebook"]


# -- the installer's mTLS identity is platform admin --------------------------

def cert_field(path, *args):
    return subprocess.run(["openssl", "x509", "-noout", *args, "-in", str(path)],
                          capture_output=True, text=True, check=True).stdout.strip()


def test_installer_uses_an_admin_client_certificate_under_rbac(ab, fake_env, config, profiles, creds):
    """Live: with OIDC on, the gateway's own local client certificate
    (OU=openshell-user) could not create workspaces. The installer issues
    CN=saw-installer, OU=openshell-admin from the gateway's CA."""
    fake_env.rbac()
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert state["gateways"] == [{"name": "saw-installer", "endpoint": "https://127.0.0.1:17670",
                                  "local": True, "roles": ["openshell-admin"]}]
    assert state["selected"] == "saw-installer"
    assert "cuda-dev" in state["workspaces"]
    crt = fake_env.admin_cert()
    subject = cert_field(crt, "-subject", "-nameopt", "sep_multiline")
    assert "OU=openshell-admin" in subject and "CN=saw-installer" in subject
    ca = fake_env.home / ".local/state/openshell/tls/ca.crt"
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
                                  "providers": {}, "sandboxes": {}, "inference": {}, "system_inference": None})
    applier = make_applier(ab, config, creds)
    with pytest.raises(ab.InstallerError, match="openshell-admin"):
        applier.apply_workspace(next(ws for _, ws in ab.enabled_workspaces(profiles) if ws.name == "cuda-dev"))


def test_admin_certificate_is_kept_while_valid_and_reissued_for_a_new_ca(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).register_gateway()
    crt = fake_env.admin_cert()
    first = cert_field(crt, "-serial")
    make_applier(ab, config, creds).register_gateway()
    assert cert_field(crt, "-serial") == first                       # reused on every boot
    ca_dir = fake_env.home / ".local/state/openshell/tls"          # gateway CA rotated
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", str(ca_dir / "ca.key"), "-out", str(ca_dir / "ca.crt"),
                    "-subj", "/O=openshell/CN=openshell-ca", "-days", "30"], check=True, capture_output=True)
    make_applier(ab, config, creds).register_gateway()
    assert cert_field(crt, "-serial") != first
    assert subprocess.run(["openssl", "verify", "-CAfile", str(ca_dir / "ca.crt"), str(crt)],
                          capture_output=True).returncode == 0


def test_missing_gateway_ca_is_a_clear_error(ab, fake_env, config, profiles, creds):
    (fake_env.home / ".local/state/openshell/tls/ca.key").unlink()
    with pytest.raises(ab.InstallerError, match="gateway CA not found"):
        make_applier(ab, config, creds).register_gateway()


def test_key_never_appears_in_argv_or_logs(ab, fake_env, config, profiles, creds, capsys):
    make_applier(ab, config, creds).register_gateway()
    key = (fake_env.admin_cert().parent / "tls.key").read_text()
    body = "".join(l for l in key.splitlines() if not l.startswith("-----"))
    assert body[:40] not in capsys.readouterr().err


def test_full_apply_mounts_the_harness_into_notebook(ab, fake_env, config, profiles, creds):
    """A full apply fills the notebook's harness volume, creates the sandbox
    with it mounted read-only at /sandbox/harness, points OpenClaw at it, and
    never copies bundle files with `sandbox exec`."""
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
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
    # The bundle and its native plugin, each enabled (2026.9.x keeps them off).
    assert "openclaw plugins enable ds-default --accept-capabilities" in scripts
    assert "openclaw plugins enable saw-echo --accept-capabilities" in scripts
    # The bundle's MCP server, re-declared where OpenClaw expands ${VAR}.
    cfg = fake_env.openshell_state()["sandboxes"]["default/notebook"]["openclawConfig"]
    echo = cfg["mcp.servers.saw-mcp-echo"]
    assert echo["args"] == ["/sandbox/harness/mcp/echo-server.mjs"]
    assert echo["env"]["NODE_EXTRA_CA_CERTS"] == "${NODE_EXTRA_CA_CERTS}"
    assert applier.verify(profiles) == []


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
        "sandboxes": {}, "inference": {}, "system_inference": None})
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
