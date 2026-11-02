"""Credential mode contracts and migrations, with real CLI subprocesses."""
import json
from pathlib import Path

import pytest

from conftest import TEST_PROXY


def direct(config):
    return {**config, "credentialMode": "direct",
            "credentialProxy": {"url": "", "markerPrefix": "saw-cred", "secrets": [], "keyGeneration": 1}}


def small_profile(ab, **provider):
    p = ab.Provider(name="nvidia", type="nvidia", credential_secret="inference", **provider)
    ws = ab.Workspace(name="default", providers=[p], sandboxes=[
        ab.Sandbox(name="tools", type="generic", providers=["nvidia"])])
    return [ab.Profile(name="mode-test", workspaces=[ws])], ws, p


@pytest.mark.parametrize("credential_mode", ["direct"], indirect=True)
def test_direct_inputs_resolve_full_keys_and_need_no_proxy_ca(ab, inputs_dir):
    _, cfg, _, creds, _ = ab.Inputs(inputs_dir).load()
    assert cfg["credentialMode"] == cfg["bootedCredentialMode"] == "direct"
    assert creds["default"]["nvidia"] == "test-direct-inference-key"
    assert not (inputs_dir / "proxy-ca/ca.crt").exists()
    assert ab.main(["validate", "--inputs", str(inputs_dir)]) == 0


def test_direct_named_credentials_and_metadata_only_restart_hint(ab, config, secrets_dir):
    profiles, _, p = small_profile(ab, credentials_spec={
        "api_key": {"secretKey": "primary"}, "app_secret": {"secretKey": "secondary"}})
    for name, value in {"primary": "primary-sentinel", "secondary": "secondary-sentinel"}.items():
        (secrets_dir / "inference" / name).write_text(value)
    creds = ab.resolve_credentials(profiles, secrets_dir, direct(config)["credentialProxy"], "direct")
    assert creds == {"default": {"nvidia": "primary-sentinel"}}
    assert p.credential_values == {"api_key": "primary-sentinel", "app_secret": "secondary-sentinel"}
    (secrets_dir / "inference/secondary").unlink()
    with pytest.raises(ab.InstallerError, match="not found") as missing:
        ab.resolve_credentials(profiles, secrets_dir, {}, "direct")
    assert "saw-restart-pending" not in str(missing.value)
    (secrets_dir / "inference/primary").unlink()
    with pytest.raises(ab.InstallerError, match="saw-restart-pending"):
        ab.resolve_credentials(profiles, secrets_dir, {}, "direct")


@pytest.mark.parametrize("url", ["http://models.example.test:8000/v1", "https://models.example.test:8443/v1"])
def test_direct_allows_custom_endpoints(ab, config, secrets_dir, url):
    profiles, ws, p = small_profile(ab)
    (secrets_dir / "inference/api_key").write_text("direct-sentinel")
    sb = ws.sandboxes[0]
    sb.inference = {"providerRef": "nvidia", "model": "test-model", "baseUrl": url}
    ab.resolve_credentials(profiles, secrets_dir, {}, "direct")
    assert sb.inference_values["baseUrl"] == url
    (secrets_dir / "inference/api_key").unlink()
    if url.startswith("https:"):
        with pytest.raises(ab.InstallerError, match="port 443 only"):
            ab.resolve_credentials(profiles, secrets_dir, TEST_PROXY)


@pytest.mark.parametrize("key", ["api_key", "client_id", "client_secret", "refresh_token", "named_key"])
def test_direct_refuses_credential_secret_key_refs(ab, secrets_dir, key):
    profiles, ws, p = small_profile(ab, refresh_strategy="oauth2_refresh_token")
    base = secrets_dir / "inference"
    for name in ("api_key", "client_id", "client_secret", "refresh_token", "named_key"):
        (base / name).write_text("must-never-reach-argv")
    p.credentials_spec = {"api_key": {"secretKey": "api_key"}, "other": {"secretKey": "named_key"}}
    ws.sandboxes[0].inference = {"providerRef": "nvidia", "model": {
        "secretKeyRef": {"name": "inference", "key": key}}}
    with pytest.raises(ab.InstallerError, match="refusing to expose"):
        ab.resolve_credentials(profiles, secrets_dir, {}, "direct")


@pytest.mark.parametrize("command", ["install", "apply", "validate"])
@pytest.mark.parametrize("credential_mode", ["proxy", "direct"], indirect=True)
def test_mode_mismatch_refuses_before_mutation(ab, inputs_dir, tmp_path, command, credential_mode):
    path = inputs_dir / "installer/config.json"
    cfg = json.loads(path.read_text())
    cfg = direct(cfg) if credential_mode == "proxy" else {**cfg, "credentialMode": "proxy", "credentialProxy": TEST_PROXY}
    path.write_text(json.dumps(cfg))
    state = tmp_path / "state"
    argv = [command, "--inputs", str(inputs_dir)]
    if command != "validate":
        argv += ["--state-dir", str(state)]
    assert ab.main(argv) == 1
    assert not state.exists() or {p.name for p in state.iterdir()} == {"status.json"}
    if state.exists():
        status = json.loads((state / "status.json").read_text())[command]
        assert status["credentialMode"] == {"configured": cfg["credentialMode"],
                                              "booted": credential_mode, "applied": None}
        assert "saw-restart-pending" in status["message"]


@pytest.mark.parametrize("before,after", [("proxy", "direct"), ("direct", "proxy")])
def test_mode_flips_use_volume_archive_before_updating_keys(ab, fake_env, config, tmp_path, before, after):
    profiles, ws, p = small_profile(ab)
    ledger = {"ledgerPath": str(tmp_path / "user/managed.json")}
    configs = {"proxy": config, "direct": direct(config)}
    first = {**configs[before], "prune": ledger}
    ab.ProfileApplier(ab.Shell(), first, {"default": {"nvidia": "old-credential"}}).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/tools"]["files"] = {"mode-proof.txt": "preserve-this-proof"}
    state["sandboxes"]["default/tools"]["execBroken"] = True
    fake_env.set_openshell_state(state)
    start = len(fake_env.openshell_calls())
    changed = {**configs[after], "prune": ledger, "credentialMigration": {"from": before, "to": after}}
    applier = ab.ProfileApplier(ab.Shell(), changed, {"default": {"nvidia": "new-credential"}})
    applier.apply(profiles)
    calls = fake_env.openshell_calls()[start:]
    deletion = next(i for i, c in enumerate(calls) if c[:2] == ["sandbox", "delete"])
    update = next(i for i, c in enumerate(calls) if c[:2] == ["provider", "update"])
    assert deletion < update
    assert any(c[0] == "unshare" for c in fake_env.podman_calls())
    assert not any(c[:2] == ["sandbox", "download"] for c in calls)
    assert fake_env.openshell_state()["sandboxes"]["default/tools"]["files"] == {
        "mode-proof.txt": "preserve-this-proof"}
    assert applier.migrations == {}


def test_provider_update_failure_is_fatal_during_migration(ab, fake_env, config, tmp_path):
    profiles, _, _ = small_profile(ab)
    cfg = {**config, "prune": {"ledgerPath": str(tmp_path / "managed.json")}}
    ab.ProfileApplier(ab.Shell(), cfg, {"default": {"nvidia": "old-sentinel"}}).apply(profiles)
    fake_env.deny("provider update")
    cfg = {**direct(cfg), "credentialMigration": {"from": "proxy", "to": "direct"}}
    with pytest.raises(ab.InstallerError, match="credential migration: could not update"):
        ab.ProfileApplier(ab.Shell(), cfg, {"default": {"nvidia": "new-sentinel"}}).apply(profiles)
    assert json.loads((tmp_path / "sandbox-migrations.json").read_text())["default/tools"]["via"] == "volume"
    assert "default/tools" not in fake_env.openshell_state()["sandboxes"]


@pytest.mark.parametrize("prior", ["status", "ca", "legacy"])
def test_prior_mode_inference_and_rotation_state(ab, config, fake_env, tmp_path, prior):
    state_dir, etc = tmp_path / "state", tmp_path / "etc"
    state_dir.mkdir(); etc.mkdir()
    if prior == "status":
        ab.write_json_atomic(state_dir / "status.json", {"install": {"credentialProxy": {"url": "http://old:3128"}}})
    if prior == "legacy":
        (state_dir / "installed.json").write_text("{}")
    if prior == "ca":
        (etc / "credential-proxy-ca.pem").write_text("old public CA")
    cfg = direct(config) if prior != "legacy" else config
    state = ab.prepare_credential_mode(state_dir, cfg, fake_env.home, etc)
    assert state["applied"] == ("direct" if prior == "legacy" else "proxy")
    assert cfg["credentialMigration"] == state["transition"]
    if prior == "legacy":
        assert state["rotationRequired"] == ["inference/api_key", "web-search/api_key"]
    assert (state_dir / "credential-mode.json").stat().st_mode & 0o777 == 0o600


def test_transition_cleanup_and_key_generation_acknowledgement(ab, fake_env, config, tmp_path):
    state_dir, etc = tmp_path / "state", tmp_path / "etc"
    user = state_dir / "user"
    user.mkdir(parents=True); etc.mkdir()
    ab.write_json_atomic(state_dir / "credential-mode.json", {
        "applied": "proxy", "transition": None, "exposed": [], "keyGeneration": 1})
    refresh = user / "refresh.json"; refresh.write_text('{"old": "digest"}')
    public_cas = [etc / "credential-proxy-ca.pem", fake_env.home / ".config/openshell/credential-proxy-ca.pem"]
    for path in public_cas:
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text("old public CA")
    profiles, _, _ = small_profile(ab, refresh_strategy="oauth2_refresh_token")
    cfg = direct(config)
    state = ab.prepare_credential_mode(state_dir, cfg, fake_env.home, etc)
    assert not refresh.exists() and all(p.exists() for p in public_cas)
    ab.write_json_atomic(user / "sandbox-migrations.json", {"default/tools": {"pending": True}})
    with pytest.raises(ab.InstallerError, match="pending sandbox restores"):
        ab.finish_credential_mode(state_dir, cfg, state, profiles, fake_env.home, etc)
    assert all(p.exists() for p in public_cas)
    (user / "sandbox-migrations.json").write_text("{}")
    ab.finish_credential_mode(state_dir, cfg, state, profiles, fake_env.home, etc)
    assert all(not p.exists() for p in public_cas)
    assert state["exposed"] == ["inference/api_key", "inference/client_id", "inference/client_secret", "inference/refresh_token"]
    nemoclaw = fake_env.home / ".nemoclaw/credentials.json"
    nemoclaw.parent.mkdir(); nemoclaw.write_text("old key")
    cfg = {**config, "credentialMode": "proxy"}
    state = ab.prepare_credential_mode(state_dir, cfg, fake_env.home, etc)
    assert not nemoclaw.exists() and state["rotationRequired"] == state["exposed"]
    ab.finish_credential_mode(state_dir, cfg, state, profiles, fake_env.home, etc)
    assert ab.prepare_credential_mode(state_dir, cfg, fake_env.home, etc)["rotationRequired"]
    cfg["credentialProxy"] = {**cfg["credentialProxy"], "keyGeneration": 2}
    assert "rotationRequired" not in ab.prepare_credential_mode(state_dir, cfg, fake_env.home, etc)


def test_proxy_wiring_formula_is_compatible(ab, config):
    assert ab.ProfileApplier(ab.Shell(), config, {}).wiring_label == "2512abc6923b877e"


def test_static_token_fallback_still_guards_refresh_material_refs(ab, secrets_dir):
    profiles, ws, p = small_profile(ab, refresh_strategy="oauth2_refresh_token")
    (secrets_dir / "inference/api_key").write_text("static-token-sentinel")
    (secrets_dir / "inference/client_secret").write_text("partial-refresh-secret")
    ws.sandboxes[0].inference = {"providerRef": "nvidia", "model": {
        "secretKeyRef": {"name": "inference", "key": "client_secret"}}}
    with pytest.raises(ab.InstallerError, match="refusing to expose"):
        ab.resolve_credentials(profiles, secrets_dir, {}, "direct")


def test_fresh_vm_does_not_require_rotation_even_with_prebooted_gateway_tls(ab, config, fake_env, tmp_path):
    state = ab.prepare_credential_mode(tmp_path / "state", config, fake_env.home, tmp_path / "etc")
    assert state["applied"] == "proxy" and not state["transition"]
    assert "rotationRequired" not in state


def test_reversing_an_interrupted_direct_migration_still_requires_rotation(ab, config, fake_env, tmp_path):
    state_dir = tmp_path / "state"
    ab.write_json_atomic(state_dir / "credential-mode.json", {
        "applied": "proxy", "transition": {"from": "proxy", "to": "direct"},
        "exposed": ["inference/api_key"], "keyGeneration": 1})
    state = ab.prepare_credential_mode(state_dir, config, fake_env.home, tmp_path / "etc")
    assert state["rotationRequired"] == ["inference/api_key"]
    assert config["credentialMigration"] == {"from": "direct", "to": "proxy"}


@pytest.mark.parametrize("credential_mode", ["proxy", "direct"], indirect=True)
def test_mode_fallback_uses_credentials_and_ignores_extra_metadata(ab, inputs_dir, credential_mode):
    for p in (inputs_dir / "proxy-ca").iterdir():
        p.unlink()
    (inputs_dir / "secrets/inference/cuda_model").write_text("model-metadata")
    _, cfg, _, _, _ = ab.Inputs(inputs_dir).load()
    assert cfg["bootedCredentialMode"] == credential_mode


@pytest.mark.parametrize("mode,proxy,error", [
    ("invalid", TEST_PROXY, "credentialMode"),
    ("proxy", {"url": "", "markerPrefix": "saw-cred", "secrets": []}, "requires credentialProxy.url"),
    ("direct", TEST_PROXY, "empty proxy url and no bindings"),
    ("proxy", {**TEST_PROXY, "keyGeneration": True}, "positive integer"),
])
def test_config_refuses_invalid_mode_contract(ab, tmp_path, mode, proxy, error):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"vmName": "test", "credentialMode": mode, "credentialProxy": proxy}))
    with pytest.raises(ab.InstallerError, match=error):
        ab.load_config(path)


@pytest.mark.parametrize("advertises", [False, True])
def test_direct_apf_refresh_requires_live_gateway_metadata(ab, config, fake_env, advertises):
    profiles, ws, p = small_profile(ab, refresh_strategy="oauth2_refresh_token")
    cfg = {**direct(config), "governanceEngine": "apf"}
    a = ab.ProfileApplier(ab.Shell(), cfg, {})
    a.catalogs["default"] = {"nvidia": {"integrate.api.nvidia.com"}}
    credential = {"name": "api_key", "source": {"kind": "oauth2"}}
    if advertises:
        credential["refresh"] = {"strategy": "oauth2_refresh_token"}
    a.catalog_details["default"] = {"nvidia": {"credentials": [credential]}}
    if advertises:
        a.preflight(profiles)
    else:
        with pytest.raises(ab.InstallerError, match="APF does not advertise"):
            a.preflight(profiles)
    assert fake_env.openshell_calls() == []
