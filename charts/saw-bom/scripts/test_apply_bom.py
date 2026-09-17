"""Unit tests for the pure-Python pieces of apply_bom.py — profile parsing,
credential resolution, and provider selection/validation. None of these need
a live gateway VM or cluster.

Run with:
    pip install pytest pyyaml
    pytest charts/saw-bom/scripts/test_apply_bom.py -v
"""
import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.dirname(__file__))

from apply_bom import (  # noqa: E402
    Provider,
    Sandbox,
    Shell,
    Workspace,
    check_provider_type_mismatch,
    find_provider,
    parse_profiles,
    resolve_configured_type,
    resolve_credential,
)


def _write_profile(root, profile="data-science", workspace="default",
                    workspace_yaml=None, providers_yaml=None, sandbox_yaml=None):
    """Write a minimal BOM profile directory tree under `root`."""
    ws_dir = root / profile / workspace
    ws_dir.mkdir(parents=True, exist_ok=True)

    default_workspace_yaml = {
        "apiVersion": "saw.redhat.com/v1alpha1",
        "kind": "Workspace",
        "metadata": {"name": workspace},
        "spec": {"enabled": True},
    }
    (ws_dir / "workspace.yaml").write_text(
        yaml.safe_dump(workspace_yaml or default_workspace_yaml))

    if providers_yaml is not None:
        (ws_dir / "providers.yaml").write_text(yaml.safe_dump(providers_yaml))
    if sandbox_yaml is not None:
        (ws_dir / "sandbox.yaml").write_text(yaml.safe_dump(sandbox_yaml))

    return ws_dir


# ---------------------------------------------------------------------------
# parse_profiles()
# ---------------------------------------------------------------------------

def test_parse_profiles_basic(tmp_path):
    _write_profile(
        tmp_path,
        providers_yaml={"spec": {"providers": [
            {"name": "nvidia", "type": "nvidia", "nemoclawProvider": "build",
             "credentialSecret": "inference", "credentialSecretKey": "api_key"},
        ]}},
        sandbox_yaml={"spec": {"sandboxes": [
            {"name": "notebook", "type": "openclaw", "enabled": True,
             "providers": ["nvidia"]},
        ]}},
    )
    profiles = parse_profiles(tmp_path)
    assert len(profiles) == 1
    ws = profiles[0].workspaces[0]
    assert ws.name == "default"
    assert [p.name for p in ws.providers] == ["nvidia"]
    assert ws.providers[0].nemoclaw_provider == "build"
    assert [sb.name for sb in ws.sandboxes] == ["notebook"]
    assert ws.sandboxes[0].providers == ["nvidia"]


def test_parse_profiles_skips_workspace_dir_missing_workspace_yaml(tmp_path):
    # A directory with no workspace.yaml at all should be skipped, not crash.
    bogus_dir = tmp_path / "data-science" / "not-a-workspace"
    bogus_dir.mkdir(parents=True)
    (bogus_dir / "sandbox.yaml").write_text("spec:\n  sandboxes: []\n")
    profiles = parse_profiles(tmp_path)
    assert profiles == []


def test_parse_profiles_no_profiles_dir_entries(tmp_path):
    assert parse_profiles(tmp_path) == []


def test_parse_profiles_disabled_workspace_still_parsed(tmp_path):
    _write_profile(
        tmp_path,
        workspace_yaml={"metadata": {"name": "cuda-dev"},
                         "spec": {"enabled": False}},
        providers_yaml={"spec": {"providers": []}},
        sandbox_yaml={"spec": {"sandboxes": []}},
    )
    profiles = parse_profiles(tmp_path)
    ws = profiles[0].workspaces[0]
    assert ws.enabled is False


# ---------------------------------------------------------------------------
# resolve_credential()
# ---------------------------------------------------------------------------

def test_resolve_credential_prefers_provider_specific_env(monkeypatch):
    monkeypatch.setenv("PROV_NVIDIA_KEY", "specific-key")
    monkeypatch.setenv("NVIDIA_API_KEY", "generic-key")
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_credential(p) == "specific-key"


def test_resolve_credential_falls_back_to_type_map(monkeypatch):
    monkeypatch.delenv("PROV_NVIDIA_KEY", raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", "generic-key")
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_credential(p) == "generic-key"


def test_resolve_credential_none_when_unset(monkeypatch):
    monkeypatch.delenv("PROV_NVIDIA_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_credential(p) is None


def test_resolve_credential_handles_hyphenated_names(monkeypatch):
    monkeypatch.setenv("PROV_GOOGLE_VERTEX_AI_KEY", "vertex-key")
    p = Provider(name="google-vertex-ai", type="google-vertex-ai")
    assert resolve_credential(p) == "vertex-key"


# ---------------------------------------------------------------------------
# find_provider() — regression test for the ws.providers[0] bug (finding #5):
# reordering providers.yaml must never change which provider a sandbox that
# declares its own `providers:` list actually gets.
# ---------------------------------------------------------------------------

def _ws_with_providers(*names_and_types):
    ws = Workspace(name="default")
    for name, ptype in names_and_types:
        ws.providers.append(Provider(name=name, type=ptype))
    return ws


def test_find_provider_selects_by_declared_name_not_index():
    ws = _ws_with_providers(("brave", "brave"), ("nvidia", "nvidia"))
    prov = find_provider(ws, ["nvidia"])
    assert prov.name == "nvidia"


def test_find_provider_order_independent():
    # Same providers, opposite order — result must be identical.
    ws_a = _ws_with_providers(("nvidia", "nvidia"), ("brave", "brave"))
    ws_b = _ws_with_providers(("brave", "brave"), ("nvidia", "nvidia"))
    assert find_provider(ws_a, ["nvidia"]).name == "nvidia"
    assert find_provider(ws_b, ["nvidia"]).name == "nvidia"


def test_find_provider_falls_back_to_first_when_no_names_declared():
    ws = _ws_with_providers(("nvidia", "nvidia"))
    assert find_provider(ws, []).name == "nvidia"
    assert find_provider(ws, None).name == "nvidia"


def test_find_provider_falls_back_when_declared_name_not_found():
    ws = _ws_with_providers(("nvidia", "nvidia"))
    prov = find_provider(ws, ["does-not-exist"])
    assert prov.name == "nvidia"  # falls back to index 0, not None


def test_find_provider_none_when_workspace_has_no_providers():
    ws = Workspace(name="default")
    assert find_provider(ws, ["nvidia"]) is None


# ---------------------------------------------------------------------------
# check_provider_type_mismatch() — regression test for finding #14.
# ---------------------------------------------------------------------------

def test_provider_type_mismatch_none_when_no_configured_type(monkeypatch):
    monkeypatch.delenv("PROV_NVIDIA_TYPE", raising=False)
    p = Provider(name="nvidia", type="nvidia", nemoclaw_provider="build")
    assert check_provider_type_mismatch(p) is None


def test_provider_type_mismatch_accepts_nemoclaw_alias(monkeypatch):
    # values-secret.yaml.template documents NVIDIA's provider identifier as
    # "build", distinct from the OpenShell provider type "nvidia" — this
    # must NOT be flagged as a mismatch for the bundled default profile.
    monkeypatch.setenv("PROV_NVIDIA_TYPE", "build")
    p = Provider(name="nvidia", type="nvidia", nemoclaw_provider="build")
    assert check_provider_type_mismatch(p) is None


def test_provider_type_mismatch_detects_real_mismatch(monkeypatch):
    monkeypatch.setenv("PROV_NVIDIA_TYPE", "gemini")
    p = Provider(name="nvidia", type="nvidia", nemoclaw_provider="build")
    msg = check_provider_type_mismatch(p)
    assert msg is not None
    assert "gemini" in msg


def test_resolve_configured_type_reads_env(monkeypatch):
    monkeypatch.setenv("PROV_NVIDIA_TYPE", "build")
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_configured_type(p) == "build"


def test_resolve_configured_type_none_when_unset(monkeypatch):
    monkeypatch.delenv("PROV_NVIDIA_TYPE", raising=False)
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_configured_type(p) is None


# ---------------------------------------------------------------------------
# Provider.url — custom endpoint URL propagation
# ---------------------------------------------------------------------------

def test_provider_url_defaults_to_empty():
    p = Provider(name="custom", type="custom")
    assert p.url == ""


def test_parse_profiles_reads_url_from_yaml(tmp_path):
    _write_profile(
        tmp_path,
        providers_yaml={"spec": {"providers": [
            {"name": "custom", "type": "custom",
             "credentialSecret": "inference", "credentialSecretKey": "api_key",
             "url": "https://vllm.example.com/v1"},
        ]}},
    )
    profiles = parse_profiles(tmp_path)
    p = profiles[0].workspaces[0].providers[0]
    assert p.url == "https://vllm.example.com/v1"


def test_parse_profiles_reads_url_from_env_when_urlsecretkey_declared(monkeypatch, tmp_path):
    monkeypatch.setenv("PROV_CUSTOM_URL", "https://env-vllm.example.com/v1")
    _write_profile(
        tmp_path,
        providers_yaml={"spec": {"providers": [
            {"name": "custom", "type": "custom",
             "credentialSecret": "inference", "credentialSecretKey": "api_key",
             "urlSecretKey": "url"},
        ]}},
    )
    profiles = parse_profiles(tmp_path)
    p = profiles[0].workspaces[0].providers[0]
    assert p.url == "https://env-vllm.example.com/v1"


def test_parse_profiles_no_url_from_env_without_urlsecretkey(monkeypatch, tmp_path):
    # Providers without urlSecretKey must NOT pick up PROV_{name}_URL even if
    # the env var is set — prevents the vLLM URL leaking onto nvidia providers.
    monkeypatch.setenv("PROV_NVIDIA_URL", "https://should-not-apply.example.com/v1")
    _write_profile(
        tmp_path,
        providers_yaml={"spec": {"providers": [
            {"name": "nvidia", "type": "nvidia",
             "credentialSecret": "inference", "credentialSecretKey": "api_key"},
        ]}},
    )
    profiles = parse_profiles(tmp_path)
    p = profiles[0].workspaces[0].providers[0]
    assert p.url == ""


def test_parse_profiles_yaml_url_takes_precedence_over_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PROV_CUSTOM_URL", "https://env-vllm.example.com/v1")
    _write_profile(
        tmp_path,
        providers_yaml={"spec": {"providers": [
            {"name": "custom", "type": "custom",
             "credentialSecret": "inference", "credentialSecretKey": "api_key",
             "urlSecretKey": "url",
             "url": "https://yaml-vllm.example.com/v1"},
        ]}},
    )
    profiles = parse_profiles(tmp_path)
    p = profiles[0].workspaces[0].providers[0]
    assert p.url == "https://yaml-vllm.example.com/v1"


def test_create_provider_includes_config_base_url_when_url_set():
    commands = []

    class FakeShell:
        dry_run = False
        def run(self, cmd, **_):
            commands.append(cmd)
            return 0, "", ""

    from apply_bom import GatewaySetup, WorkspaceDeployer
    sh = FakeShell()
    gw = GatewaySetup(sh, "openshell", "openshell-local")
    deployer = WorkspaceDeployer(sh, gw)

    p = Provider(name="custom", type="custom", url="https://vllm.example.com/v1")
    deployer.create_provider(p, credential="tok123")

    assert commands, "expected at least one command"
    cmd = commands[0]
    assert "--config" in cmd
    idx = cmd.index("--config")
    assert cmd[idx + 1] == "base_url=https://vllm.example.com/v1"


def test_create_provider_omits_config_when_url_empty():
    commands = []

    class FakeShell:
        dry_run = False
        def run(self, cmd, **_):
            commands.append(cmd)
            return 0, "", ""

    from apply_bom import GatewaySetup, WorkspaceDeployer
    sh = FakeShell()
    gw = GatewaySetup(sh, "openshell", "openshell-local")
    deployer = WorkspaceDeployer(sh, gw)

    p = Provider(name="nvidia", type="nvidia")
    deployer.create_provider(p, credential="apikey")

    cmd = commands[0]
    assert "--config" not in cmd


def test_onboard_nemoclaw_sets_inference_base_url_when_url_set():
    envs_captured = []

    class FakeShell:
        dry_run = False
        def run(self, cmd, env=None, **_):
            envs_captured.append(env or {})
            return 0, "", ""

    from apply_bom import GatewaySetup, WorkspaceDeployer
    sh = FakeShell()
    gw = GatewaySetup(sh, "openshell", "openshell-local")
    deployer = WorkspaceDeployer(sh, gw)

    p = Provider(name="custom", type="custom", url="https://vllm.example.com/v1")
    sb = Sandbox(name="test-sb", type="nemoclaw", agent="openclaw")
    deployer.onboard_nemoclaw(sb, p, credential="tok")

    assert any("NEMOCLAW_INFERENCE_BASE_URL" in e for e in envs_captured), (
        "expected NEMOCLAW_INFERENCE_BASE_URL in env passed to nemoclaw onboard"
    )
    for e in envs_captured:
        if "NEMOCLAW_INFERENCE_BASE_URL" in e:
            assert e["NEMOCLAW_INFERENCE_BASE_URL"] == "https://vllm.example.com/v1"


def test_onboard_nemoclaw_omits_inference_base_url_when_url_empty():
    envs_captured = []

    class FakeShell:
        dry_run = False
        def run(self, cmd, env=None, **_):
            envs_captured.append(env or {})
            return 0, "", ""

    from apply_bom import GatewaySetup, WorkspaceDeployer
    sh = FakeShell()
    gw = GatewaySetup(sh, "openshell", "openshell-local")
    deployer = WorkspaceDeployer(sh, gw)

    p = Provider(name="nvidia", type="nvidia")
    sb = Sandbox(name="test-sb", type="nemoclaw", agent="openclaw")
    deployer.onboard_nemoclaw(sb, p, credential="apikey")

    assert all("NEMOCLAW_INFERENCE_BASE_URL" not in e for e in envs_captured)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
