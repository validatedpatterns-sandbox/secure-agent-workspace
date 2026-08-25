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


def test_parse_profiles_gpu_field_parsed(tmp_path):
    _write_profile(
        tmp_path,
        providers_yaml={"spec": {"providers": [
            {"name": "nvidia", "type": "nvidia", "nemoclawProvider": "build",
             "credentialSecret": "inference", "credentialSecretKey": "api_key"},
        ]}},
        sandbox_yaml={"spec": {"sandboxes": [
            {"name": "cuda-sandbox", "type": "nemoclaw", "enabled": True,
             "providers": ["nvidia"], "gpu": {"enabled": True, "count": 2}},
        ]}},
    )
    profiles = parse_profiles(tmp_path)
    sb = profiles[0].workspaces[0].sandboxes[0]
    assert sb.gpu_enabled is True
    assert sb.gpu_count == 2


def test_parse_profiles_gpu_field_defaults_when_absent(tmp_path):
    # A sandbox with no `gpu:` block at all (the common case) must default
    # to disabled — GPU is opt-in per sandbox, not implicit.
    _write_profile(
        tmp_path,
        providers_yaml={"spec": {"providers": [
            {"name": "nvidia", "type": "nvidia"},
        ]}},
        sandbox_yaml={"spec": {"sandboxes": [
            {"name": "notebook", "type": "openclaw", "enabled": True,
             "providers": ["nvidia"]},
        ]}},
    )
    profiles = parse_profiles(tmp_path)
    sb = profiles[0].workspaces[0].sandboxes[0]
    assert sb.gpu_enabled is False
    assert sb.gpu_count == 1


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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
