"""The credential env var is read from the provider's profile
(credentials[0].env_vars[0]), falling back to the built-in PROVIDER_CRED_MAP.

This lets a profile-backed type (github, slack, gmail, ...) be used as a BOM
provider without a per-type installer edit. For the shipped built-ins the
profile and the map agree, so behaviour is unchanged.
"""
import pytest

GH_PROFILE = (
    "id: github\n"
    "credentials:\n"
    "  - name: api_token\n"
    "    env_vars: [GITHUB_TOKEN, GH_TOKEN]\n"
    "endpoints:\n"
    "  - host: api.github.com\n"
    "    port: 443\n"
)


def test_env_var_comes_from_the_profile_then_falls_back_to_the_map(ab):
    # Profile-backed, not in PROVIDER_CRED_MAP: use its first env var.
    assert ab.credential_env_name("github", {"github": GH_PROFILE}) == "GITHUB_TOKEN"
    # No profile: fall back to the built-in map (unchanged behaviour).
    assert ab.credential_env_name("openai", {}) == "OPENAI_API_KEY"
    # Unknown everywhere: empty (caller warns/skips).
    assert ab.credential_env_name("mystery", {}) == ""
    assert ab.profile_credential_env("") == ""
    assert ab.profile_credential_env("id: x\ncredentials: []\n") == ""


def _github_profiles(ab):
    provider = ab.Provider(name="gh", type="github",
                           credential_secret="gh", credential_secret_key="token")
    sandbox = ab.Sandbox(name="tools", type="generic", providers=[provider.name])
    workspace = ab.Workspace(name="default", providers=[provider], sandboxes=[sandbox])
    return [ab.Profile(name="test", workspaces=[workspace])]


def test_profile_backed_type_passes_validation_only_when_its_profile_ships(ab):
    profiles = _github_profiles(ab)
    # Accepted when the profile ships with the chart.
    ab.validate_profiles(profiles, known_profiles={"github"})
    # Rejected when neither a built-in type nor a shipped profile exists.
    with pytest.raises(ab.InstallerError, match="unsupported type 'github'"):
        ab.validate_profiles(profiles)


def test_github_provider_is_created_with_the_profile_env_var(ab, fake_env, config):
    applier = ab.ProfileApplier(ab.Shell(), config, {"default": {"gh": "ghp-test"}},
                                provider_profile_docs={"github": GH_PROFILE})
    applier.apply(_github_profiles(ab))
    created = fake_env.openshell_state()["providers"]["default/gh"]
    assert created["type"] == "github"
    # The installer passed the credential through GITHUB_TOKEN (from the
    # profile), not a hardcoded map entry (github has none).
    assert created["credential"] == "GITHUB_TOKEN=ghp-test"
