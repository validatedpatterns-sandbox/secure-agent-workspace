"""A custom OpenAI-compatible endpoint (vLLM, Ollama, ...) through OpenShell's
OpenShell 0.1.x: an `openai` provider with OPENAI_BASE_URL, and OpenClaw
onboarded against that endpoint itself (no inference routes, no
https://inference.local)."""
from conftest import TEST_PROXY

import shlex
import pytest

from conftest import profile_files

URL = "https://vllm.models.svc.cluster.local/v1"
MODEL = "meta-llama/Llama-3.1-8B-Instruct"


@pytest.fixture
def custom_secrets(secrets_dir):
    inference = secrets_dir / "inference"
    for key, value in {"provider": "openai", "url": URL + "/", "model": MODEL}.items():
        (inference / key).write_text(value + "\n")
    return secrets_dir


@pytest.fixture
def profiles(ab):
    return ab.parse_profiles(profile_files("custom-inference"))


def test_profile_is_valid_and_reads_url_and_model_from_the_secret(ab, profiles, custom_secrets):
    ab.validate_profiles(profiles)
    creds = ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)
    custom = next(p for p in profiles[0].workspaces[0].providers if p.name == "custom")
    assert (custom.type, custom.base_url, custom.model) == ("openai", URL, MODEL)
    assert creds["default"]["custom"] == "saw-cred.inference.api_key"


def test_apply_creates_an_openai_provider_and_onboards_on_its_endpoint(
        ab, fake_env, config, profiles, custom_secrets):
    creds = ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert state["providers"]["default/custom"] == {
        "type": "openai", "credential": "OPENAI_API_KEY=saw-cred.inference.api_key",
        "config": [f"OPENAI_BASE_URL={URL}"]}
    assert not [c for c in fake_env.openshell_calls() if c[:1] == ["inference"]]
    # Only a nonsecret marker travels to the gateway.
    assert not any("saw-cred.inference.api_key" in " ".join(c) for c in fake_env.openshell_calls())
    onboard = next(" ".join(c) for c in fake_env.openshell_calls() if "onboard" in " ".join(c))
    assert f'--custom-base-url {URL} ' in onboard and "inference.local" not in onboard
    assert 'CUSTOM_API_KEY="$OPENAI_API_KEY"' in onboard
    assert f'--custom-model-id {shlex.quote(MODEL)} ' in onboard


def test_rerun_updates_the_base_url(ab, fake_env, config, profiles, custom_secrets):
    creds = ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    (custom_secrets / "inference" / "url").write_text("http://ollama.models.svc:11434/v1\n")
    profiles2 = ab.parse_profiles(profile_files("custom-inference"))
    creds = ab.resolve_credentials(profiles2, custom_secrets, TEST_PROXY)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles2)
    assert fake_env.openshell_state()["providers"]["default/custom"]["config"] == [
        "OPENAI_BASE_URL=http://ollama.models.svc:11434/v1"]


@pytest.mark.parametrize("url", ["ftp://host/v1", "https://user:pw@host/v1", "https://host/v1?key=x",
                                 "https://host/v1#f", "http://localhost:8000/v1", "https://host:99999/v1",
                                 "not a url"])
def test_bad_base_urls_are_refused_without_echoing_them(ab, profiles, custom_secrets, url):
    (custom_secrets / "inference" / "url").write_text(url)
    with pytest.raises(ab.InstallerError) as err:
        ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)
    assert url not in str(err.value) and "base URL" in str(err.value)


def test_a_secret_for_another_provider_still_fails(ab, profiles, custom_secrets):
    """Selecting a profile is explicit (saw-bom `profiles`); a mismatched
    Secret is still an error, never a silent skip."""
    (custom_secrets / "inference" / "provider").write_text("gemini\n")
    with pytest.raises(ab.InstallerError, match="is for 'gemini'"):
        ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)


def test_the_secret_names_the_openshell_provider_type(ab, profiles, custom_secrets):
    """There is no `custom` provider type in OpenShell: the Secret says
    `openai`, the type the gateway creates."""
    (custom_secrets / "inference" / "provider").write_text("custom\n")
    with pytest.raises(ab.InstallerError, match="expects a openai credential"):
        ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)


def test_base_url_only_for_types_the_router_supports(ab):
    files = profile_files("custom-inference")
    key = next(k for k in files if k.endswith("providers.yaml"))
    files[key] = files[key].replace("type: openai", "type: gemini")
    with pytest.raises(ab.InstallerError, match="does not take a base URL"):
        ab.validate_profiles(ab.parse_profiles(files))


def test_data_science_profile_is_unchanged(ab, shipped_profile_files, secrets_dir):
    """No url/model keys in the Secret: providers keep their profile model."""
    profiles = ab.parse_profiles(shipped_profile_files)
    ab.resolve_credentials(profiles, secrets_dir, TEST_PROXY)
    nvidia = next(p for p in profiles[0].workspaces[0].providers if p.name == "nvidia")
    assert (nvidia.base_url, nvidia.model) == ("", "nvidia/nemotron-3-super-120b-a12b")


def test_without_an_openai_profile_the_agent_is_not_onboarded_with_another_provider(
        ab, fake_env, config, profiles, custom_secrets):
    """Found live with governance on: `openai` had no provider profile, the
    provider was skipped, and OpenClaw was onboarded with `brave` and a
    default NVIDIA model while verification passed."""
    fake_env.without_profiles("openai")
    creds = ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)
    applier = ab.ProfileApplier(ab.Shell(), config, creds)
    applier.apply(profiles)
    calls = [" ".join(c) for c in fake_env.openshell_calls()]
    assert not any("onboard" in c for c in calls)
    failures = applier.verify(profiles)
    assert any("has no usable provider" in f and "custom (openai)" in f for f in failures), failures


def test_the_shipped_openai_profile_is_imported_when_the_gateway_lacks_it(
        ab, fake_env, config, profiles, custom_secrets, tmp_path):
    """Governance off: the installer imports its copy of the `openai` profile."""
    from pathlib import Path
    fake_env.without_profiles("openai")
    shipped = Path(__file__).resolve().parents[2] / "charts/openshell-saw/files/provider-profiles/openai.yaml"
    creds = ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)
    applier = ab.ProfileApplier(ab.Shell(), config, creds, {"openai": shipped.read_text()})
    applier.apply(profiles)
    assert fake_env.openshell_state()["providers"]["default/custom"]["type"] == "openai"
    assert applier.verify(profiles) == []


def test_a_provider_that_arrives_later_is_attached_to_the_existing_sandbox(
        ab, fake_env, config, profiles, custom_secrets):
    """Found live: boot 1 had no `openai` profile, so `notebook` was created
    without `custom`; after the profile reached the catalog, boot 2 created
    the provider but left the running sandbox without it."""
    fake_env.without_profiles("openai")
    creds = ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["providers"] == []
    (fake_env.state / "no-profiles.json").write_text("[]")      # the catalog now has it
    applier = ab.ProfileApplier(ab.Shell(), config, creds)
    applier.apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["providers"] == ["custom"]
    assert applier.verify(profiles) == []


REPLACED = ("error: Replacement credential saved but inactive. Your connection is unchanged. "
            "Test and activate it with:\nopenclaw models auth activate "
            "openai:setup-df67c47c-d3f2-46f5-b698-c42390c67b5d --agent main")


def test_a_replaced_openclaw_credential_is_activated(ab, fake_env, config, profiles, custom_secrets):
    """Found live: re-onboarding the existing notebook for the custom
    endpoint left OpenClaw on its previous connection."""
    import json
    (fake_env.state / "exec-output.json").write_text(json.dumps({"openclaw onboard": REPLACED}))
    creds = ab.resolve_credentials(profiles, custom_secrets, TEST_PROXY)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    calls = [" ".join(c) for c in fake_env.openshell_calls()]
    assert any("openclaw models auth activate openai:setup-df67c47c-d3f2-46f5-b698-c42390c67b5d --agent main"
               in c for c in calls)


@pytest.mark.parametrize("output", [
    "Onboarding complete",
    "Replacement credential saved but inactive.\nopenclaw models auth activate x;rm -rf / --agent main",
    REPLACED + "\nopenclaw models auth activate openai:setup-00000000-0000-0000-0000-000000000000 --agent main",
])
def test_replacement_parsing_is_strict(ab, output):
    assert ab.openclaw_replacement_profile(output) is None
