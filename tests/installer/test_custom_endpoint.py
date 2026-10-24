"""A custom OpenAI-compatible endpoint (vLLM, Ollama, ...) on OpenShell 0.1.x:
a `custom-inference` provider (the deployment's own governance profile, from
overrides/governance-profiles) holds only the key; the endpoint and the model
are the sandbox's `inference:` settings (protocol openai, baseUrl and model
from the Secret), and OpenClaw is onboarded against that endpoint itself (no
inference routes, no https://inference.local)."""

import json
import shlex
from pathlib import Path

import pytest
import yaml

from conftest import profile_files

URL = "https://vllm.models.svc.cluster.local:8443/v1"
MODEL = "meta-llama/Llama-3.1-8B-Instruct"
ROOT = Path(__file__).resolve().parents[2]
EXTRA_PROFILE = ROOT / "overrides/governance-profiles/custom-inference.yaml"
DEFAULT_CATALOG = {"web-search": ["api.tavily.com", "api.search.brave.com", "registry.npmjs.org"],
                   "brave": ["api.search.brave.com"], "nvidia": ["integrate.api.nvidia.com"]}


@pytest.fixture
def governed_catalog(fake_env):
    """The gateway's catalog with the deployment's custom-inference profile
    (the file in overrides/governance-profiles, as the interceptor serves it)."""
    record = yaml.safe_load(EXTRA_PROFILE.read_text())
    fake_env.set_catalog({**DEFAULT_CATALOG, "custom-inference": record})
    return record


@pytest.fixture
def custom_secrets(secrets_dir):
    inference = secrets_dir / "inference"
    for key, value in {"provider": "custom-inference", "api_key": "sk-CUSTOM-TEST-KEY",
                       "url": URL + "/", "model": MODEL}.items():
        (inference / key).write_text(value + "\n")
    return secrets_dir


@pytest.fixture
def profiles(ab):
    return ab.parse_profiles(profile_files("custom-inference"))


def notebook(profiles):
    return next(s for s in profiles[0].workspaces[0].sandboxes if s.name == "notebook")


def test_profile_is_valid_and_reads_url_and_model_from_the_secret(ab, profiles, custom_secrets):
    # The type is the deployment's governance profile: valid under governance
    # (checked against the live catalog at apply), refused without it.
    ab.validate_profiles(profiles, governed=True)
    with pytest.raises(ab.InstallerError, match="unsupported type 'custom-inference'"):
        ab.validate_profiles(profiles)
    creds = ab.resolve_credentials(profiles, custom_secrets)
    custom = next(p for p in profiles[0].workspaces[0].providers if p.name == "custom")
    # The provider is only the credential...
    assert (custom.type, custom.base_url, custom.model) == ("custom-inference", "", "")
    assert creds["default"]["custom"] == "sk-CUSTOM-TEST-KEY"
    # ...the endpoint and model are the sandbox's (the URL normalised).
    sb = notebook(profiles)
    assert sb.inference_values == {"providerRef": "custom", "protocol": "openai",
                                   "baseUrl": URL, "model": MODEL, "timeoutSeconds": 300}
    assert (ab.sandbox_endpoint(sb, custom), ab.sandbox_model(sb, custom)) == (URL, MODEL)


def test_apply_creates_the_provider_from_the_governed_profile_and_onboards_on_its_endpoint(
        ab, fake_env, config, profiles, custom_secrets, governed_catalog):
    creds = ab.resolve_credentials(profiles, custom_secrets)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    state = fake_env.openshell_state()
    # The credential env var is the governed profile's, not a built-in one;
    # no provider --config (not part of OpenShell 0.1.2's provider CLI).
    assert state["providers"]["default/custom"] == {
        "type": "custom-inference", "credential": "CUSTOM_INFERENCE_API_KEY=sk-CUSTOM-TEST-KEY"}
    assert "env" not in state["sandboxes"]["default/notebook"]     # inference is not env
    # The shipped profile's timeoutSeconds: 300 reaches OpenClaw's provider config.
    assert state["sandboxes"]["default/notebook"]["openclawConfig"][
        "models.providers.custom-inference.timeoutSeconds"] == 300
    assert not [c for c in fake_env.openshell_calls() if c[:1] == ["inference"]]
    # The key only ever travels in the environment.
    assert not any("sk-CUSTOM-TEST-KEY" in " ".join(c) for c in fake_env.openshell_calls())
    onboard = next(" ".join(c) for c in fake_env.openshell_calls() if "onboard" in " ".join(c))
    assert f'--custom-base-url {URL} ' in onboard and "inference.local" not in onboard
    assert 'CUSTOM_API_KEY="$CUSTOM_INFERENCE_API_KEY"' in onboard
    assert f'--custom-model-id {shlex.quote(MODEL)} ' in onboard


def test_rerun_updates_the_base_url(ab, fake_env, config, profiles, custom_secrets, governed_catalog):
    creds = ab.resolve_credentials(profiles, custom_secrets)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    (custom_secrets / "inference" / "url").write_text("http://ollama.models.svc:11434/v1\n")
    profiles2 = ab.parse_profiles(profile_files("custom-inference"))
    creds = ab.resolve_credentials(profiles2, custom_secrets)
    before = len(fake_env.openshell_calls())
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles2)
    calls = fake_env.openshell_calls()[before:]
    # The sandbox exists already: the agent is onboarded again on the new
    # endpoint (inference is agent configuration, not the sandbox's env, so
    # no recreation is needed).
    assert "sandbox delete" not in [" ".join(c[:2]) for c in calls]
    onboard = next(" ".join(c) for c in calls if "openclaw onboard " in " ".join(c))
    assert "--custom-base-url http://ollama.models.svc:11434/v1 " in onboard


@pytest.mark.parametrize("url", ["ftp://host/v1", "https://user:pw@host/v1", "https://host/v1?key=x",
                                 "https://host/v1#f", "http://localhost:8000/v1", "https://host:99999/v1",
                                 "not a url"])
def test_bad_base_urls_are_refused_without_echoing_them(ab, profiles, custom_secrets, url):
    (custom_secrets / "inference" / "url").write_text(url)
    with pytest.raises(ab.InstallerError) as err:
        ab.resolve_credentials(profiles, custom_secrets)
    assert url not in str(err.value) and "base URL" in str(err.value)


def test_a_secret_for_another_provider_still_fails(ab, profiles, custom_secrets):
    """Selecting a profile is explicit (saw-bom `profiles`); a mismatched
    Secret is still an error, never a silent skip."""
    (custom_secrets / "inference" / "provider").write_text("gemini\n")
    with pytest.raises(ab.InstallerError, match="is for 'gemini'"):
        ab.resolve_credentials(profiles, custom_secrets)


def test_the_secret_names_the_provider_type_or_nothing(ab, profiles, custom_secrets):
    """The Secret's `provider` key, when present, is the provider type the
    gateway creates (the deployment's profile id); a shared Secret may leave
    it out."""
    (custom_secrets / "inference" / "provider").write_text("custom\n")
    with pytest.raises(ab.InstallerError, match="expects a custom-inference credential"):
        ab.resolve_credentials(profiles, custom_secrets)
    (custom_secrets / "inference" / "provider").write_text("")
    ab.resolve_credentials(profiles, custom_secrets)


def test_base_url_only_for_types_the_router_supports(ab):
    """The provider-level baseUrlSecretKey (still accepted) only for types
    that take a base URL."""
    files = profile_files("custom-inference")
    key = next(k for k in files if k.endswith("providers.yaml"))
    files[key] = files[key].replace("type: custom-inference", "type: gemini").replace(
        "credentialSecretKey: api_key", "credentialSecretKey: api_key\n      baseUrlSecretKey: url", 1)
    with pytest.raises(ab.InstallerError, match="does not take a base URL"):
        ab.validate_profiles(ab.parse_profiles(files))


def test_data_science_profile_is_unchanged(ab, shipped_profile_files, secrets_dir):
    """No url/model keys in the Secret: the sandbox keeps its profile model;
    the provider carries credentials only."""
    profiles = ab.parse_profiles(shipped_profile_files)
    ab.resolve_credentials(profiles, secrets_dir)
    ws = next(w for w in profiles[0].workspaces if w.name == "default")
    nvidia = next(p for p in ws.providers if p.name == "nvidia")
    assert (nvidia.base_url, nvidia.model) == ("", "")
    notebook = next(s for s in ws.sandboxes if s.name == "notebook")
    assert ab.sandbox_model(notebook, nvidia) == "nvidia/nemotron-3.5-lightning-30b-a3b"


def test_without_the_profile_in_the_catalog_the_apply_fails_before_creating_anything(
        ab, fake_env, config, profiles, custom_secrets):
    """A deployment that selects custom-inference but has not added the
    profile under overrides/governance-profiles: the error names the fix.
    (Earlier, with `type: openai`, the provider was skipped with a warning
    and OpenClaw was onboarded without it - found live.)"""
    creds = ab.resolve_credentials(profiles, custom_secrets)
    applier = ab.ProfileApplier(ab.Shell(), config, creds)
    with pytest.raises(ab.InstallerError, match="overrides/governance-profiles") as err:
        applier.apply(profiles)
    assert "type 'custom-inference'" in str(err.value)
    calls = [" ".join(c) for c in fake_env.openshell_calls()]
    assert not any("provider create" in c or "sandbox create" in c or "onboard" in c for c in calls)


def test_a_governed_profile_without_a_credential_env_var_is_refused(
        ab, fake_env, config, profiles, custom_secrets, governed_catalog):
    record = dict(governed_catalog)
    record["credentials"] = [{"name": "api_key"}]
    fake_env.set_catalog({**DEFAULT_CATALOG, "custom-inference": record})
    creds = ab.resolve_credentials(profiles, custom_secrets)
    with pytest.raises(ab.InstallerError, match="declares no credential env var"):
        ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)


def test_the_profile_arriving_later_makes_the_next_apply_succeed(
        ab, fake_env, config, profiles, custom_secrets):
    """Boot 1 before the governance-extra-profiles app synced: the apply
    fails (nothing half-built); boot 2, with the profile in the catalog,
    creates the provider and the sandbox with it."""
    creds = ab.resolve_credentials(profiles, custom_secrets)
    with pytest.raises(ab.InstallerError):
        ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    fake_env.set_catalog({**DEFAULT_CATALOG,
                          "custom-inference": yaml.safe_load(EXTRA_PROFILE.read_text())})
    applier = ab.ProfileApplier(ab.Shell(), config, creds)
    applier.apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["providers"] == ["custom"]
    assert applier.verify(profiles) == []


def test_the_extra_profile_file_is_a_complete_openshell_profile():
    """overrides/governance-profiles/custom-inference.yaml: what the BOM's
    `type: custom-inference` relies on."""
    doc = yaml.safe_load(EXTRA_PROFILE.read_text())
    assert doc["id"] == "custom-inference" and doc["category"] == "inference"
    assert doc["credentials"][0]["env_vars"] == ["CUSTOM_INFERENCE_API_KEY"]
    assert doc["endpoints"] and all({"host", "port"} <= set(e) for e in doc["endpoints"])
    kustomization = yaml.safe_load((EXTRA_PROFILE.parent / "kustomization.yaml").read_text())
    gen = kustomization["configMapGenerator"][0]
    assert gen["name"] == "governance-interceptor-extra-profiles"
    assert "custom-inference.yaml" in gen["files"]


REPLACED = ("error: Replacement credential saved but inactive. Your connection is unchanged. "
            "Test and activate it with:\nopenclaw models auth activate "
            "openai:setup-df67c47c-d3f2-46f5-b698-c42390c67b5d --agent main")


def test_a_replaced_openclaw_credential_is_activated(ab, fake_env, config, profiles, custom_secrets,
                                                     governed_catalog):
    """Found live: re-onboarding the existing notebook for the custom
    endpoint left OpenClaw on its previous connection."""
    (fake_env.state / "exec-output.json").write_text(json.dumps({"openclaw onboard": REPLACED}))
    creds = ab.resolve_credentials(profiles, custom_secrets)
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
