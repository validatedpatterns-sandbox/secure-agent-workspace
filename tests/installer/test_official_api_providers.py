"""Official APIs use native onboarding; explicit endpoint URLs remain custom."""
import pytest


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
@pytest.mark.parametrize("native", [True, False])
def test_existing_custom_settings_are_cleared_only_for_native_apis(
        ab, fake_env, config, kind, native):
    endpoint = "https://private-model.example/v1"
    provider = ab.Provider(name="inference", type=kind, model="test-model", base_url=endpoint)
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=[provider.name])
    workspace = ab.Workspace(name="default", providers=[provider], sandboxes=[sandbox])
    profiles = [ab.Profile(name="test", workspaces=[workspace])]
    applier = ab.ProfileApplier(ab.Shell(), config, {"default": {provider.name: "test-key"}})
    applier.apply(profiles)
    # Native onboarding preserves existing custom endpoint settings in OpenClaw.
    state = fake_env.openshell_state()
    key = f"models.providers.{kind}"
    saved = {key: {"baseUrl": endpoint, "api": "openai-completions"},
             "models.providers.unrelated": {"baseUrl": "https://keep.example/v1"}}
    state["sandboxes"]["default/chat"]["openclawConfig"] = saved
    fake_env.set_openshell_state(state)
    if native:
        provider.base_url = ""
    call_count = len(fake_env.openshell_calls())
    applier.apply(profiles)
    current = fake_env.openshell_state()["sandboxes"]["default/chat"]["openclawConfig"]
    assert (key not in current) == native
    assert current["models.providers.unrelated"] == saved["models.providers.unrelated"]
    if native:
        scripts = [c[-1] for c in fake_env.openshell_calls()[call_count:]
                   if c[:2] == ["sandbox", "exec"]]
        cleanup = next(i for i, s in enumerate(scripts)
                       if f"openclaw config unset {key}" in s)
        onboard = next(i for i, s in enumerate(scripts) if "openclaw onboard " in s)
        assert cleanup < onboard


@pytest.mark.parametrize("kind,endpoint,choice,model", [
    ("openai", "", "openai-api-key", "gpt-4o"),
    ("anthropic", "", "apiKey", "claude-sonnet-4-6"),
    ("openai", "http://ollama.models.svc:11434/v1", "custom-api-key", "llama3"),
    ("openai", "https://api.openai.com/v1", "custom-api-key", "gpt-4o"),
    ("nvidia", "", "custom-api-key", "nvidia/nemotron-3.5-lightning-30b-a3b"),
])
def test_onboarding_uses_the_provider_protocol(
        ab, fake_env, config, kind, endpoint, choice, model):
    provider = ab.Provider(name="inference", type=kind, model=model, base_url=endpoint)
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=[provider.name])
    workspace = ab.Workspace(name="default", providers=[provider], sandboxes=[sandbox])
    applier = ab.ProfileApplier(ab.Shell(), config,
                                {"default": {provider.name: "test-secret-key"}})
    applier.apply([ab.Profile(name="test", workspaces=[workspace])])
    calls = fake_env.openshell_calls()
    scripts = [c[-1] for c in calls if c[:2] == ["sandbox", "exec"]]
    onboard = next(s for s in scripts if "openclaw onboard " in s)
    assert f"--auth-choice {choice} " in onboard
    if choice == "custom-api-key":
        assert f"--custom-model-id {model}" in onboard
        if endpoint:
            assert f"--custom-base-url {endpoint} " in onboard
    else:
        assert "--custom-" not in onboard
        assert any(f"openclaw models set {kind}/{model}" in s for s in scripts)
    assert not any("test-secret-key" in " ".join(c) for c in calls)


def test_optional_openai_uses_openclaw_runtime_when_nvidia_is_default(ab, fake_env, config):
    providers = [ab.Provider(name="nvidia", type="nvidia", model="nvidia/test-model"),
                 ab.Provider(name="openai", type="openai", model="gpt-4o")]
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=[p.name for p in providers])
    workspace = ab.Workspace(name="default", providers=providers, sandboxes=[sandbox])
    ab.ProfileApplier(ab.Shell(), config, {"default": {p.name: "test-key" for p in providers}}).apply(
        [ab.Profile(name="test", workspaces=[workspace])])
    scripts = [c[-1] for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"]]
    assert any("agents.defaults.models.openai/*.agentRuntime" in s and '"openclaw"' in s
               for s in scripts)
    onboard = next(s for s in scripts if "openclaw onboard " in s)
    assert "--custom-model-id nvidia/test-model" in onboard
    assert set(fake_env.openshell_state()["sandboxes"]["default/chat"]["providers"]) == {
        "nvidia", "openai"}


def test_shipped_optional_apis_do_not_require_keys_by_default(ab, secrets_dir):
    from conftest import profile_files

    profiles = ab.parse_profiles(profile_files())
    ab.validate_profiles(profiles)
    workspace = next(ws for ws in profiles[0].workspaces if ws.name == "default")
    optional = [p for p in workspace.providers if p.type in ("openai", "anthropic")]
    assert {p.type for p in optional} == {"openai", "anthropic"}
    assert all(not p.enabled and not p.base_url_secret_key for p in optional)
    assert workspace.sandboxes[0].providers == ["nvidia"]
    nvidia = next(p for p in workspace.providers if p.name == "nvidia")
    # The model is the sandbox's (inference.model); the provider holds credentials only.
    assert nvidia.model == ""
    assert nvidia.credential_secret_key == "api_key"
    assert set(ab.resolve_credentials(profiles, secrets_dir)["default"]) == {"nvidia", "brave"}
    assert ab.sandbox_model(workspace.sandboxes[0], nvidia) == "nvidia/nemotron-3.5-lightning-30b-a3b"


def test_each_official_api_reads_its_own_secret(ab, secrets_dir):
    from conftest import profile_files

    profiles = ab.parse_profiles(profile_files())
    workspace = next(ws for ws in profiles[0].workspaces if ws.name == "default")
    for kind in ("openai", "anthropic"):
        provider = next(p for p in workspace.providers if p.name == kind)
        provider.enabled = True
        workspace.sandboxes[0].providers.append(kind)
        secret = secrets_dir / f"inference-{kind}"
        secret.mkdir()
        (secret / "provider").write_text(kind)
        (secret / "api_key").write_text(f"test-{kind}-key")
        (secret / "model").write_text(f"test-{kind}-model")
    ab.validate_profiles(profiles)
    credentials = ab.resolve_credentials(profiles, secrets_dir)
    assert credentials["default"] == {
        "nvidia": "nvapi-TEST-KEY-123", "brave": "brave-TEST-KEY-456",
        "openai": "test-openai-key", "anthropic": "test-anthropic-key"}
    assert credentials["cuda-dev"]["nvidia"] == credentials["default"]["nvidia"]
    for kind in ("openai", "anthropic"):
        provider = next(p for p in workspace.providers if p.name == kind)
        assert provider.credential_secret == f"inference-{kind}"
        assert provider.model == f"test-{kind}-model"
