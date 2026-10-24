"""A sandbox's `inference:` (how the agent reaches its model) and `env:` (its
ordinary environment), and a provider's named `credentials:`.

A value is a literal or `{secretKeyRef: {name, key}, default?, required?,
title?}`. The env is fixed at `sandbox create` (changing it recreates the
sandbox, see test_review_135); inference is agent configuration.
"""
import json

import pytest

REF = {"secretKeyRef": {"name": "inference", "key": "model"}}


def _secret(dirpath, name, **keys):
    base = dirpath / name
    base.mkdir(parents=True, exist_ok=True)
    for key, value in keys.items():
        (base / key).write_text(value)


def _one(ab, sandbox_type="openclaw", provider=None, **sb):
    provider = provider or ab.Provider(name="inference", type="openai", model="provider-model",
                                       credential_secret="inference",
                                       credential_secret_key="api_key")
    sandbox = ab.Sandbox(name="chat", type=sandbox_type, providers=[provider.name], **sb)
    workspace = ab.Workspace(name="default", providers=[provider], sandboxes=[sandbox])
    return provider, sandbox, [ab.Profile(name="test", workspaces=[workspace])]


# --- env: validation and resolution -------------------------------------------------

@pytest.mark.parametrize("name,src,problem", [
    ("OPENSHELL_X", {"value": "1"}, "reserved by OpenShell"),
    ("NVIDIA_API_KEY", {"value": "1"}, "provider credential variable"),
    ("OPENAI_BASE_URL", {"value": "x"}, "inference setting"),
    ("MODEL", {"value": "x"}, "inference setting"),
    ("1BAD", {"value": "1"}, "not a valid variable name"),
    ("X", {"value": "a\nb"}, "single line"),
    ("X", {"value": True}, "must be a string"),
    ("X", {"value": "1", "secretKeyRef": {"name": "s", "key": "k"}}, "exactly one of value or secretKeyRef"),
    ("X", {"secretKeyRef": {"key": "k"}}, "secretKeyRef.name must be a valid Secret name"),
    ("X", {"secretKeyRef": {"name": "s", "key": "k", "extra": 1}}, "takes only name and key"),
    ("X", {"value": "1", "titel": "typo"}, "unknown keys titel"),
])
def test_bad_env_entries_are_rejected(ab, name, src, problem):
    _, _, profiles = _one(ab, env={name: src})
    with pytest.raises(ab.InstallerError, match=problem):
        ab.validate_profiles(profiles)


def test_literals_secret_refs_and_defaults_resolve(ab, tmp_path):
    _, sb, profiles = _one(ab, env={
        "HF_HUB_OFFLINE": {"value": "1"},
        "PROJECT": {"secretKeyRef": {"name": "inference", "key": "project"}},
        "REGION": {"secretKeyRef": {"name": "inference", "key": "region"}, "default": "eu"},
    })
    ab.validate_profiles(profiles)
    _secret(tmp_path, "inference", api_key="k", project="p-1\n")
    ab.resolve_credentials(profiles, tmp_path)
    assert sb.env_values == {"HF_HUB_OFFLINE": "1", "PROJECT": "p-1", "REGION": "eu"}


def test_a_missing_env_value_names_the_secret_not_a_value(ab, tmp_path):
    _, _, profiles = _one(ab, env={"PROJECT": {"secretKeyRef": {"name": "inference", "key": "project"}}})
    _secret(tmp_path, "inference", api_key="k")
    with pytest.raises(ab.InstallerError, match="Secret 'inference' key 'project'"):
        ab.resolve_credentials(profiles, tmp_path)


def test_the_env_is_set_at_create_and_labelled(ab, fake_env, config, tmp_path):
    _, _, profiles = _one(ab, env={"HF_HUB_OFFLINE": {"value": "1"}, "B": {"value": "2"}})
    _secret(tmp_path, "inference", api_key="k")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert state["sandboxes"]["default/chat"]["env"] == ["B=2", "HF_HUB_OFFLINE=1"]
    assert any(l.startswith("saw.redhat.com/env=") for l in state["labels"]["sandbox/default/chat"])
    # exec commands carry no env of their own: the sandbox has it.
    assert not any("--env" in c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"])


# --- inference: model, endpoint, protocol ----------------------------------------------

def test_model_comes_from_inference_then_the_legacy_fields(ab, tmp_path):
    provider, sb, profiles = _one(ab, model="sandbox-model")
    assert ab.sandbox_model(sb, provider, "builtin") == "sandbox-model"
    sb.model = ""
    assert ab.sandbox_model(sb, provider, "builtin") == "provider-model"
    provider.model = ""
    assert ab.sandbox_model(sb, provider, "builtin") == "builtin"
    sb.inference = {"providerRef": "inference", "protocol": "openai", "model": REF}
    _secret(tmp_path, "inference", api_key="k", model="from-secret")
    ab.resolve_credentials(profiles, tmp_path)
    assert ab.sandbox_model(sb, provider, "builtin") == "from-secret"


def test_the_model_reaches_nemoclaw(ab, fake_env, config, tmp_path):
    nvidia = ab.Provider(name="nvidia", type="nvidia",
                         credential_secret="inference", credential_secret_key="api_key")
    _, _, profiles = _one(ab, "nemoclaw", nvidia, inference={
        "providerRef": "nvidia", "protocol": "openai", "model": "nvidia/m"})
    _secret(tmp_path, "inference", api_key="nvapi-x")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    assert fake_env.other_calls("nemoclaw")[0]["model"] == "nvidia/m"


def _onboard(fake_env):
    return next(c[-1] for c in fake_env.openshell_calls()
                if c[:2] == ["sandbox", "exec"] and "openclaw onboard " in c[-1])


def test_without_a_base_url_the_provider_types_own_api_is_used(ab, fake_env, config, tmp_path):
    """NVIDIA speaks the OpenAI protocol but at its own endpoint."""
    nvidia = ab.Provider(name="nvidia", type="nvidia",
                         credential_secret="inference", credential_secret_key="api_key")
    _, _, profiles = _one(ab, provider=nvidia, inference={
        "providerRef": "nvidia", "protocol": "openai", "model": "nvidia/m"})
    _secret(tmp_path, "inference", api_key="nvapi-x")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    onboard = _onboard(fake_env)
    assert "--custom-base-url https://integrate.api.nvidia.com/v1 " in onboard
    assert "--custom-compatibility openai" in onboard


def test_an_official_api_without_a_base_url_onboards_natively(ab, fake_env, config, tmp_path):
    _, _, profiles = _one(ab, inference={"providerRef": "inference", "protocol": "openai",
                                         "model": "gpt-4o"})
    _secret(tmp_path, "inference", api_key="sk")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    assert "--auth-choice openai-api-key" in _onboard(fake_env)


def test_anthropic_protocol_on_a_custom_endpoint(ab, fake_env, config, tmp_path):
    claude = ab.Provider(name="claude", type="anthropic",
                         credential_secret="inference", credential_secret_key="api_key")
    _, _, profiles = _one(ab, provider=claude, inference={
        "providerRef": "claude", "protocol": "anthropic",
        "baseUrl": "https://gateway.example/anthropic", "model": "claude-sonnet-4-6"})
    _secret(tmp_path, "inference", api_key="sk")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    onboard = _onboard(fake_env)
    assert "--custom-base-url https://gateway.example/anthropic " in onboard
    assert "--custom-compatibility anthropic" in onboard


def test_a_bad_inference_base_url_is_refused_without_echoing_it(ab, tmp_path):
    _, _, profiles = _one(ab, inference={"providerRef": "inference", "protocol": "openai",
                                         "model": "m", "baseUrl": {
                                             "secretKeyRef": {"name": "inference", "key": "url"}}})
    _secret(tmp_path, "inference", api_key="k", url="http://localhost:8000/v1")
    with pytest.raises(ab.InstallerError) as err:
        ab.resolve_credentials(profiles, tmp_path)
    assert "base URL" in str(err.value) and "localhost:8000" not in str(err.value)


def test_timeout_must_be_a_non_negative_integer(ab, tmp_path):
    _, _, profiles = _one(ab, inference={"providerRef": "inference", "protocol": "openai",
                                         "model": "m", "timeoutSeconds": "soon"})
    _secret(tmp_path, "inference", api_key="k")
    with pytest.raises(ab.InstallerError, match="timeoutSeconds must be a non-negative integer"):
        ab.resolve_credentials(profiles, tmp_path)


# --- credentials by name ------------------------------------------------------------------

TWO_CRED_PROFILE = ("id: twokey\ncredentials:\n  - name: api_key\n    env_vars: [TWOKEY_API_KEY]\n"
                    "  - name: app_secret\n    env_vars: [TWOKEY_APP_SECRET]\n")


def _two_cred(ab, credentials):
    provider = ab.Provider(name="tk", type="twokey", credential_secret="tk",
                           credentials_spec=credentials)
    sandbox = ab.Sandbox(name="tools", type="generic", providers=["tk"])
    workspace = ab.Workspace(name="default", providers=[provider], sandboxes=[sandbox])
    return provider, [ab.Profile(name="test", workspaces=[workspace])]


def test_named_credentials_bind_to_their_profile_env_vars(ab, fake_env, config, tmp_path):
    _, profiles = _two_cred(ab, {"app_secret": {"secretKey": "secret"},   # order irrelevant
                                 "api_key": {"secretKey": "key"}})
    ab.validate_profiles(profiles, known_profiles={"twokey"})
    _secret(tmp_path, "tk", key="k-1", secret="s-2")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds,
                      provider_profile_docs={"twokey": TWO_CRED_PROFILE}).apply(profiles)
    created = fake_env.openshell_state()["providers"]["default/tk"]
    assert sorted(created["credentials"]) == ["TWOKEY_API_KEY=k-1", "TWOKEY_APP_SECRET=s-2"]
    assert not any("s-2" in " ".join(c) for c in fake_env.openshell_calls())   # env only


def test_a_missing_named_credential_is_an_error(ab, tmp_path):
    _, profiles = _two_cred(ab, {"api_key": {"secretKey": "key"}, "app_secret": {"secretKey": "secret"}})
    _secret(tmp_path, "tk", key="k-1")
    with pytest.raises(ab.InstallerError, match="credential 'app_secret' of provider 'tk' in workspace 'default' not found"):
        ab.resolve_credentials(profiles, tmp_path)


def test_credentials_and_credential_secret_key_are_exclusive(ab):
    from conftest import profile_files
    files = profile_files("custom-inference")
    key = next(k for k in files if k.endswith("providers.yaml"))
    files[key] = files[key].replace("credentialSecretKey: api_key",
                                    "credentialSecretKey: api_key\n      credentials:\n"
                                    "        api_key: {secretKey: api_key}", 1)
    with pytest.raises(ab.InstallerError, match="both credentials and credentialSecretKey"):
        ab.parse_profiles(files)


def test_bad_credential_entries_are_rejected(ab):
    _, profiles = _two_cred(ab, {"api_key": {"secretKey": "key"}, "bad name": {"secretKey": "x"},
                                 "app_secret": {"nope": "x"}})
    with pytest.raises(ab.InstallerError) as err:
        ab.validate_profiles(profiles, known_profiles={"twokey"})
    assert "credential 'bad name' is not a valid credential name" in str(err.value)
    assert "credential 'app_secret' needs a valid secretKey" in str(err.value)


# --- the plan the installer re-executes itself with keeps all of it ------------------------

def test_the_plan_keeps_sandbox_config_and_named_credentials(ab, tmp_path):
    provider, profiles = _two_cred(ab, {"api_key": {"secretKey": "key"}, "app_secret": {"secretKey": "secret"}})
    sb = profiles[0].workspaces[0].sandboxes[0]
    sb.env = {"A": {"value": "1"}}
    sb.inference = {"providerRef": "tk", "protocol": "openai", "model": "m"}
    _secret(tmp_path, "tk", key="k-1", secret="s-2")
    creds = ab.resolve_credentials(profiles, tmp_path)
    back = ab.profiles_from_plan(json.loads(json.dumps(ab.plan_for_user({}, profiles, creds, "d.sh"))))
    ws = back[0].workspaces[0]
    assert ws.sandboxes[0].env_values == {"A": "1"}
    assert ws.sandboxes[0].inference_values["model"] == "m"
    assert ws.providers[0].credential_values == {"api_key": "k-1", "app_secret": "s-2"}


def test_protocol_is_implied_by_a_known_provider_type(ab):
    nvidia = ab.Provider(name="nvidia", type="nvidia", credential_secret="inference")
    sb = ab.Sandbox(name="nb", type="openclaw", providers=["nvidia"],
                    inference={"providerRef": "nvidia", "model": "m"})
    assert ab.sandbox_inference_problems(sb, {"nvidia": "nvidia"}) == []
    assert ab.inference_protocol(sb.inference, "nvidia") == "openai"
    assert ab.inference_protocol(sb.inference, "anthropic") == "anthropic"
    assert ab.inference_protocol({"protocol": "anthropic"}, "nvidia") == "anthropic"


def test_protocol_is_required_for_a_profile_type_the_installer_does_not_know(ab):
    sb = ab.Sandbox(name="nb", type="openclaw", providers=["vllm"],
                    inference={"providerRef": "vllm", "model": "m"})
    problems = ab.sandbox_inference_problems(sb, {"vllm": "vllm-prod"})
    assert any("needs protocol" in p and "vllm-prod" in p for p in problems)
    sb.inference["protocol"] = "openai"
    assert ab.sandbox_inference_problems(sb, {"vllm": "vllm-prod"}) == []
