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
from conftest import marker, resolve

URL = "https://vllm.models.svc.cluster.local/v1"
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
    for key, value in {"provider": "custom-inference",
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
    creds = resolve(ab, profiles, custom_secrets)
    custom = next(p for p in profiles[0].workspaces[0].providers if p.name == "custom-inference")
    # The provider is only the credential...
    assert (custom.type, custom.base_url, custom.model) == ("custom-inference", "", "")
    assert creds["default"]["custom-inference"] == marker("inference")
    # ...the endpoint and model are the sandbox's (the URL normalised).
    sb = notebook(profiles)
    assert sb.inference_values == {"providerRef": "custom-inference", "protocol": "openai",
                                   "baseUrl": URL, "model": MODEL, "timeoutSeconds": 300}
    assert (ab.sandbox_endpoint(sb, custom), ab.sandbox_model(sb, custom)) == (URL, MODEL)


def test_apply_creates_the_provider_from_the_governed_profile_and_onboards_on_its_endpoint(
        ab, fake_env, config, profiles, custom_secrets, governed_catalog):
    creds = resolve(ab, profiles, custom_secrets)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    state = fake_env.openshell_state()
    # The credential env var is the governed profile's, not a built-in one;
    # no provider --config (not part of OpenShell 0.1.2's provider CLI).
    assert state["providers"]["default/custom-inference"] == {
        "type": "custom-inference", "credential": "CUSTOM_INFERENCE_API_KEY=" + marker("inference")}
    assert "env" not in state["sandboxes"]["default/notebook"]     # inference is not env
    # The shipped profile's timeoutSeconds: 300 reaches OpenClaw's provider config.
    assert state["sandboxes"]["default/notebook"]["openclawConfig"][
        "models.providers.custom-inference.timeoutSeconds"] == 300
    assert not [c for c in fake_env.openshell_calls() if c[:1] == ["inference"]]
    credential_args = [c[i + 1] for c in fake_env.openshell_calls()
                       for i, arg in enumerate(c[:-1]) if arg == "--credential"]
    assert "CUSTOM_INFERENCE_API_KEY" in credential_args
    assert all("=" not in arg for arg in credential_args)
    onboard = next(" ".join(c) for c in fake_env.openshell_calls() if "onboard" in " ".join(c))
    assert f'--custom-base-url {URL} ' in onboard and "inference.local" not in onboard
    assert 'CUSTOM_API_KEY="$CUSTOM_INFERENCE_API_KEY"' in onboard
    assert f'--custom-model-id {shlex.quote(MODEL)} ' in onboard


def test_rerun_updates_the_base_url(ab, fake_env, config, profiles, custom_secrets, governed_catalog):
    creds = resolve(ab, profiles, custom_secrets)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    (custom_secrets / "inference" / "url").write_text("http://ollama.models.svc:11434/v1\n")
    profiles2 = ab.parse_profiles(profile_files("custom-inference"))
    creds = resolve(ab, profiles2, custom_secrets)
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
        resolve(ab, profiles, custom_secrets)
    assert url not in str(err.value) and "base URL" in str(err.value)


def test_a_secret_for_another_provider_still_fails(ab, profiles, custom_secrets):
    """Selecting a profile is explicit (saw-bom `profiles`); a mismatched
    Secret is still an error, never a silent skip."""
    (custom_secrets / "inference" / "provider").write_text("gemini\n")
    with pytest.raises(ab.InstallerError, match="is for 'gemini'"):
        resolve(ab, profiles, custom_secrets)


def test_the_secret_names_the_provider_type_or_nothing(ab, profiles, custom_secrets):
    """The Secret's `provider` key, when present, is the provider type the
    gateway creates (the deployment's profile id); a shared Secret may leave
    it out."""
    (custom_secrets / "inference" / "provider").write_text("custom\n")
    with pytest.raises(ab.InstallerError, match="expects a custom-inference credential"):
        resolve(ab, profiles, custom_secrets)
    (custom_secrets / "inference" / "provider").write_text("")
    resolve(ab, profiles, custom_secrets)


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
    resolve(ab, profiles, secrets_dir)
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
    creds = resolve(ab, profiles, custom_secrets)
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
    creds = resolve(ab, profiles, custom_secrets)
    with pytest.raises(ab.InstallerError, match="declares no credential env var"):
        ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)


def test_the_profile_arriving_later_makes_the_next_apply_succeed(
        ab, fake_env, config, profiles, custom_secrets):
    """Boot 1 before the governance-extra-profiles app synced: the apply
    fails (nothing half-built); boot 2, with the profile in the catalog,
    creates the provider and the sandbox with it."""
    creds = resolve(ab, profiles, custom_secrets)
    with pytest.raises(ab.InstallerError):
        ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    fake_env.set_catalog({**DEFAULT_CATALOG,
                          "custom-inference": yaml.safe_load(EXTRA_PROFILE.read_text())})
    applier = ab.ProfileApplier(ab.Shell(), config, creds)
    applier.apply(profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["providers"] == ["custom-inference"]
    assert applier.verify(profiles) == []


def test_the_extra_profile_file_is_a_complete_openshell_profile():
    """overrides/governance-profiles/custom-inference.yaml: what the BOM's
    `type: custom-inference` relies on."""
    doc = yaml.safe_load(EXTRA_PROFILE.read_text())
    assert doc["id"] == "custom-inference" and doc["category"] == "inference"
    assert doc["credentials"][0]["env_vars"] == ["CUSTOM_INFERENCE_API_KEY"]
    assert doc["endpoints"] and all({"host", "port"} <= set(e) for e in doc["endpoints"])
    # The default profile is published, but its placeholder alone grants no
    # network access: an administrator must also set egress.extraAllow.
    kustomization = yaml.safe_load((EXTRA_PROFILE.parent / "kustomization.yaml").read_text())
    assert kustomization["configMapGenerator"][0]["files"] == ["custom-inference.yaml"]
    assert doc["endpoints"][0]["host"] == "api.inference.example.com", "a placeholder, not a real host"


REPLACED = ("error: Replacement credential saved but inactive. Your connection is unchanged. "
            "Test and activate it with:\nopenclaw models auth activate "
            "openai:setup-df67c47c-d3f2-46f5-b698-c42390c67b5d --agent main")


def test_a_replaced_openclaw_credential_is_activated(ab, fake_env, config, profiles, custom_secrets,
                                                     governed_catalog):
    """Found live: re-onboarding the existing notebook for the custom
    endpoint left OpenClaw on its previous connection."""
    (fake_env.state / "exec-output.json").write_text(json.dumps({"openclaw onboard": REPLACED}))
    creds = resolve(ab, profiles, custom_secrets)
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


def test_under_governance_a_provider_is_named_after_its_type(ab):
    """Found live: the governance interceptor compares a new sandbox's
    provider *names* with the vended profile ids, so `name: custom` with
    `type: custom-inference` is refused at sandbox create ("sandbox providers
    may only use vended provider profiles") while `brave`/`brave` passes."""
    files = profile_files("custom-inference")
    key = next(k for k in files if k.endswith("providers.yaml"))
    files[key] = files[key].replace("- name: custom-inference", "- name: custom", 1)
    sb_key = next(k for k in files if k.endswith("sandbox.yaml"))
    files[sb_key] = files[sb_key].replace("- custom-inference", "- custom").replace(
        "providerRef: custom-inference", "providerRef: custom")
    profiles = ab.parse_profiles(files)
    with pytest.raises(ab.InstallerError, match="must be named after its type 'custom-inference'"):
        ab.validate_profiles(profiles, governed=True)
    # Shipped profiles all satisfy it.
    for name in ("custom-inference", "data-science"):
        ab.validate_profiles(ab.parse_profiles(profile_files(name)), governed=True)


def test_reapply_replaces_saved_runtime_placeholder_with_provider_env_reference(
        ab, fake_env, config, profiles, custom_secrets, governed_catalog):
    """A reboot issues a new opaque OpenShell credential revision (#161).

    Persisting the old value in openclaw.json makes inference fail before it
    reaches the credential proxy. Keep a reference to the actual provider env
    name, including when repairing an existing sandbox in place.
    """
    creds = resolve(ab, profiles, custom_secrets)
    applier = ab.ProfileApplier(ab.Shell(), config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    sb = state["sandboxes"]["default/notebook"]
    key = "models.providers.custom-inference.apiKey"
    sb["openclawConfig"][key] = "openshell:resolve:env:v111_CUSTOM_INFERENCE_API_KEY"
    sb["openclawConfig"]["models.providers.user-choice.apiKey"] = "keep-user-choice"
    sb.setdefault("files", {})["notes.md"] = "preserve across reapply"
    fake_env.set_openshell_state(state)
    before = len(fake_env.openshell_calls())
    applier.apply(profiles)
    actual = fake_env.openshell_state()["sandboxes"]["default/notebook"]
    assert actual["openclawConfig"][key] == {
        "source": "env", "provider": "default", "id": "CUSTOM_INFERENCE_API_KEY"}
    assert actual["openclawConfig"]["models.providers.user-choice.apiKey"] == "keep-user-choice"
    assert actual["files"]["notes.md"] == "preserve across reapply"
    assert not any(c[:2] == ["sandbox", "delete"]
                   for c in fake_env.openshell_calls()[before:])


def test_failed_credential_reference_write_stops_apply_before_agent_launch(
        ab, fake_env, config, profiles, custom_secrets, governed_catalog, monkeypatch):
    creds = resolve(ab, profiles, custom_secrets)
    applier = ab.ProfileApplier(ab.Shell(), config, creds)
    original = applier.cli
    launched = []

    def reject_reference(*args, **kwargs):
        if "# SAW: bind runtime credential references" in str(args[-1]):
            raise ab.InstallerError("credential reference write failed")
        return original(*args, **kwargs)

    monkeypatch.setattr(applier, "cli", reject_reference)
    monkeypatch.setattr(applier, "launch_openclaw", lambda *a, **kw: launched.append(True))
    with pytest.raises(ab.InstallerError, match="credential reference write failed"):
        applier.apply(profiles)
    assert not launched


def test_replacement_auth_profile_uses_real_env_ref_before_activation(
        ab, fake_env, config, profiles, custom_secrets, governed_catalog):
    profile_id = "custom-inference:setup-00000000-0000-0000-0000-000000000001"
    output = ("Replacement credential saved but inactive.\n"
              f"openclaw models auth activate {profile_id} --agent main")
    (fake_env.state / "exec-output.json").write_text(json.dumps({"openclaw onboard": output}))
    creds = resolve(ab, profiles, custom_secrets)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    saved = fake_env.openshell_state()["sandboxes"]["default/notebook"]
    assert saved["openclawAuthRefs"][profile_id] == {
        "source": "env", "provider": "default", "id": "CUSTOM_INFERENCE_API_KEY"}
    plan = saved["credentialRefPlans"][-1]
    assert plan["scrubEnv"] is False
    assert plan["scrubAuthProfilesForProviderTargets"] is False
    assert [t["type"] for t in plan["targets"]] == [
        "models.providers.apiKey", "auth-profiles.api_key.key"]
    scripts = [str(c[-1]) for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"]]
    binding = next(i for i, text in enumerate(scripts) if "# SAW: bind runtime credential references" in text)
    activation = next(i for i, text in enumerate(scripts) if f"openclaw models auth activate {profile_id}" in text)
    assert binding < activation


@pytest.mark.parametrize("preflight_fails", [False, True])
def test_reference_plan_shell_validates_regular_file_and_cleans_up(ab, tmp_path, preflight_fails):
    """Run the generated shell against the native API's regular-JSON-file contract."""
    import os
    import subprocess
    import textwrap

    capture = tmp_path / "captured.jsonl"
    executable = tmp_path / "openclaw"
    executable.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import json, os, pathlib, stat, sys
        assert sys.argv[1:3] == ['secrets', 'apply']
        path = pathlib.Path(sys.argv[sys.argv.index('--from') + 1])
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        plan = json.loads(path.read_text())
        with open(os.environ['ISSUE161_TEST_CAPTURE'], 'a') as out:
            out.write(json.dumps({'dryRun': '--dry-run' in sys.argv, 'plan': plan}) + '\\n')
        if os.environ.get('ISSUE161_PREFLIGHT_FAIL') == '1' and '--dry-run' in sys.argv:
            raise SystemExit(1)
        """))
    executable.chmod(0o755)
    script = ab.openclaw_credential_ref_script(
        "custom-inference", "CUSTOM_INFERENCE_API_KEY",
        "custom-inference:setup-00000000-0000-0000-0000-000000000001", "")
    script = script.replace("/sandbox/.openclaw/state", str(tmp_path))
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True,
                            env={**os.environ, 'PATH': str(tmp_path) + os.pathsep + os.environ['PATH'],
                                 'ISSUE161_TEST_CAPTURE': str(capture),
                                 'ISSUE161_PREFLIGHT_FAIL': '1' if preflight_fails else '0'})
    assert (result.returncode != 0) == preflight_fails, result.stderr
    calls = [json.loads(line) for line in capture.read_text().splitlines()]
    assert [c['dryRun'] for c in calls] == ([True] if preflight_fails else [True, False])
    assert all(t['ref']['id'] == 'CUSTOM_INFERENCE_API_KEY' for t in calls[0]['plan']['targets'])
    assert not list(tmp_path.glob('saw-credential-ref.*'))
