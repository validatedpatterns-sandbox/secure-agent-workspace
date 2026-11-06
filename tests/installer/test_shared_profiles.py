"""One profile language and dependency sequence for VM and Kubernetes backends."""

from dataclasses import asdict
from types import SimpleNamespace

import pytest
import yaml

from conftest import PROFILES, profile_files


def files_for(*, providers=None, sandboxes=None, workspace=None):
    documents = {"workspace.yaml": ("Workspace", workspace or {"enabled": True})}
    if providers is not None:
        documents["providers.yaml"] = ("Providers", {"providers": providers})
    if sandboxes is not None:
        documents["sandbox.yaml"] = ("Sandboxes", {"sandboxes": sandboxes})
    return {"profiles__p__team__" + filename: yaml.safe_dump({
        "apiVersion": "saw.redhat.com/v1alpha1", "kind": kind,
        "metadata": {"name": "team"}, "spec": spec})
        for filename, (kind, spec) in documents.items()}


@pytest.mark.parametrize("profile", sorted(p.name for p in PROFILES.iterdir() if p.is_dir()))
def test_every_shipped_profile_has_the_same_strict_and_legacy_normalization(ab, profile):
    files = profile_files(profile)
    strict = ab.parse_profiles(files, strict=True)
    legacy = ab.parse_profiles(files)
    assert [asdict(p) for p in strict] == [asdict(p) for p in legacy]
    ab.validate_profiles(strict, governed=True)
    for _, workspace in ab.enabled_workspaces(strict):
        for provider in workspace.providers:
            assert provider.credential_values == {}
            assert provider.refresh_material == {}
        for sandbox in workspace.sandboxes:
            assert sandbox.inference_values == {}


def test_vm_reexports_actual_shared_objects(ab):
    for name in ("Provider", "Sandbox", "Workspace", "Profile", "HarnessBundle",
                 "InstallerError", "read_profile_files", "parse_profiles",
                 "validate_profiles", "apply_workspace_sequence"):
        assert getattr(ab, name) is getattr(ab._saw_core, name)


@pytest.mark.parametrize("files", [
    files_for(workspace={"enabled": "false"}),
    files_for(workspace={"enabled": False, "serviceAccountName": "admin"}),
    files_for(providers=[{"name": "p", "type": "p", "enabled": "false"}]),
    files_for(providers=[{"name": "p", "type": "p", "credentials": {"api_key": {"value": "private"}}}]),
    files_for(providers=[{"name": "p", "type": "p", "refresh": {"strategy": "oauth2_refresh_token", "token": "private"}}]),
    files_for(sandboxes=[{"name": "s", "enabled": False, "privileged": True}]),
    files_for(sandboxes=[{"name": "s", "providers": "p"}]),
    files_for(sandboxes=[{"name": "s", "harnessRef": {"hostPath": "/"}}]),
    files_for(sandboxes=[{"name": "s", "harnessRequired": "false"}]),
    files_for(sandboxes=[{"name": "s", "ui": {"route": "false"}}]),
    files_for(sandboxes=[{"name": "s", "ui": {"serviceAccountName": "admin"}}]),
    files_for(sandboxes=[{"name": "s", "env": {"TEST": {"value": "ok", 1: "bad"}}}]),
    files_for(sandboxes=[{"name": "s", "env": {"TEST": {"value": "ok", "title": False}}}]),
    files_for(sandboxes=[{"name": "s", "inference": {"model": {"secretKeyRef": {"name": 1, "key": "model"}}}}]),
    files_for(sandboxes=[{"name": "s", "inference": {"model": {"secretKeyRef": {"name": "i", "key": "model"}, 1: "bad"}}}]),
    files_for(sandboxes=[{"name": "s", "inference": {"model": {"secretKeyRef": {"name": "i", "key": "model"}, "title": False}}}]),
])
def test_strict_schema_rejects_unknown_privilege_and_mistyped_fields(ab, files):
    with pytest.raises(ab.InstallerError):
        ab.parse_profiles(files, strict=True)


def test_strict_profile_preserves_supported_inputs_without_resolving_secrets(ab, monkeypatch):
    def forbid_read(*args, **kwargs):
        raise AssertionError("pure parser must not read files or resolve credentials")

    monkeypatch.setattr(ab._saw_core.Path, "read_text", forbid_read)
    provider = {"name": "openai", "type": "openai", "credentialSecret": "inference",
                "credentials": {"api_key": {"secretKey": "token", "title": "Provider API key"}},
                "refresh": {"strategy": "oauth2_refresh_token"}}
    sandbox = {"name": "agent", "type": "openclaw", "providers": ["openai"],
               "env": {"RUN_MODE": {"value": "demo"}}, "harnessRef": {"name": "harness"},
               "inference": {"providerRef": "openai", "protocol": "openai",
                             "model": {"secretKeyRef": {"name": "inference", "key": "model"}},
                             "timeoutSeconds": 300}}
    profiles = ab.parse_profiles(files_for(providers=[provider], sandboxes=[sandbox]), strict=True)
    ab.validate_profiles(profiles, governed=True)
    workspace = profiles[0].workspaces[0]
    assert workspace.providers[0].credentials_spec == provider["credentials"]
    assert workspace.providers[0].credential_values == {}
    assert workspace.providers[0].refresh_material == {}
    assert workspace.sandboxes[0].inference == sandbox["inference"]
    assert workspace.sandboxes[0].inference_values == {}
    assert workspace.sandboxes[0].env_values == {"RUN_MODE": "demo"}


def test_legacy_parse_behavior_and_private_plan_roundtrip_remain_compatible(ab):
    # Strict parsing is opt-in for new adapters; preserve the VM compatibility
    # contract, including its separate private runtime-user transport plan.
    files = files_for(sandboxes=[{"name": "s", "futureField": True}])
    profiles = ab.parse_profiles(files)
    profiles[0].workspaces[0].providers.append(ab.Provider(
        name="openai", type="openai", credential_values={"api_key": "synthetic-test-marker"}))
    plan = {"profiles": [asdict(p) for p in profiles]}
    assert ab.profiles_from_plan(plan) == profiles
    with pytest.raises(ab.InstallerError):
        ab.parse_profiles(files, strict=True)


def test_backend_document_check_sees_chart_directives_before_normalization(ab):
    files = files_for(sandboxes=[{"name": "s", "ui": {"route": True}, "harnessRequired": True}])
    seen = []

    def capabilities(doc, kind):
        seen.append(kind)
        if kind == "Sandboxes":
            assert doc["spec"]["sandboxes"][0]["harnessRequired"] is True
            if doc["spec"]["sandboxes"][0]["ui"]["route"]:
                raise ab.InstallerError("backend has no UI route support")

    with pytest.raises(ab.InstallerError, match="backend has no UI route support"):
        ab.parse_profiles(files, strict=True, document_check=capabilities)
    assert seen == ["Workspace", "Sandboxes"]


def test_strict_schema_runs_before_backend_document_check(ab):
    seen = []
    with pytest.raises(ab.InstallerError):
        ab.parse_profiles(files_for(workspace={"privileged": True}), strict=True,
                          document_check=lambda *args: seen.append(args))
    assert seen == []


@pytest.mark.parametrize("workspace_ready, pending_providers, pending_sandboxes, expected, ready", [
    (False, set(), set(), ["workspace"], False),
    (True, {"p1"}, set(), ["workspace", "p1", "p2"], False),
    (True, {"p2"}, set(), ["workspace", "p1", "p2"], False),
    (True, set(), {"s1"}, ["workspace", "p1", "p2", "s1", "s2"], False),
    (True, set(), set(), ["workspace", "p1", "p2", "s1", "s2"], True),
])
def test_shared_sequence_preserves_dependency_barrier_and_visits_all_peers(
        ab, workspace_ready, pending_providers, pending_sandboxes, expected, ready):
    calls = []
    workspace = object()

    def prepare(ws):
        assert ws is workspace
        calls.append("workspace")
        return workspace_ready

    def apply_provider(ws, provider):
        assert ws is workspace
        calls.append(provider)
        return provider not in pending_providers

    def apply_sandbox(ws, sandbox):
        assert ws is workspace
        calls.append(sandbox)
        return sandbox not in pending_sandboxes

    adapter = SimpleNamespace(prepare_workspace=prepare, apply_provider=apply_provider,
                              apply_sandbox=apply_sandbox)
    assert ab.apply_workspace_sequence(workspace, ["p1", "p2"], ["s1", "s2"], adapter) is ready
    assert calls == expected


def test_shared_sequence_propagates_backend_errors_before_dependents(ab):
    calls = []

    def fail(ws, provider):
        calls.append(provider)
        raise ab.InstallerError("provider refused")

    adapter = SimpleNamespace(prepare_workspace=lambda ws: True, apply_provider=fail,
                              apply_sandbox=lambda ws, sb: calls.append(sb))
    with pytest.raises(ab.InstallerError, match="provider refused"):
        ab.apply_workspace_sequence("workspace", ["p1", "p2"], ["s1"], adapter)
    assert calls == ["p1"]


def test_vm_sequence_keeps_migration_and_aggregated_sandbox_failures(ab):
    calls = []

    def failing_sandbox(ws, sb):
        calls.append(sb.name)
        if sb.name == "bad":
            raise ab.InstallerError("synthetic failure")

    applier = SimpleNamespace(
        apply_workspace=lambda ws: calls.append("workspace"),
        adopt_governed_profiles=lambda ws: calls.append("catalog"),
        prepare_credential_migration=lambda ws: calls.append("migration"),
        apply_provider=lambda ws, p: calls.append(p.name),
        apply_sandbox=failing_sandbox, sandbox_failures=[])
    adapter = ab._VMWorkspaceSequence(applier)
    assert ab.apply_workspace_sequence(
        ab.Workspace("team"), [ab.Provider("p", "p")],
        [ab.Sandbox("bad"), ab.Sandbox("disabled", enabled=False), ab.Sandbox("good")], adapter) is False
    assert calls == ["workspace", "catalog", "migration", "p", "bad", "good"]
    assert applier.sandbox_failures == ["sandbox 'bad': synthetic failure"]
